// wallet.ts  --  guided wallet mint / persist / fund for the `shopping` skill.
//
// The gap this closes (P1-3): the skill otherwise REQUIRES the user to already
// hold a wallet key in the environment (FACET_WALLET_KEY). A walletless user
// could not onboard. This module mints a fresh wallet, persists it securely, and
// funds it, presenting the wallet as a capped spend instrument, and wires it into
// the existing env-based wallet model so a minted wallet is usable immediately by
// wallets / provision / buy without the user exporting a key.
//
// THE NEVER-LEAK INVARIANT (this module handles a real private key, so read this):
//   * The BIP-39 recovery phrase is revealed EXACTLY ONCE, on STDERR only, with a
//     write-it-down warning. It is never written to stdout, the JSON result, a
//     log, or any file.
//   * The private key is stored ONLY in the OS keychain (macOS) or an AES-256-GCM
//     encrypted keystore under ~/.facet/keys. It never appears on stdout, in the
//     JSON result, in a log, on a command line, or in cleartext on disk.
//   * The keychain write feeds the key through `security -i` on STDIN, so the key
//     never lands on the process argument list (ps shows only `security -i`).
//   * stdout carries ONLY non-secret facts: the derived (public) address, the
//     label, where the key was stored, and a fund hint. This is load-bearing: the
//     session transcript and memory indexers mine stdout, so a key or phrase on
//     stdout is a permanent leak.
//   * The key lives in-process only during signing, exactly like the env path.
//
// Crypto: AES-256-GCM for the keystore, with the symmetric key derived from a
// passphrase via PBKDF2-HMAC-SHA256 (600,000 iterations, random 32-byte salt,
// random 12-byte IV, the GCM auth tag stored for tamper/wrong-passphrase
// detection). node:crypto is used for a fully synchronous read path so the
// existing (synchronous) resolveWallet can fall back to a persisted key without
// becoming async.
//
// Permissions: the keychain tier needs --allow-run (to exec `security`); the
// keystore tier needs --allow-read/--allow-write to ~/.facet; both need
// --allow-env (for HOME). Without --allow-run the keychain tier is skipped and
// the encrypted keystore is used instead (graceful degrade).

import {
  english,
  generateMnemonic,
  mnemonicToAccount,
  privateKeyToAccount,
} from "npm:viem@2.50.4/accounts";
import { bytesToHex } from "npm:viem@2.50.4";
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";
import { die, emit, EXPECT_NETWORK, note, resolveWallet, usdcAtomic } from "./facet-checkout.ts";

// ---- constants + paths -----------------------------------------------------
const KEYCHAIN_SERVICE_PREFIX = "facet-wallet-";
const KEYSTORE_VERSION = 1;
// PBKDF2-HMAC-SHA256 work factor. 600k iterations tracks the OWASP 2023 floor for
// PBKDF2-SHA256; a keystore is only as strong as the passphrase behind it, so the
// KDF cost is what makes a weak passphrase expensive to brute-force offline.
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_KEYLEN = 32; // 256-bit AES key
const PBKDF2_HASH = "sha256";
const GCM_IV_BYTES = 12; // standard AES-GCM nonce size
const SALT_BYTES = 32;
const MIN_PASSPHRASE_LEN = 8;
const POLL_INTERVAL_MS = 10_000;

// ~/.facet is off Google Drive by design (the vault syncs; ~/.facet does not), so
// an encrypted keystore never rides a sync service. Mirrors the receipt archive.
function facetHome(): string {
  return `${Deno.env.get("HOME") ?? "."}/.facet`;
}
function keysDir(): string {
  return `${facetHome()}/keys`;
}
export function walletsIndexPath(): string {
  return `${facetHome()}/wallets.json`;
}
export function keystorePathFor(label: string): string {
  return `${keysDir()}/${safeLabel(label)}.json`;
}
function keychainServiceFor(label: string): string {
  return `${KEYCHAIN_SERVICE_PREFIX}${safeLabel(label)}`;
}

// ---- label validation ------------------------------------------------------
// A label names a persisted key and is used to build a keystore FILENAME and a
// keychain SERVICE name. Reject a path separator or a leading dot so a hostile
// label can never traverse out of ~/.facet/keys or shadow a dotfile. Keep it to a
// short, filesystem-safe token.
// Pure predicate (no die), so both the accept and reject paths are unit-testable.
export function isValidLabel(label: string): boolean {
  return typeof label === "string" && label.trim() !== "" && label.length <= 64 &&
    /^[a-zA-Z0-9._-]+$/.test(label) && !label.startsWith(".");
}
export function assertValidLabel(label: string): void {
  if (!isValidLabel(label)) {
    die(
      `invalid wallet label "${label}": use 1 to 64 characters of letters, digits, dot, ` +
        `underscore, or dash, and do not start with a dot.`,
    );
  }
}
// Filesystem-safe form. assertValidLabel already constrains user input; this is a
// defense-in-depth backstop so a filename or service name can never contain a
// separator even if a caller reaches here without validating first.
export function safeLabel(label: string): string {
  return label.replace(/[^a-zA-Z0-9._-]/g, "_");
}

// ---- mnemonic + key derivation ---------------------------------------------
export interface MintedWallet {
  mnemonic: string; // SECRET
  privateKey: string; // SECRET, 0x + 64 hex
  address: string; // public
}

// Generate a fresh BIP-39 mnemonic and derive its default account (m/44'/60'/0'/0/0).
// The mnemonic and the private key are SECRETS: the caller persists the key in a
// secure tier and reveals the mnemonic ONCE on stderr. Neither ever reaches
// stdout, the JSON result, a log, or any file but the encrypted keystore.
export function mintWallet(): MintedWallet {
  const mnemonic = generateMnemonic(english);
  const account = mnemonicToAccount(mnemonic);
  const hd = account.getHdKey();
  if (hd.privateKey === null || hd.privateKey === undefined) {
    die("internal: derived HD account carries no private key.");
  }
  const privateKey = bytesToHex(hd.privateKey);
  return { mnemonic, privateKey, address: account.address };
}

export function normalizePrivateKey(k: string): `0x${string}` {
  const s = k.trim();
  return (s.startsWith("0x") ? s : `0x${s}`) as `0x${string}`;
}

// Derive the public address from a private key. Used by tests and by the fund
// path; throws (via viem) on a malformed key, which the caller turns into a die().
export function addressFromPrivateKey(k: string): string {
  return privateKeyToAccount(normalizePrivateKey(k)).address;
}

// ---- encrypted keystore (AES-256-GCM + PBKDF2), synchronous -----------------
export interface Keystore {
  version: number;
  label: string;
  address: string;
  crypto: {
    cipher: "aes-256-gcm";
    ciphertext: string; // base64
    iv: string; // base64
    auth_tag: string; // base64 GCM tag
    kdf: "pbkdf2";
    kdfparams: { hash: string; iterations: number; keylen: number; salt: string };
  };
  created_at: string;
}

// Encrypt a private key under a passphrase into a standard keystore object. The
// plaintext is the 0x key STRING. AES-256-GCM gives confidentiality plus
// integrity; the AES key is derived from the passphrase with PBKDF2-HMAC-SHA256
// over a fresh random salt, and a fresh random IV is used per encryption. The GCM
// auth tag is stored so decryption can detect a wrong passphrase or tampering.
export function encryptKeystore(
  privateKey: string,
  passphrase: string,
  meta: { label: string; address: string },
): Keystore {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(GCM_IV_BYTES);
  const key = pbkdf2Sync(
    Buffer.from(passphrase, "utf8"),
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_HASH,
  );
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(privateKey, "utf8")),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    version: KEYSTORE_VERSION,
    label: meta.label,
    address: meta.address,
    crypto: {
      cipher: "aes-256-gcm",
      ciphertext: ciphertext.toString("base64"),
      iv: iv.toString("base64"),
      auth_tag: authTag.toString("base64"),
      kdf: "pbkdf2",
      kdfparams: {
        hash: PBKDF2_HASH,
        iterations: PBKDF2_ITERATIONS,
        keylen: PBKDF2_KEYLEN,
        salt: salt.toString("base64"),
      },
    },
    created_at: new Date().toISOString(),
  };
}

// Decrypt a keystore back to the 0x private-key string. Throws on a wrong
// passphrase or a tampered file (the GCM tag check fails in decipher.final()).
// The returned key is a secret: the caller uses it in-process to sign and never
// persists or prints it.
export function decryptKeystore(ks: Keystore, passphrase: string): string {
  const c = ks.crypto;
  if (c.cipher !== "aes-256-gcm" || c.kdf !== "pbkdf2") {
    throw new Error("unsupported keystore cipher or kdf");
  }
  const key = pbkdf2Sync(
    Buffer.from(passphrase, "utf8"),
    Buffer.from(c.kdfparams.salt, "base64"),
    c.kdfparams.iterations,
    c.kdfparams.keylen,
    c.kdfparams.hash,
  );
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(c.iv, "base64"));
  decipher.setAuthTag(Buffer.from(c.auth_tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(c.ciphertext, "base64")),
    decipher.final(),
  ]);
  return plaintext.toString("utf8");
}

// ---- OS keychain tier (macOS `security`) -----------------------------------
// Available only on macOS with the `security` binary reachable. Any failure
// (wrong OS, missing binary, --allow-run not granted) is treated as "unavailable"
// and the caller falls back to the encrypted keystore.
export function keychainAvailable(): boolean {
  if (Deno.build.os !== "darwin") return false;
  try {
    const r = new Deno.Command("security", {
      args: ["list-keychains"],
      stdout: "null",
      stderr: "null",
    }).outputSync();
    return r.success;
  } catch {
    return false;
  }
}

// Store a key in the keychain WITHOUT placing it on the process argument list.
// `security -i` reads commands from stdin, so the add-generic-password line (which
// contains the key) travels through our pipe, never through argv; `ps` shows only
// `security -i`. The key is a 0x-hex string with no whitespace, so it needs no
// quoting on the interactive line. Verifies the round-trip so a silent keychain
// failure falls back to the keystore. Returns true only when the key reads back.
export async function keychainSet(label: string, privateKey: string): Promise<boolean> {
  if (Deno.build.os !== "darwin") return false;
  try {
    const child = new Deno.Command("security", {
      args: ["-i"],
      stdin: "piped",
      stdout: "null",
      stderr: "null",
    }).spawn();
    const w = child.stdin.getWriter();
    const line =
      `add-generic-password -a ${safeLabel(label)} -s ${keychainServiceFor(label)} -U -w ${privateKey}\n`;
    await w.write(new TextEncoder().encode(line));
    await w.close();
    const status = await child.status;
    if (!status.success) return false;
    return keychainGet(label) === privateKey;
  } catch {
    return false;
  }
}

// Read a persisted key from the keychain. `security -w` prints the value to THIS
// process's captured stdout only; it is used in-process and never forwarded to
// the skill's stdout. Returns undefined if absent or on any error (missing
// binary, --allow-run denied, a locked keychain the user declined to unlock).
export function keychainGet(label: string): string | undefined {
  if (Deno.build.os !== "darwin") return undefined;
  try {
    const r = new Deno.Command("security", {
      args: [
        "find-generic-password",
        "-a",
        safeLabel(label),
        "-s",
        keychainServiceFor(label),
        "-w",
      ],
      stdout: "piped",
      stderr: "null",
    }).outputSync();
    if (!r.success) return undefined;
    const v = new TextDecoder().decode(r.stdout).trim();
    return v === "" ? undefined : v;
  } catch {
    return undefined;
  }
}

// Existence probe that does NOT print the value (no -w), used for the overwrite
// guard so `wallet new` cannot silently destroy a key funds may be bound to.
export function keychainHas(label: string): boolean {
  if (Deno.build.os !== "darwin") return false;
  try {
    const r = new Deno.Command("security", {
      args: ["find-generic-password", "-a", safeLabel(label), "-s", keychainServiceFor(label)],
      stdout: "null",
      stderr: "null",
    }).outputSync();
    return r.success;
  } catch {
    return false;
  }
}

// Remove a keychain entry (best effort). Used on --force to drop a stale copy in
// the tier not being written this time.
export function keychainDelete(label: string): void {
  if (Deno.build.os !== "darwin") return;
  try {
    new Deno.Command("security", {
      args: ["delete-generic-password", "-a", safeLabel(label), "-s", keychainServiceFor(label)],
      stdout: "null",
      stderr: "null",
    }).outputSync();
  } catch {
    // best effort
  }
}

// ---- keystore file IO ------------------------------------------------------
function ensureKeysDir(): void {
  Deno.mkdirSync(keysDir(), { recursive: true, mode: 0o700 });
}
export function keystoreExists(label: string): boolean {
  try {
    Deno.statSync(keystorePathFor(label));
    return true;
  } catch {
    return false;
  }
}
export function writeKeystore(label: string, ks: Keystore): string {
  ensureKeysDir();
  const path = keystorePathFor(label);
  Deno.writeTextFileSync(path, JSON.stringify(ks, null, 2), { mode: 0o600 });
  return path;
}
export function readKeystore(label: string): Keystore | undefined {
  try {
    return JSON.parse(Deno.readTextFileSync(keystorePathFor(label))) as Keystore;
  } catch {
    return undefined;
  }
}
export function deleteKeystore(label: string): void {
  try {
    Deno.removeSync(keystorePathFor(label));
  } catch {
    // best effort
  }
}

// ---- discovery index (NON-SECRET) ------------------------------------------
// Records ONLY the label, the storage tier, and the PUBLIC address of each minted
// wallet, never a key. It lets `wallets` list a persisted wallet and lets
// walletRegistry resolve it by label with no env var set. A missing or corrupt
// index is treated as empty. Mirrors the receipt archive's index pattern.
export interface WalletIndexEntry {
  label: string;
  storage: "keychain" | "keystore";
  address: string;
  created_at: string;
}
export function readWalletIndex(): WalletIndexEntry[] {
  try {
    const parsed = JSON.parse(Deno.readTextFileSync(walletsIndexPath()));
    if (!Array.isArray(parsed)) return [];
    const out: WalletIndexEntry[] = [];
    for (const e of parsed) {
      if (e === null || typeof e !== "object") continue;
      const r = e as Partial<WalletIndexEntry>;
      if (typeof r.label === "string" && typeof r.address === "string") {
        out.push(r as WalletIndexEntry);
      }
    }
    return out;
  } catch {
    return [];
  }
}
export function walletIndexEntry(label: string): WalletIndexEntry | undefined {
  return readWalletIndex().find((e) => e.label === label);
}
function upsertWalletIndex(entry: WalletIndexEntry): void {
  try {
    const entries = readWalletIndex().filter((e) => e.label !== entry.label);
    entries.push(entry);
    Deno.mkdirSync(facetHome(), { recursive: true, mode: 0o700 });
    Deno.writeTextFileSync(walletsIndexPath(), JSON.stringify(entries, null, 2), { mode: 0o600 });
  } catch {
    // Discovery index is best-effort; the key is already persisted in its tier.
  }
}

// ---- passphrase prompt (no echo) -------------------------------------------
// Prompt on the tty WITHOUT echoing. The prompt goes to stderr (stdout is
// reserved for the one JSON result). On a real terminal it disables echo via raw
// mode and reads until Enter; when stdin is a pipe (a test or a non-interactive
// run) it reads one line without masking. The passphrase never touches stdout, a
// file, or a log.
export function promptPassphrase(prompt: string): string {
  const enc = new TextEncoder();
  Deno.stderr.writeSync(enc.encode(prompt));
  if (!Deno.stdin.isTerminal()) {
    const line = readLineSync();
    Deno.stderr.writeSync(enc.encode("\n"));
    return line;
  }
  Deno.stdin.setRaw(true);
  try {
    const bytes: number[] = [];
    const buf = new Uint8Array(1);
    while (true) {
      const n = Deno.stdin.readSync(buf);
      if (n === null || n === 0) break;
      const c = buf[0];
      if (c === 3) { // Ctrl-C
        Deno.stdin.setRaw(false);
        Deno.stderr.writeSync(enc.encode("\n"));
        die("passphrase entry cancelled.");
      }
      if (c === 13 || c === 10) break; // Enter (CR or LF)
      if (c === 127 || c === 8) { // Backspace / Delete
        if (bytes.length > 0) bytes.pop();
        continue;
      }
      bytes.push(c);
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  } finally {
    Deno.stdin.setRaw(false);
    Deno.stderr.writeSync(enc.encode("\n"));
  }
}

function readLineSync(): string {
  const bytes: number[] = [];
  const buf = new Uint8Array(1);
  while (true) {
    const n = Deno.stdin.readSync(buf);
    if (n === null || n === 0) break;
    if (buf[0] === 10) break; // LF ends the line
    if (buf[0] === 13) continue; // ignore CR
    bytes.push(buf[0]);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

// ---- loadPersistedKey: the fallback resolveWallet uses ---------------------
// Resolve a persisted key for a label: keychain first, then the encrypted
// keystore (prompting for the passphrase). Returns the 0x key string, or
// undefined if neither tier holds it. Synchronous so the existing (synchronous)
// resolveWallet can call it without becoming async. The key stays in-process; it
// is never printed or written back out.
export function loadPersistedKey(label: string): string | undefined {
  const fromKeychain = keychainGet(label);
  if (fromKeychain !== undefined && fromKeychain !== "") return fromKeychain;
  const ks = readKeystore(label);
  if (ks === undefined) return undefined;
  const pass = promptPassphrase(`Passphrase to unlock wallet "${label}" (encrypted keystore): `);
  try {
    return decryptKeystore(ks, pass);
  } catch {
    die(
      `could not decrypt keystore for wallet "${label}": wrong passphrase or the file is corrupt.`,
    );
  }
}

// ---- fund threshold (pure) -------------------------------------------------
// Whether a wallet is funded enough to proceed. minAtomic 0 means "any positive
// balance". Pure, so it is unit-tested with no network call.
export function fundedEnough(balanceAtomic: bigint, minAtomic: bigint): boolean {
  if (minAtomic > 0n) return balanceAtomic >= minAtomic;
  return balanceAtomic > 0n;
}

// ---- wallet-new stdout result (NON-SECRET) ---------------------------------
// The ONLY thing `wallet new` prints to stdout. It deliberately carries NO
// secret: the public address, the label, where the key was stored, and a fund
// hint. The mnemonic and private key are revealed only on stderr (mnemonic, once)
// and stored only in the keychain or encrypted keystore. Exported so a test can
// assert the object contains neither the key nor the mnemonic.
export function buildWalletNewResult(opts: {
  label: string;
  address: string;
  storage: "keychain" | "keystore";
  keystorePath?: string;
}): Record<string, unknown> {
  return {
    ok: true,
    label: opts.label,
    address: opts.address,
    network: EXPECT_NETWORK,
    storage: opts.storage,
    stored: opts.storage === "keychain"
      ? `macOS keychain (service ${KEYCHAIN_SERVICE_PREFIX}${safeLabel(opts.label)})`
      : "AES-256-GCM encrypted keystore",
    ...(opts.storage === "keystore" && opts.keystorePath !== undefined
      ? { keystore_path: opts.keystorePath }
      : {}),
    spend_instrument: {
      per_order_cap:
        "Every buy is capped per order by --max-usdc under an absolute ceiling; treat this " +
        "wallet as a spend instrument and fund only what you intend to spend.",
      per_session_cap: "A per-session cap is a separate Terminal-side control, not set here.",
    },
    fund_hint:
      `Fund on ${EXPECT_NETWORK}: send USDC to ${opts.address}, then check with ` +
      `\`fund --label ${opts.label} --await\`.`,
    message:
      `Wallet "${opts.label}" created. Its recovery phrase was shown ONCE on stderr; write it ` +
      `down now, it will not be shown again. The private key was stored securely and never printed.`,
  };
}

// Reveal the recovery phrase EXACTLY ONCE, on stderr only. This is the single
// moment the mnemonic is visible. It never goes to stdout (the transcript and
// memory indexers mine stdout), never to a file, never to a log.
function revealMnemonicOnce(mnemonic: string, label: string): void {
  const bar = "=".repeat(72);
  const block = [
    "",
    bar,
    `  RECOVERY PHRASE for wallet "${label}". WRITE THIS DOWN NOW.`,
    "  Shown ONCE and never displayed again. Anyone with these words controls",
    "  the wallet and its funds. Do not screenshot, paste, or store it digitally.",
    bar,
    "",
    `  ${mnemonic}`,
    "",
    bar,
    "",
  ].join("\n");
  Deno.stderr.writeSync(new TextEncoder().encode(block));
}

// Prompt for a passphrase twice and encrypt the key into a keystore file. Returns
// the keystore path. Requires a matching, minimum-length passphrase so a typo can
// never lock funds behind an unknown secret.
function persistToKeystore(label: string, minted: MintedWallet): string {
  const pass = promptPassphrase(`Set a passphrase to encrypt wallet "${label}" (keystore): `);
  if (pass.length < MIN_PASSPHRASE_LEN) {
    die(
      `passphrase too short: use at least ${MIN_PASSPHRASE_LEN} characters. Nothing was written.`,
    );
  }
  const confirm = promptPassphrase("Confirm passphrase: ");
  if (pass !== confirm) {
    die("passphrases did not match; nothing was written. Run `wallet new` again.");
  }
  const ks = encryptKeystore(minted.privateKey, pass, { label, address: minted.address });
  return writeKeystore(label, ks);
}

// ---- `wallet new` ----------------------------------------------------------
// `wallet new [--label <name>] [--keystore] [--force]` : mint, persist, reveal.
//   - Mnemonic shown once on stderr with a warning.
//   - Key stored keychain-first (macOS, unless --keystore), else encrypted
//     keystore, and NEVER printed or returned.
//   - stdout carries only the public address, label, storage, and a fund hint.
//   - Refuses to overwrite an existing wallet at the label without --force.
export async function cmdWalletNew(
  sub: string,
  flags: Record<string, string | boolean>,
): Promise<never> {
  if (sub !== "new") {
    die(
      `unknown wallet subcommand "${sub}". Use: wallet new [--label <name>] [--keystore] [--force].`,
    );
  }
  const label = typeof flags.label === "string" && flags.label !== "" ? flags.label : "default";
  assertValidLabel(label);
  const force = flags.force === true;

  // Idempotency: never silently destroy a key that funds may be bound to.
  const indexed = walletIndexEntry(label) !== undefined;
  const exists = keychainHas(label) || keystoreExists(label) || indexed;
  if (exists && !force) {
    die(
      `a wallet labeled "${label}" already exists. Refusing to overwrite it (funds may be bound ` +
        `to it). Use a different --label, or pass --force to replace it (this destroys the old key).`,
    );
  }

  const useKeychain = flags.keystore !== true && keychainAvailable();

  // Mint locally. The mnemonic and key are secrets from here on.
  const minted = mintWallet();

  // Reveal the mnemonic ONCE on stderr BEFORE anything else, so it is shown even
  // if a later storage step fails. Never stdout, never a file.
  revealMnemonicOnce(minted.mnemonic, label);

  let storage: "keychain" | "keystore";
  let keystorePath: string | undefined;
  if (useKeychain) {
    if (await keychainSet(label, minted.privateKey)) {
      storage = "keychain";
      if (force) deleteKeystore(label); // drop any stale fallback copy
    } else {
      note("keychain store failed; falling back to an encrypted keystore.");
      keystorePath = persistToKeystore(label, minted);
      storage = "keystore";
    }
  } else {
    keystorePath = persistToKeystore(label, minted);
    storage = "keystore";
    if (force) keychainDelete(label); // drop any stale keychain copy
  }

  // Record in the non-secret discovery index so wallets/provision/buy can use it
  // by label without an exported env key.
  upsertWalletIndex({
    label,
    storage,
    address: minted.address,
    created_at: new Date().toISOString(),
  });

  emit(buildWalletNewResult({ label, address: minted.address, storage, keystorePath }));
}

// ---- `fund` ----------------------------------------------------------------
// `fund [--label <name>] [--await] [--min-usdc <n>]` : show the wallet address and
// its current USDC-on-Base balance so the user can send funds. With --await, poll
// every ~10s (progress on stderr) until the balance reaches the threshold (>0, or
// >= --min-usdc), then report funded on stdout. USDC-on-Base only.
export async function cmdFund(flags: Record<string, string | boolean>): Promise<never> {
  const label = typeof flags.label === "string" && flags.label !== "" ? flags.label : "default";
  const address = fundAddress(label);
  const minUsdc = flags["min-usdc"] !== undefined ? Number(flags["min-usdc"]) : 0;
  if (!Number.isFinite(minUsdc) || minUsdc < 0) {
    die("--min-usdc must be a non-negative number.");
  }
  const minAtomic = BigInt(Math.round(minUsdc * 1e6));

  const balance = await usdcAtomic(address);
  if (flags.await !== true) {
    emit({
      ok: true,
      label,
      address,
      network: EXPECT_NETWORK,
      usdc_balance: Number(balance) / 1e6,
      funded: fundedEnough(balance, minAtomic),
      ...(minUsdc > 0 ? { min_usdc: minUsdc } : {}),
      fund_hint: `Send USDC on ${EXPECT_NETWORK} to ${address} to fund this wallet.`,
    });
  }

  // --await: poll until funded. Unbounded by design; the caller stops with Ctrl-C.
  note(
    `waiting for USDC on ${EXPECT_NETWORK} at ${address} ` +
      (minUsdc > 0 ? `(need >= ${minUsdc} USDC)` : `(any positive balance)`) +
      `; send funds now. Polling every ${POLL_INTERVAL_MS / 1000}s, Ctrl-C to stop.`,
  );
  let bal = balance;
  while (!fundedEnough(bal, minAtomic)) {
    note(`current balance: ${Number(bal) / 1e6} USDC; not funded yet, checking again in 10s`);
    await sleep(POLL_INTERVAL_MS);
    bal = await usdcAtomic(address);
  }
  emit({
    ok: true,
    label,
    address,
    network: EXPECT_NETWORK,
    usdc_balance: Number(bal) / 1e6,
    funded: true,
    ...(minUsdc > 0 ? { min_usdc: minUsdc } : {}),
    message: `Wallet "${label}" is funded with ${Number(bal) / 1e6} USDC on ${EXPECT_NETWORK}.`,
  });
}

// Resolve the address to fund WITHOUT unlocking a key when possible. The
// discovery index holds the PUBLIC address of a minted wallet, so the common case
// (fund a wallet you just minted) needs no keychain unlock and no passphrase. For
// an env-configured or declared-but-not-indexed wallet, fall back to the full
// registry resolution (which derives the address), matching how buy resolves it.
function fundAddress(label: string): string {
  const idx = walletIndexEntry(label);
  if (idx !== undefined) return idx.address;
  return resolveWallet(label).address;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
