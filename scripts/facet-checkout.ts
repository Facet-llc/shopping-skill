#!/usr/bin/env -S deno run --allow-env --allow-read --allow-net
//
// facet-checkout.ts  --  non-custodial, KYA-authenticated shopping helper for a
// Facet-enabled merchant. Deterministic crypto + HTTP legs for the `shopping`
// skill; the conversation (card rendering, the buy confirmation) stays with the
// assistant.
//
// NON-CUSTODIAL, by construction:
//   * Your wallet private key (FACET_WALLET_KEY) is read from the environment,
//     used to sign an ERC-3009 payment authorization LOCALLY, and is NEVER
//     transmitted, logged, or written anywhere. Only the resulting signature (an
//     authorization to move a specific amount to a specific destination) leaves
//     this process.
//   * Funds settle on-chain into the merchant's Boson escrow, straight from your
//     wallet. No third party ever holds your money or your key.
//
// IDENTITY (bring your own):
//   FACET_KYA         Your Facet KYA (an ES256 bearer JWT) from an issuer the
//                     merchant trusts. Authenticates every browse + checkout call.
//   FACET_WALLET_KEY  Your wallet private key (0x + 64 hex). Signs the payment.
//                     Ideally the SAME wallet your KYA is bound to (payer_wallet),
//                     which is required on sites that tie identity to the paying wallet.
//
// WALLET SELECTION (choose BEFORE shopping):
//   The wallet is chosen first, like picking a card before you check out: it
//   sets your identity (the wallet-bound KYA), your spendable USDC, and where
//   funds come from. `wallets` lists every configured wallet (label, address,
//   USDC balance) so the assistant can ask which to use; the choice rides as
//   --wallet <label> on search/product/buy.
//   FACET_WALLETS     Optional JSON to register more than one wallet, e.g.
//                       [{"label":"personal","key_env":"FACET_WALLET_KEY","kya_env":"FACET_KYA"},
//                        {"label":"business","key_env":"FACET_BIZ_WALLET_KEY","kya_env":"FACET_BIZ_KYA"}]
//                     Each entry names the env vars that hold that wallet's key
//                     and KYA (never the values). With no registry, one default
//                     wallet (FACET_WALLET_KEY + FACET_KYA) is used.
//
// SAFETY (money path):
//   `buy` is DRY by default: it creates the checkout, reads the merchant's
//   server-advertised terms, checks them against hard guardrails, signs the
//   authorization locally, and STOPS. Nothing moves. It prints the exact atomic
//   amount to confirm. Only `buy --settle --confirm <atomic>` posts the real
//   settlement, and only when <atomic> matches the freshly-advertised price.
//
// SUBCOMMANDS
//   wallet new [--label <name>] [--keystore] [--force]
//   wallets
//   fund      [--label <name>] [--await] [--min-usdc <n>]
//   discover  --site <host>
//   directory --query <q> [--near "<lat>,<lng>"] [--radius-km N] [--capabilities a,b]
//             [--taxonomy a,b] [--min-reputation N] [--claimed-only] [--limit n] [--terminal <url>] [--wallet <label>]
//   search    --terminal <url> [--query q] [--category c] [--tags a,b] [--limit n] [--wallet <label>]
//   product   --terminal <url> --id <product_id> [--wallet <label>]
//   provision [--wallet <label>]
//   buy       --terminal <url> --items '<json>' --ship '<json>'
//             [--gift-message "..."] [--delivery-date YYYY-MM-DD] [--occasion "..."]
//             [--shipping-email <addr>] [--max-usdc N] [--wallet <label>] [--settle --confirm <atomic>]
//   email-pref set <address> | email-pref set --none | email-pref show
//   redeem    --terminal <url> --exchange-id <id> [--wallet <label>]
//   cancel    --terminal <url> --exchange-id <id> [--wallet <label>] [--withdraw] [--amount <atomic>]
//   withdraw  --terminal <url> --exchange-id <id> [--wallet <label>] [--amount <atomic>] [--dry-run]
//   dispute   --terminal <url> --exchange-id <id> [--action raise|retract|escalate] [--wallet <label>]
//   refund    --terminal <url> --order-id <id> [--wallet <label>]
//   reorder   --terminal <url> [--order-id <id>] [--limit <n>] [--wallet <label>]
//   receipt   --terminal <url> --order-id <id> [--no-verify] [--wallet <label>]
//   receipts
//
// THE RECEIPT (your portable proof):
//   Every settled purchase leaves a signed, self-verifying receipt on the Facet
//   ledger. `buy --settle` fetches, verifies, and archives it inline; `receipt`
//   re-fetches any past order (re-authorizing with the payer wallet if the buy
//   KYA has expired), and `receipts` lists the local archive. It is a compact
//   Ed25519 JWS (RFC 7515) that verifies against the merchant Terminal's
//   published JWKS with a stock JOSE library and NO call back to Facet: evidence,
//   not a service lookup. Every fetched receipt is also SAVED to a durable
//   archive (default ~/.facet/receipts, override FACET_RECEIPTS_DIR): one
//   <order_id>.json per order plus an index.jsonl the `receipts` subcommand
//   lists. Saving needs --allow-write to that dir; without it the save is skipped
//   and the receipt is still returned. See verifyReceipt / saveReceipt below.
//
// Every subcommand prints ONE JSON object to stdout (progress notes go to stderr),
// so the assistant can parse the result deterministically.

import { privateKeyToAccount } from "npm:viem@2.50.4/accounts";
import { type Chain, createPublicClient, getAddress, http } from "npm:viem@2.50.4";
import { createX402bClient, type Signer } from "npm:@bosonprotocol/x402-client@0.3.1";
import { compactVerify, createLocalJWKSet } from "npm:jose@5.9.6";
import { cachePathFor, kyaUsable, provisionKya, readCachedKya } from "./kya-provision.ts";
import {
  attachShippingEmail,
  getShippingEmailPref,
  isPlausibleEmail,
  orderPrefsFile,
  setShippingEmailPref,
} from "./order-prefs.ts";
// Wallet-mint onboarding (P1-3). facet-checkout.ts and wallet.ts intentionally
// import each other: facet-checkout provides the shared plumbing (emit/die/note/
// usdcAtomic/EXPECT_NETWORK) and resolveWallet, and wallet.ts provides the mint/
// fund commands plus the persisted-key fallback that resolveWallet, walletRegistry,
// browseKyaHeaders, and wallets use. The cycle is safe because neither module
// calls the other's bindings at module-eval time, only inside functions run later.
import {
  cmdFund,
  cmdWalletNew,
  loadPersistedKey,
  readWalletIndex,
  walletIndexEntry,
} from "./wallet.ts";

// ---- network profile: FACET_NETWORK selects a coherent set of chain defaults,
// so a run needs no pile of env vars. `base` is Base mainnet (the default and, in
// this release, the only network). Every value below still honors its individual
// FACET_* override when set; the profile only supplies the default. `usdcDomainName`
// is the token contract's real EIP-712 name (Base mainnet USDC is "USD Coin"): a
// wrong name makes the ERC-3009 signature recover the wrong signer, which the
// Terminal reads as "buyer identity not bound to the paying wallet".
interface NetworkProfile {
  readonly chain: number;
  readonly network: string;
  readonly usdc: string;
  readonly rpc: string;
  readonly usdcDomainName: string;
  readonly platform: string;
  readonly originationSuffixes: string;
}
const NETWORK_PROFILES: Record<string, NetworkProfile> = {
  base: {
    chain: 8453,
    network: "base",
    usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    rpc: "https://base-rpc.publicnode.com",
    usdcDomainName: "USD Coin",
    platform: "https://api.facet.llc",
    originationSuffixes: ".facet.llc",
  },
};
const PROFILE = NETWORK_PROFILES[(Deno.env.get("FACET_NETWORK") ?? "base").toLowerCase()] ??
  NETWORK_PROFILES.base;

// ---- chain constants: the profile is the default, an explicit FACET_* wins ---
const USDC = Deno.env.get("FACET_USDC_ADDRESS") ?? PROFILE.usdc;
const EXPECT_CHAIN = Number(Deno.env.get("FACET_EXPECT_CHAIN") ?? PROFILE.chain);
export const EXPECT_NETWORK = Deno.env.get("FACET_EXPECT_NETWORK") ?? PROFILE.network;
// The Boson escrow Diamond is the ERC-3009 recipient/spender the buyer's
// signature authorizes: the x402 SDK binds it as both `to` and `spender`
// (@bosonprotocol/x402-client signErc3009 -> { spender: requirements.escrowAddress }).
// It is network-scoped: one Diamond per network, and sellers are distinguished
// by recipientId, not by escrow, so it is a fixed, verifiable address for the
// expected chain, never a per-merchant value. Pinning it stops a hostile
// Terminal from getting the buyer to sign a payment whose recipient is the
// attacker's address while amount, token, and chain all still look correct.
// Default to the Diamond for the expected chain; override deliberately via env.
const BOSON_ESCROW_BY_CHAIN: Record<number, string> = {
  8453: "0x59A4C19b55193D5a2EAD0065c54af4d516E18Cb5", // Base mainnet Diamond
};
const BOSON_ESCROW = (Deno.env.get("FACET_BOSON_ESCROW") ?? BOSON_ESCROW_BY_CHAIN[EXPECT_CHAIN] ?? "").toLowerCase();
const TOKEN_DOMAIN_NAME = Deno.env.get("FACET_TOKEN_DOMAIN_NAME") ?? PROFILE.usdcDomainName;
const RPC = Deno.env.get("FACET_RPC") ?? PROFILE.rpc;
// Read a positive-number env var, falling back to `fallback` when the value is
// unset, non-numeric, or not greater than zero. A garbage FACET_MAX_USDC must
// never silently become NaN (which compares false against every cap) nor
// disable the ceiling; it falls back to the pinned default instead.
function posNumEnv(name: string, fallback: number): number {
  const raw = Deno.env.get(name);
  if (raw === undefined) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}
const DEFAULT_MAX_USDC = posNumEnv("FACET_MAX_USDC", 200);
// Absolute per-checkout ceiling. --max-usdc can only tighten below this, never
// raise above it, so a caller (or a coaxed agent) cannot lift the spend cap to
// an arbitrary value. Operator-pinned; override deliberately via env. A garbage
// override falls back to 200, never NaN, so the ceiling can never be disabled.
const MAX_USDC_CEILING = posNumEnv("FACET_MAX_USDC_CEILING", 200);
// The Facet directory is served by every live Terminal over the shared index;
// point at any one of them. Override for a private or test directory host.
const DIRECTORY_TERMINAL = Deno.env.get("FACET_DIRECTORY_TERMINAL") ?? "https://api.facet.llc";
const BOSON_HANDLER = "llc.facet.boson_escrow";
const X402_HANDLER = "llc.facet.x402";
// The JWS `typ` the Facet ledger stamps on a settlement receipt. Part of the
// wire contract: the verifier routes on it and refuses anything else.
const FACET_RECEIPT_TYP = "facet-receipt+jws";
// The reversal (cancel / withdraw / dispute / refund) receipt typ. A DISTINCT typ
// from the settlement receipt so a reversal can never be verified as a settlement
// (and vice versa); the Terminal's verifier enforces the same split.
const FACET_LIFECYCLE_TYP = "facet-lifecycle+jws";

// The Facet platform Terminal that holds the UCP platform signer and serves the
// origination surface (POST /ucp/v1/originated-checkouts). When the target
// merchant is first-party, CREATE and COMPLETE route THROUGH here: the platform,
// not the buyer, supplies the RFC 9421 co-signature a dual-auth store requires,
// and it forwards the buyer KYA verbatim as the merchant's KYA factor. The buyer
// still signs its own ERC-3009 payment client-side, so no key or fund custody
// ever reaches the server. Same host as the directory by default (one Fly app).
const PLATFORM_TERMINAL_URL = Deno.env.get("FACET_PLATFORM_TERMINAL") ?? PROFILE.platform;
// Host suffixes treated as first-party, mirroring the Terminal's own origination
// allowlist default (.facet.llc). A target whose host matches is routed through
// PLATFORM_TERMINAL_URL; anything else checks out buyer-direct, because the
// origination surface only relays to first-party merchants. Comma-separated.
const PLATFORM_ORIGINATION_SUFFIXES = (Deno.env.get("FACET_PLATFORM_ORIGINATION_SUFFIXES") ?? PROFILE.originationSuffixes)
  .split(",").map((s) => s.trim().toLowerCase()).filter((s) => s !== "");

// ---- tiny plumbing ---------------------------------------------------------
export const note = (m: string) => console.error("   " + m);
export function emit(obj: Record<string, unknown>): never {
  console.log(JSON.stringify(obj));
  Deno.exit(obj.ok === false ? 1 : 0);
}
export function die(error: string, extra: Record<string, unknown> = {}): never {
  emit({ ok: false, error, ...extra });
}

// Parse an UNTRUSTED external response body (merchant or Terminal) into a plain
// JSON object, or die with one clean error. A hostile or broken peer can return
// non-JSON (an HTML 502 page), the literal `null` (valid JSON, not an object),
// or a scalar. JSON.parse throws on the first and returns a non-object on the
// others, and every follow-on field access (j.results, session.payment_handlers,
// completion.status) would then throw an uncaught TypeError that breaks the
// one-JSON-object stdout contract. Every external parse funnels through here so
// the failure is a structured die, never a stack trace. `ctx` names the caller.
function parseJsonObjOrDie(text: string, ctx: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    die(`${ctx}: response was not valid JSON.`, { body: text.slice(0, 500) });
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    die(`${ctx}: response was not a JSON object.`, { body: text.slice(0, 500) });
  }
  return parsed as Record<string, unknown>;
}

function parseArgs(
  argv: string[],
): { cmd: string; sub: string; positional: string[]; flags: Record<string, string | boolean> } {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        flags[key] = true;
      } else {
        flags[key] = next;
        i++;
      }
    } else {
      positional.push(a);
    }
  }
  return { cmd: positional[0] ?? "", sub: positional[1] ?? "", positional, flags };
}

function requireFlag(flags: Record<string, string | boolean>, name: string): string {
  const v = flags[name];
  if (typeof v !== "string" || v === "") die(`missing required --${name}`);
  return v;
}

function hostOf(siteOrUrl: string): string {
  const s = siteOrUrl.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return s.trim().toLowerCase();
}
function terminalBase(url: string): string {
  // Trim first, then detect ANY scheme case-insensitively (RFC 3986 grammar) so
  // a mixed-case or padded value like " HTTP://x" cannot slip a bare host past
  // the prepend and end up malformed. Only when no scheme is present do we
  // assume https. The final URL must then be https:// (any case); anything else
  // (http, ftp, javascript) is refused: identity and checkout must ride TLS.
  const trimmed = url.trim();
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed);
  const u = hasScheme ? trimmed : `https://${trimmed}`;
  if (!/^https:\/\//i.test(u)) {
    die(`refusing a non-HTTPS Terminal URL: ${u}. Identity and checkout must ride TLS.`);
  }
  return u.replace(/\/+$/, "");
}

// True when a target merchant host is first-party (matches PLATFORM_ORIGINATION_
// SUFFIXES), meaning its checkout should route through the platform origination
// surface. A dotted suffix (".facet.llc") matches any subdomain; a bare suffix
// matches the host itself or a subdomain of it.
export function isFirstPartyTarget(targetUrl: string): boolean {
  const h = hostOf(targetUrl);
  return PLATFORM_ORIGINATION_SUFFIXES.some((suf) =>
    suf.startsWith(".") ? h.endsWith(suf) : h === suf || h.endsWith("." + suf)
  );
}

function kyaHeaders(kya?: string): Record<string, string> {
  const tok = kya ?? Deno.env.get("FACET_KYA") ?? "";
  if (tok === "") {
    die("no KYA available. Export your Facet KYA (an ES256 bearer token) as FACET_KYA, or select a wallet whose KYA env is set.");
  }
  return {
    authorization: `Bearer ${tok}`,
    "content-type": "application/json",
    "idempotency-key": crypto.randomUUID(),
  };
}

export async function usdcAtomic(addr: string): Promise<bigint> {
  const data = "0x70a08231" + addr.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const r = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: USDC, data }, "latest"] }),
  });
  const j = await r.json().catch(() => ({}));
  return BigInt((j as { result?: string }).result ?? "0x0");
}

// ---- wallet registry: choose which wallet shops ----------------------------
//   A user may hold more than one wallet. Selection happens BEFORE shopping,
//   like picking a card before checkout: the chosen wallet sets identity (its
//   KYA), spendable USDC, and the funds source. `wallets` lists each configured
//   wallet (label, address, USDC balance); the choice rides as --wallet <label>.
//   Keys are referenced by env var NAME and read in-process only; a key is never
//   printed, logged, or placed on a command line.
interface WalletEntry {
  label: string;
  key_env: string;
  kya_env: string;
}

function walletRegistry(): WalletEntry[] {
  const entries: WalletEntry[] = [];
  const raw = Deno.env.get("FACET_WALLETS");
  if (raw !== undefined && raw.trim() !== "") {
    try {
      const parsed = JSON.parse(raw) as Array<Partial<WalletEntry>>;
      for (const e of parsed) {
        if (typeof e.label === "string" && typeof e.key_env === "string") {
          entries.push({
            label: e.label,
            key_env: e.key_env,
            kya_env: typeof e.kya_env === "string" && e.kya_env !== "" ? e.kya_env : "FACET_KYA",
          });
        }
      }
    } catch {
      // malformed registry: fall through to the single default wallet below
    }
  }
  if (entries.length === 0) {
    entries.push({ label: "default", key_env: "FACET_WALLET_KEY", kya_env: "FACET_KYA" });
  }
  // Merge in wallets minted by `wallet new` (recorded in the non-secret discovery
  // index) so a persisted wallet is listable and usable by label without the user
  // declaring it in FACET_WALLETS. Each discovered wallet gets a conventional
  // per-label env name (FACET_WALLET_KEY for "default", else FACET_WALLET_KEY_<LABEL>)
  // that env can still override; when that var is unset, resolveWallet loads the key
  // from the keychain/keystore. Env-declared entries win on a label clash.
  for (const idx of readWalletIndex()) {
    if (entries.some((e) => e.label.toLowerCase() === idx.label.toLowerCase())) continue;
    const key_env = idx.label === "default"
      ? "FACET_WALLET_KEY"
      : `FACET_WALLET_KEY_${idx.label.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}`;
    entries.push({ label: idx.label, key_env, kya_env: "FACET_KYA" });
  }
  return entries;
}

interface ResolvedWallet {
  label: string;
  key: string;
  kya: string;
  address: string;
}

// Resolve the selected wallet's secrets IN-PROCESS (key + KYA + derived address).
// Used by `buy`, which needs both the signing key and the wallet-bound identity.
export function resolveWallet(label?: string): ResolvedWallet {
  const reg = walletRegistry();
  const entry = label !== undefined && label !== ""
    ? reg.find((e) => e.label.toLowerCase() === label.toLowerCase())
    : reg[0];
  if (entry === undefined) {
    die(`no wallet labeled "${label}". Configured: ${reg.map((e) => e.label).join(", ")}. Run \`wallets\` to list.`);
  }
  // The key comes from the environment when the env var is set (env wins), else
  // from the persisted store (keychain, then encrypted keystore) so a wallet
  // minted by `wallet new` is usable without exporting a key. Either way the key
  // stays in-process: it signs locally and is never printed or written out.
  let key = Deno.env.get(entry.key_env);
  if (key === undefined || key === "") {
    key = loadPersistedKey(entry.label);
  }
  if (key === undefined || key === "") {
    die(
      `wallet "${entry.label}" has no key: ${entry.key_env} is not set and no persisted key was ` +
        `found. Mint one with \`wallet new${
          entry.label === "default" ? "" : ` --label ${entry.label}`
        }\`, or export ${entry.key_env}.`,
    );
  }
  const address = privateKeyToAccount(key as `0x${string}`).address;
  return { label: entry.label, key, kya: Deno.env.get(entry.kya_env) ?? "", address };
}

// KYA header resolution for the browse legs (directory/search/product). Prefer the
// wallet's env token if usable, then the KYA cached by `provision`, and finally
// self-serve mint a fresh wallet-bound KYA from the Facet issuer. So a stale,
// expired, untrusted, absent, or uncached FACET_KYA self-heals into a fresh trusted
// token instead of being sent and rejected at the Terminal. Mirrors buy's identity
// self-heal; minting signs locally with the wallet key, which never leaves this process.
async function browseKyaHeaders(
  flags: Record<string, string | boolean>,
): Promise<Record<string, string>> {
  const label = typeof flags.wallet === "string" ? flags.wallet : undefined;
  const entry = (label === undefined || label === "")
    ? walletRegistry()[0]
    : walletRegistry().find((e) => e.label.toLowerCase() === label.toLowerCase());
  if (entry === undefined) {
    die(`no wallet labeled "${label}". Run \`wallets\` to list configured wallets.`);
  }
  const envKya = Deno.env.get(entry.kya_env);
  if (kyaUsable(envKya)) return kyaHeaders(envKya);
  const cached = readCachedKya(entry.label);
  if (kyaUsable(cached)) return kyaHeaders(cached);
  let key = Deno.env.get(entry.key_env);
  if (key === undefined || key === "") key = loadPersistedKey(entry.label);
  if (key === undefined || key === "") {
    die(
      `no trusted KYA for [${entry.label}] and no ${entry.key_env} or persisted key to mint one. ` +
        `Set a trusted, wallet-bound FACET_KYA, set the wallet key, or run \`wallet new\`.`,
    );
  }
  note(
    `no trusted KYA for [${entry.label}]; minting a fresh wallet-bound one from the Facet ` +
      `issuer (self-serve, no key leaves this process)`,
  );
  const minted = await provisionKya(key, { cacheKey: entry.label });
  return kyaHeaders(minted.token);
}

// ---- wallets: list the configured wallets so the user can choose ------------
async function cmdWallets(_flags: Record<string, string | boolean>): Promise<never> {
  const reg = walletRegistry();
  const wallets: Array<Record<string, unknown>> = [];
  for (const entry of reg) {
    const envKey = Deno.env.get(entry.key_env);
    let address: string | undefined;
    let source: "env" | "persisted" | undefined;
    let storage: string | undefined;
    if (envKey !== undefined && envKey !== "") {
      try {
        address = privateKeyToAccount(envKey as `0x${string}`).address;
        source = "env";
      } catch {
        wallets.push({
          label: entry.label,
          configured: false,
          note: `${entry.key_env} is not a valid key`,
        });
        continue;
      }
    } else {
      // No env key: a wallet minted by `wallet new` is listable from its PUBLIC
      // address in the discovery index, with NO key load and NO passphrase prompt.
      const idx = walletIndexEntry(entry.label);
      if (idx !== undefined) {
        address = idx.address;
        source = "persisted";
        storage = idx.storage;
      }
    }
    if (address === undefined) {
      wallets.push({
        label: entry.label,
        configured: false,
        note: `${entry.key_env} not set and no persisted wallet found`,
      });
      continue;
    }
    const bal = await usdcAtomic(address);
    const kya = Deno.env.get(entry.kya_env);
    wallets.push({
      label: entry.label,
      address,
      usdc_balance: Number(bal) / 1e6,
      network: EXPECT_NETWORK,
      kya_present: kya !== undefined && kya !== "",
      source,
      ...(storage !== undefined ? { storage } : {}),
      configured: true,
    });
  }
  emit({ ok: true, network: EXPECT_NETWORK, wallets });
}

// ---- discover: read the merchant's public agents.txt, then re-read the ------
//      Terminal's OWN canonical manifest as authoritative. A storefront copy
//      (e.g. a WooCommerce plugin re-serving stored options) can drift from
//      what the Terminal actually advertises; the Terminal generates the
//      canonical manifest per request, so it is the one owner of the fields.
async function fetchAgentsTxt(
  url: string,
): Promise<{ status: number; ok: boolean; text: string; error?: string }> {
  try {
    const res = await fetch(url, { headers: { accept: "text/plain" } });
    return { status: res.status, ok: res.ok, text: await res.text() };
  } catch (e) {
    return { status: 0, ok: false, text: "", error: String(e).slice(0, 120) };
  }
}

function manifestParsers(text: string) {
  const field = (name: string): string | undefined => {
    const m = text.match(new RegExp(`^${name}:\\s*(.+)$`, "im"));
    return m ? m[1].trim() : undefined;
  };
  const list = (name: string): string[] =>
    (field(name) ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  return { field, list };
}

// ---- provision: self-serve mint a wallet-bound KYA from the Facet issuer ----
//   Explicit, non-custodial provisioning: the chosen wallet signs a challenge
//   locally and the Facet issuer mints a KYA bound to that wallet (dual-auth
//   ready), on the self-serve path with NO issuer service key. The token is
//   cached (mode 600) and used automatically by search/buy for this wallet; it
//   is never printed. Use when a store rejects the current identity as untrusted.
async function cmdProvision(flags: Record<string, string | boolean>): Promise<never> {
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  note(
    `provisioning a wallet-bound KYA for [${wallet.label}] ${wallet.address} from the Facet ` +
      `issuer (self-serve, no key leaves this process)`,
  );
  try {
    const { claims } = await provisionKya(wallet.key, { cacheKey: wallet.label });
    emit({
      ok: true,
      wallet: wallet.label,
      address: wallet.address,
      iss: claims.iss ?? null,
      aid: claims.aid ?? null,
      payer_wallet: claims.payer_wallet ?? null,
      aud: claims.aud ?? null,
      exp: claims.exp ?? null,
      cached_at: cachePathFor(wallet.label),
      message:
        `Wallet-bound KYA minted and cached; search and buy use it automatically for this wallet. The token was not printed.`,
    });
  } catch (e) {
    die(`provision failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// email-pref: record the buyer's throwaway shipping-email choice ONCE so the
// agent never has to ask again. `set <address>` opts in and stores the address;
// `set --none` opts out (stored, so the agent stops asking); `show` prints the
// current preference as JSON. The address is buyer-provided and non-secret, so
// it may ride the command line (unlike a wallet key or KYA); it only ever lands
// on order_attributes.contact_email and authorizes nothing. Writes plain JSON under
// ~/.cache/facet, never the ~/.facet keystore. Synchronous (local file only).
function cmdEmailPref(
  sub: string,
  address: string | undefined,
  flags: Record<string, string | boolean>,
): never {
  if (sub === "show") {
    const pref = getShippingEmailPref();
    emit({
      ok: true,
      subcommand: "email-pref",
      asked: pref !== null,
      shipping_email_pref: pref === null ? "unset" : (pref.optedIn ? "opted_in" : "opted_out"),
      shipping_email: pref,
      prefs_path: orderPrefsFile(),
    });
  }
  if (sub === "set") {
    const optOut = flags.none === true;
    if (optOut && typeof address === "string" && address !== "") {
      die("email-pref set: pass either <address> to opt in, or --none to decline, not both.");
    }
    if (optOut) {
      setShippingEmailPref({ optedIn: false, address: null });
      emit({
        ok: true,
        subcommand: "email-pref",
        shipping_email_pref: "opted_out",
        shipping_email: { optedIn: false, address: null },
        message: "Shipping-confirmation emails will stay off. The agent will not ask again.",
        prefs_path: orderPrefsFile(),
      });
    }
    if (typeof address !== "string" || address === "") {
      die("email-pref set <address>: provide a throwaway email to opt in, or --none to decline.");
    }
    const addr = address.trim();
    if (!isPlausibleEmail(addr)) {
      die("email-pref set: that does not look like a valid email address.");
    }
    setShippingEmailPref({ optedIn: true, address: addr });
    emit({
      ok: true,
      subcommand: "email-pref",
      shipping_email_pref: "opted_in",
      shipping_email: { optedIn: true, address: addr },
      message:
        `Stored ${addr} for shipping confirmations. It will be reused on every future order and the agent will not ask again.`,
      prefs_path: orderPrefsFile(),
    });
  }
  die(`email-pref: unknown action "${sub}". Use: email-pref set <address> | email-pref set --none | email-pref show.`);
}

async function cmdDiscover(flags: Record<string, string | boolean>): Promise<never> {
  const host = hostOf(requireFlag(flags, "site"));
  const storeUrl = `https://${host}/.well-known/agents.txt`;
  note(`GET ${storeUrl}`);
  const store = await fetchAgentsTxt(storeUrl);
  if (store.status === 0) die(`could not reach ${host}: ${store.error}`);
  if (store.status === 404) {
    die(`no Facet Terminal at ${host} (agents.txt 404). This site is not Facet-enabled.`, {
      facet_enabled: false,
    });
  }
  if (!store.ok) die(`agents.txt returned HTTP ${store.status}`, { body: store.text.slice(0, 200) });

  const terminal = manifestParsers(store.text).field("Terminal");
  if (terminal === undefined) die("agents.txt present but advertises no Terminal URL.");

  // Re-read the manifest at the Terminal's own host and trust it over the
  // storefront copy. Skip when the Terminal is this same host (already
  // canonical) or when the canonical fetch does not return a real manifest.
  const termHost = hostOf(terminal);
  let manifest = store.text;
  let source = "storefront";
  if (termHost !== "" && termHost !== host) {
    const canonUrl = `https://${termHost}/.well-known/agents.txt`;
    note(`GET ${canonUrl} (canonical)`);
    const canon = await fetchAgentsTxt(canonUrl);
    if (canon.ok && /^Facet-Version:/im.test(canon.text)) {
      manifest = canon.text;
      source = "terminal";
    } else {
      note(`canonical manifest unavailable (HTTP ${canon.status}); using storefront copy`);
    }
  }

  const { field, list } = manifestParsers(manifest);
  emit({
    ok: true,
    facet_enabled: true,
    site: host,
    manifest_source: source,
    terminal: field("Terminal") ?? terminal,
    kya_issuers: list("KYA-Issuers"),
    checkout: field("Checkout"),
    commerce_rails: list("Commerce-Rails"),
    capabilities: list("Capabilities"),
    ucp_profile_url: field("UCP-Profile-URL"),
    mcp_endpoint: field("MCP-Endpoint"),
    rate_limit: field("Rate-Limit"),
  });
}

// ---- directory: search the Facet directory for merchants, and which of them
//      run a live Terminal. The directory is Facet's index, not open data, so
//      it is identity-gated: it wants a valid FACET_KYA (a plain agents.txt
//      resolve does not). Each result's `terminal_url` is a real, checkout-able
//      Terminal when present, and null when the merchant is listed but not yet
//      Facet-enabled. This is the "does this merchant have a Terminal" answer
//      at network scale; for a single named host, `discover --site` is the
//      authoritative per-host resolve.
async function cmdDirectory(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(
    typeof flags.terminal === "string" ? flags.terminal : DIRECTORY_TERMINAL,
  );
  const body: Record<string, unknown> = {};
  if (typeof flags.query === "string") body.query = flags.query;
  if (typeof flags.near === "string") {
    const [lat, lng] = flags.near.split(",").map((s) => Number(s.trim()));
    if (Number.isFinite(lat) && Number.isFinite(lng)) body.near = { lat, lng };
  }
  if (typeof flags["radius-km"] === "string") body.radius_km = Number(flags["radius-km"]);
  if (typeof flags.capabilities === "string") {
    body.capabilities = flags.capabilities.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  }
  if (typeof flags.taxonomy === "string") {
    body.taxonomy = flags.taxonomy.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  }
  if (typeof flags["min-reputation"] === "string") body.min_reputation = Number(flags["min-reputation"]);
  if (flags["claimed-only"] === true) body.claimed_only = true;
  body.limit = flags.limit !== undefined ? Number(flags.limit) : 20;

  const hasFilter = "query" in body || "near" in body || "capabilities" in body ||
    "taxonomy" in body || "min_reputation" in body || body.claimed_only === true;
  if (!hasFilter) {
    die(
      "directory needs at least one filter: --query, --near <lat,lng>, --capabilities, --taxonomy, --min-reputation, or --claimed-only.",
    );
  }

  note(`POST ${base}/v1/discover`);
  const r = await fetch(`${base}/v1/discover`, { method: "POST", headers: await browseKyaHeaders(flags), body: JSON.stringify(body) });
  const text = await r.text();
  if (r.status === 401 || r.status === 402 || r.status === 403) {
    die(`the Facet directory is identity-gated; set a valid FACET_KYA first (HTTP ${r.status}).`, {
      http_status: r.status,
    });
  }
  if (!r.ok) die(`directory search failed HTTP ${r.status}`, { body: text.slice(0, 400) });
  const j = parseJsonObjOrDie(text, "directory search") as {
    results?: Array<Record<string, unknown>>;
    total_estimate?: number;
    next_offset?: number | null;
  };
  const results = j.results ?? [];
  const withTerminal = results.filter(
    (x) => typeof x.terminal_url === "string" && x.terminal_url !== "",
  ).length;
  emit({
    ok: true,
    count: results.length,
    with_terminal: withTerminal,
    total_estimate: j.total_estimate ?? null,
    next_offset: j.next_offset ?? null,
    results,
  });
}

// ---- search: the merchant's own catalog (KYA-authenticated) ----------------
async function cmdSearch(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const body: Record<string, unknown> = {};
  if (typeof flags.query === "string") body.query = flags.query;
  if (typeof flags.category === "string") body.category = flags.category;
  if (typeof flags.tags === "string") body.tags = flags.tags.split(",").map((s) => s.trim());
  if (typeof flags.cursor === "string") body.cursor = flags.cursor;
  body.limit = flags.limit !== undefined ? Number(flags.limit) : 20;

  note(`POST ${base}/v1/search`);
  const r = await fetch(`${base}/v1/search`, { method: "POST", headers: await browseKyaHeaders(flags), body: JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) die(`search failed HTTP ${r.status}`, { body: text.slice(0, 400) });
  const j = parseJsonObjOrDie(text, "search") as { results?: unknown[]; next_cursor?: unknown };
  emit({ ok: true, results: j.results ?? [], next_cursor: j.next_cursor ?? null });
}

// ---- product: one product's detail (KYA-authenticated) ---------------------
async function cmdProduct(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const id = requireFlag(flags, "id");
  note(`POST ${base}/v1/get_product (${id})`);
  const r = await fetch(`${base}/v1/get_product`, {
    method: "POST",
    headers: await browseKyaHeaders(flags),
    body: JSON.stringify({ product_id: id }),
  });
  const text = await r.text();
  if (!r.ok) die(`get_product failed HTTP ${r.status}`, { body: text.slice(0, 400) });
  emit({ ok: true, product: parseJsonObjOrDie(text, "get_product") });
}

// ---- buy: create checkout, sign locally, DRY (default) or settle -----------
interface ShipInput {
  recipient: string;
  line1: string;
  locality: string;
  region: string;
  postal_code: string;
  country: string;
}
interface CartItem {
  id: string;
  qty: number;
}

// Validate the SELLER-SIGNED offer object that the x402 SDK will actually sign
// and settle. Per the SDK contract, ERC-3009 binds the offer object's OWN
// top-level `amount` (atomic, decimal string), `asset` (token address), and
// `network` (CAIP-2 eip155:<chainId>). It does NOT bind the checkout's sibling
// display scalars (price_atomic / chain_id / network), so those three offer
// fields are checked here directly: against the price we displayed, the cap,
// the expected USDC token, and the expected chain. Without this, a hostile
// Terminal could show a small price_atomic while embedding a larger `amount`
// in the offer object it gets us to sign. Throws on any mismatch; the caller
// turns the throw into a die(). Exported so an offline unit test can exercise
// the honest pass and each attack-refused vector with no secrets and no network.
export function assertOfferMatches(
  requirements: Record<string, unknown>,
  expect: { priceAtomic: number; capAtomic: number; usdc: string; chainId: number; escrow: string },
): void {
  // The SDK signs the offer's OWN `amount` field as an atomic uint. Require a
  // canonical decimal-integer STRING (^\d+$) before comparing numerically, so
  // the value this validator reads and the value ERC-3009 signs cannot diverge:
  // scientific notation ("5e6"), hex ("0x4C4B40"), a fractional atomic, padded
  // whitespace, or a leading sign would all parse under Number() yet settle a
  // different amount on chain. Anything that is not a plain positive integer
  // string is refused with the same "not a positive number" message.
  const amountRaw = requirements["amount"];
  const amount = Number(amountRaw);
  if (typeof amountRaw !== "string" || !/^\d+$/.test(amountRaw) || !Number.isFinite(amount) || amount <= 0) {
    throw new Error(`offer amount "${String(amountRaw)}" is not a positive number.`);
  }
  if (amount !== expect.priceAtomic) {
    throw new Error(
      `offer amount ${amount} does not match the advertised and confirmed price ${expect.priceAtomic} (atomic). Refusing.`,
    );
  }
  if (amount > expect.capAtomic) {
    throw new Error(`offer amount ${amount / 1e6} USDC exceeds the ${expect.capAtomic / 1e6} USDC cap. Refusing.`);
  }
  const asset = String(requirements["asset"] ?? "").toLowerCase();
  if (asset !== expect.usdc.toLowerCase()) {
    throw new Error(`offer asset ${asset || "(none)"} is not the expected USDC token ${expect.usdc}. Refusing.`);
  }
  const net = String(requirements["network"] ?? "");
  if (net !== `eip155:${expect.chainId}`) {
    throw new Error(`offer network "${net}" is not eip155:${expect.chainId}. Refusing.`);
  }
  // The escrowAddress is the ERC-3009 recipient/spender the buyer's signature
  // authorizes: the SDK binds it as both `to` and `spender`. A hostile Terminal
  // that swapped it for its own address would get the buyer to authorize a
  // payment straight to the attacker while amount, token, and chain all still
  // look correct. Pin it to the expected Boson escrow Diamond for this chain;
  // this is the recipient binding, and it is the last thing checked so the
  // narrower term mismatches above report first. Fail closed when no expected
  // escrow is configured (unknown chain, no env override) rather than comparing
  // against an empty string and refusing every offer with an opaque message.
  if (expect.escrow === "") {
    throw new Error(
      `no expected Boson escrow Diamond is configured for chain ${expect.chainId}; set FACET_BOSON_ESCROW. Refusing.`,
    );
  }
  const escrow = String(requirements["escrowAddress"] ?? "").toLowerCase();
  if (escrow !== expect.escrow) {
    throw new Error(
      `offer escrowAddress ${escrow || "(none)"} is not the expected Boson escrow Diamond ${expect.escrow}. Refusing.`,
    );
  }
}

// The x402-direct sibling of assertOfferMatches. Before the buyer signs an
// ERC-3009 TransferWithAuthorization straight to a merchant pay_to (no escrow,
// no buyer protection), validate the server-advertised x402 terms against the
// buyer's OWN expectations. A hostile or compromised Terminal must not be able
// to redirect funds to a different recipient, swap the asset, change the chain
// or EIP-712 domain, or inflate the amount past the per-checkout cap. Throws on
// any mismatch; the caller turns the throw into a die(). Returns the atomic
// price on success. Exported so an offline unit test exercises the honest pass
// and each attack-refused vector with no secrets and no network.
export function assertX402Terms(
  adv: { payTo: string; amountAtomic: string; domainName: string; asset: string; chainId: number },
  expect: { chainId: number; domainName: string; usdc: string; capAtomic: number; capUsdc: number },
): number {
  // The recipient the ERC-3009 authorization pays (signed as `to`). A malformed
  // or empty value is refused before any signature is produced.
  const payTo = adv.payTo.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(payTo)) {
    throw new Error(`x402 offer has no valid pay_to (${adv.payTo || "none"}). Refusing.`);
  }
  // Chain plus EIP-712 domain bind the signature to one token contract on one
  // chain; a wrong chain or domain authorizes a transfer the buyer never meant.
  if (adv.chainId !== expect.chainId || adv.domainName !== expect.domainName) {
    throw new Error(
      `x402 offer is chain ${adv.chainId} / domain "${adv.domainName}", expected ` +
        `${expect.chainId} / "${expect.domainName}". Refusing.`,
    );
  }
  // The token contract the authorization is signed against (verifyingContract).
  if (adv.asset.toLowerCase() !== expect.usdc.toLowerCase()) {
    throw new Error(
      `x402 offer asset ${adv.asset || "(none)"} is not the expected USDC token ${expect.usdc}. Refusing.`,
    );
  }
  // Require a canonical decimal-integer atomic amount (^\d+$) before comparing
  // numerically, so the value this validator reads under Number() and the value
  // ERC-3009 signs under BigInt() cannot diverge: scientific notation ("5e6"),
  // hex ("0x4C4B40"), a fractional atomic, padded whitespace, or a leading sign
  // would each parse differently across the two. Same guard as assertOfferMatches.
  const priceAtomic = Number(adv.amountAtomic);
  if (!/^\d+$/.test(adv.amountAtomic) || !Number.isFinite(priceAtomic) || !(priceAtomic > 0)) {
    throw new Error(`x402 amount "${adv.amountAtomic}" is not a positive number. Refusing.`);
  }
  if (priceAtomic > expect.capAtomic) {
    throw new Error(
      `x402 amount ${priceAtomic / 1e6} USDC exceeds the ${expect.capUsdc} USDC cap. Raise --max-usdc only if intended.`,
    );
  }
  return priceAtomic;
}

// Map a FACET_RAIL preference to an explicit UCP rail_id, or undefined to let
// the Terminal pick the merchant's OMS-keyed default (Shopify => x402-direct,
// Woo => Boson escrow). "x402" forces the direct coin rail on the active
// network; "boson" forces escrow; anything else (including "auto") defers to the
// site default. Pure and exported for offline testing.
export function forcedRailIdFor(railPref: string, network: string): string | undefined {
  const p = railPref.toLowerCase();
  if (p === "x402") return `coin/usdc-${network}`;
  if (p === "boson") return "coin/boson-escrow";
  return undefined;
}

// Choose which advertised rail to settle. The Terminal advertises every rail it
// supports in one payment_handlers map with a `default_rail` naming the merchant's
// own default (a WooCommerce store defaults to Boson escrow, a Shopify store to
// x402-direct). Honor that default so a Boson-default store is NEVER silently
// downgraded to x402-direct, which carries no escrow and no buyer protection.
// FACET_RAIL forces a specific rail; when the default is absent, prefer escrow
// (buyer protection), matching the Terminal's own fallback. Pure and exported so an
// offline test locks the precedence with no network.
export function chooseRail(
  railPref: string,
  defaultRail: string | undefined,
  hasX402: boolean,
  hasBoson: boolean,
): "x402" | "boson" | undefined {
  const forced = railPref.toLowerCase();
  if (forced === "x402") return hasX402 ? "x402" : undefined;
  if (forced === "boson") return hasBoson ? "boson" : undefined;
  if (defaultRail === X402_HANDLER && hasX402) return "x402";
  if (defaultRail === BOSON_HANDLER && hasBoson) return "boson";
  if (hasBoson) return "boson";
  if (hasX402) return "x402";
  return undefined;
}

// Validate the checkout's sibling DISPLAY scalars (price_atomic, chain_id) that
// the skill reads before it ever sees the seller-signed offer: they gate the
// balance check and, for price, feed BigInt(priceAtomic) downstream. A merchant
// (or a hostile Terminal) can return a fractional, scientific, hex, zero, or
// oversized value here; Number() would accept 5.5 or 5e6, and BigInt(5.5) then
// throws an uncaught RangeError that breaks the one-JSON-object stdout contract.
// Refuse anything that is not a canonical positive-integer decimal string.
// Exported so an offline unit test can exercise each rejected form with no
// secrets and no network.
export function assertDisplayScalarsSane(
  boson: Record<string, unknown>,
): { priceAtomic: number; chainId: number } {
  const priceRaw = boson["price_atomic"];
  if (!/^\d+$/.test(String(priceRaw))) {
    throw new Error(`merchant price_atomic "${String(priceRaw)}" is not a canonical atomic integer.`);
  }
  const priceAtomic = Number(priceRaw);
  if (!Number.isSafeInteger(priceAtomic) || priceAtomic <= 0) {
    throw new Error(`merchant price_atomic ${priceAtomic} is not a positive safe integer.`);
  }
  const chainRaw = boson["chain_id"];
  if (!/^\d+$/.test(String(chainRaw))) {
    throw new Error(`merchant chain_id "${String(chainRaw)}" is not a canonical integer.`);
  }
  return { priceAtomic, chainId: Number(chainRaw) };
}

// Pull the actionable reason out of a Terminal error body. The Terminal wraps
// auth failures as { error: { code: "UNAUTHORIZED", message: <reason> } }, so
// the reason to key on (e.g. "signature_missing") lives in error.message, not
// error.code; flatter or older shapes carry it at top-level code/error. Read
// every shape so co-signature detection fires regardless of which one comes back.
export function errorReason(text: string): string {
  try {
    const j = JSON.parse(text) as {
      code?: string;
      error?: string | { code?: string; message?: string };
    };
    if (j.error !== null && typeof j.error === "object") {
      return String(j.error.message ?? j.error.code ?? "");
    }
    return String(j.code ?? j.error ?? "");
  } catch {
    return "";
  }
}

async function cmdBuy(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  let items: CartItem[];
  try {
    items = JSON.parse(requireFlag(flags, "items")) as CartItem[];
  } catch {
    die("--items must be valid JSON: an array of {id, qty}.");
  }
  if (!Array.isArray(items) || items.length === 0) die("--items must be a non-empty JSON array of {id, qty}.");
  for (const c of items) {
    if (typeof c?.id !== "string" || c.id === "") die("each --items entry needs a non-empty string id.");
    if (!Number.isInteger(c?.qty) || c.qty <= 0) die(`--items qty for "${c?.id}" must be a positive integer.`);
  }
  let ship: ShipInput;
  try {
    ship = JSON.parse(requireFlag(flags, "ship")) as ShipInput;
  } catch {
    die("--ship must be valid JSON: recipient, line1, locality, region, postal_code, country.");
  }
  for (const k of ["recipient", "line1", "locality", "region", "postal_code", "country"] as const) {
    if (typeof ship[k] !== "string" || ship[k] === "") die(`--ship is missing "${k}".`);
  }
  // Buyer-supplied order attributes (gift message, delivery date, occasion) ride the
  // COMPLETE body and are applied to the merchant order at settle: the Terminal
  // validates and length-caps them, and the Woo adapter maps gift_message to the
  // order note and delivery_date to the requested delivery date. Display-only, never
  // priced, and never blocks settlement.
  const orderAttributes: Record<string, string> = {};
  if (typeof flags["gift-message"] === "string" && flags["gift-message"] !== "") {
    orderAttributes.gift_message = flags["gift-message"];
  }
  if (typeof flags["delivery-date"] === "string" && flags["delivery-date"] !== "") {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(flags["delivery-date"])) {
      die("--delivery-date must be an ISO date (YYYY-MM-DD).");
    }
    orderAttributes.delivery_date = flags["delivery-date"];
  }
  if (typeof flags.occasion === "string" && flags.occasion !== "") {
    orderAttributes.occasion = flags.occasion;
  }
  // Throwaway shipping-email preference (ask once, reuse forever). The chosen
  // address rides order_attributes.contact_email (the pinned contract); the Terminal
  // side threads it to the merchant order and un-suppresses the shipping-
  // confirmation email. Precedence: a one-shot --shipping-email overrides for
  // THIS purchase without changing the stored default; otherwise the stored
  // preference decides (opted in attaches the saved address, opted out or never
  // asked attaches nothing). The address is buyer-provided; a Facet-generated
  // relay alias is a future follow-up. shippingEmailSignal is surfaced in the
  // buy result so the agent knows to ask once when the preference is "unset".
  const shipEmailFlag = flags["shipping-email"];
  let shipEmailOverride: string | null = null;
  if (typeof shipEmailFlag === "string" && shipEmailFlag !== "") {
    if (!isPlausibleEmail(shipEmailFlag)) {
      die("--shipping-email must be a plausible email address.");
    }
    shipEmailOverride = shipEmailFlag.trim();
  }
  const shippingEmailSignal = attachShippingEmail(orderAttributes, shipEmailOverride, getShippingEmailPref());
  const hasOrderAttributes = Object.keys(orderAttributes).length > 0;
  const requestedCap = flags["max-usdc"] !== undefined ? Number(flags["max-usdc"]) : DEFAULT_MAX_USDC;
  if (!Number.isFinite(requestedCap) || requestedCap <= 0) die("--max-usdc must be a positive number.");
  const capUsdc = Math.min(requestedCap, MAX_USDC_CEILING);
  if (capUsdc < requestedCap) {
    note(`--max-usdc ${requestedCap} exceeds the ${MAX_USDC_CEILING} USDC ceiling; clamping to ${capUsdc}.`);
  }
  const capAtomic = Math.round(capUsdc * 1e6);
  const settle = flags.settle === true;

  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  // Resolve a trusted, wallet-bound KYA for this checkout. Use the wallet's env
  // token if it is usable (trusted issuer, unexpired, bound to this wallet),
  // else a cached one, else self-serve mint a fresh one from the Facet issuer
  // (wallet-bound; no key leaves this process). This makes a stale, absent, or
  // untrusted FACET_KYA self-heal instead of failing the checkout.
  let buyKya = kyaUsable(wallet.kya, wallet.address) ? wallet.kya : "";
  if (buyKya === "") {
    const cached = readCachedKya(wallet.label);
    if (kyaUsable(cached, wallet.address)) buyKya = cached as string;
  }
  if (buyKya === "") {
    note(
      `no trusted wallet-bound KYA for [${wallet.label}] ${wallet.address}; minting one ` +
        `from the Facet issuer (self-serve, wallet-bound, no key leaves this process)`,
    );
    try {
      buyKya = (await provisionKya(wallet.key, { cacheKey: wallet.label })).token;
    } catch (e) {
      die(`could not provision a wallet-bound KYA: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const account = privateKeyToAccount(wallet.key as `0x${string}`);
  note(`buyer wallet [${wallet.label}]: ${account.address}`);

  const balance = await usdcAtomic(account.address);
  note(`buyer USDC: ${Number(balance) / 1e6}`);

  // ---- CREATE (KYA-authenticated; quote + hold, no money) ----
  const [firstName, ...restName] = ship.recipient.trim().split(/\s+/);
  const destination = {
    id: "d1",
    first_name: firstName,
    last_name: restName.join(" "),
    street_address: ship.line1,
    address_locality: ship.locality,
    address_region: ship.region,
    postal_code: ship.postal_code,
    address_country: ship.country,
  };
  // Rail selection. Default (auto): send no rail_id and let the Terminal pick the
  // merchant's OMS-keyed default (Shopify => x402-direct, Woo => Boson escrow), then
  // this client adapts to whichever handler the CREATE advertises. FACET_RAIL forces
  // a rail via an explicit rail_id (the Terminal honors it over the site default),
  // which is how a Shopify x402-direct checkout is exercised on a plane whose site
  // default has not been set to x402 yet.
  const forcedRailId = forcedRailIdFor(Deno.env.get("FACET_RAIL") ?? "auto", EXPECT_NETWORK);
  const createBody = {
    line_items: items.map((c) => ({ item: { id: c.id }, quantity: c.qty })),
    fulfillment: { methods: [{ type: "shipping", destinations: [destination] }] },
    ...(forcedRailId !== undefined ? { rail_id: forcedRailId } : {}),
  };

  // Route the checkout. For a first-party merchant, go THROUGH the Facet platform
  // origination surface: the platform holds the UCP platform key and adds the
  // RFC 9421 co-signature a dual-auth store requires, forwarding our buyer KYA
  // verbatim as the merchant's KYA factor. The buyer still signs its own payment
  // client-side on COMPLETE, so no key or custody reaches the server. A
  // non-first-party merchant is not relayed (origination is first-party only), so
  // it checks out buyer-direct. If origination is not provisioned yet (404), fall
  // back to buyer-direct so a store that accepts a buyer-only checkout still
  // works. Track which path served CREATE so COMPLETE settles on the same one.
  const firstParty = isFirstPartyTarget(base);
  const directCreateUrl = `${base}/ucp/v1/checkout-sessions`;
  let usedPlatform = false;
  let createRes: Response;
  let createText: string;
  if (firstParty) {
    const originateUrl = `${terminalBase(PLATFORM_TERMINAL_URL)}/ucp/v1/originated-checkouts`;
    note(`POST ${originateUrl}  (platform-originated -> ${base})`);
    createRes = await fetch(originateUrl, {
      method: "POST",
      headers: kyaHeaders(buyKya),
      body: JSON.stringify({ target: base, checkout: createBody }),
    });
    createText = await createRes.text();
    if (createRes.status === 404 && /origination/i.test(errorReason(createText))) {
      note(`platform origination not provisioned (404); falling back to buyer-direct CREATE`);
      note(`POST ${directCreateUrl}`);
      createRes = await fetch(directCreateUrl, {
        method: "POST",
        headers: kyaHeaders(buyKya),
        body: JSON.stringify(createBody),
      });
      createText = await createRes.text();
    } else {
      usedPlatform = true;
    }
  } else {
    note(`POST ${directCreateUrl}`);
    createRes = await fetch(directCreateUrl, {
      method: "POST",
      headers: kyaHeaders(buyKya),
      body: JSON.stringify(createBody),
    });
    createText = await createRes.text();
  }
  if (createRes.status !== 201) {
    if ((createRes.status === 401 || createRes.status === 403) && /signature/i.test(errorReason(createText))) {
      die(
        `this store requires a platform co-signature. ` +
          (usedPlatform
            ? `The platform relayed the checkout but the store still rejected it.`
            : firstParty
            ? `Platform origination is not enabled here, so the checkout went buyer-direct and was refused.`
            : `This merchant is not first-party, so platform origination does not apply.`),
        {
          reason: "platform_cosignature_required",
          http_status: createRes.status,
          via_platform: usedPlatform,
          first_party: firstParty,
        },
      );
    }
    die(`checkout CREATE failed HTTP ${createRes.status}`, { body: createText.slice(0, 500) });
  }
  const session = parseJsonObjOrDie(createText, "checkout CREATE") as {
    id: string;
    payment_handlers?: Record<string, Array<{ config?: Record<string, unknown> }>>;
    default_rail?: string;
  };
  const handlers = session.payment_handlers ?? {};
  const x402cfg = handlers[X402_HANDLER]?.[0]?.config;
  const boson = handlers[BOSON_HANDLER]?.[0]?.config;
  // Choose the rail to settle. The Terminal advertises every rail it supports in one
  // payment_handlers map plus a `default_rail` naming the merchant's own default (a
  // WooCommerce store defaults to Boson escrow). Honor that default so a Boson-default
  // store is NEVER silently downgraded to x402-direct (no escrow, no buyer protection);
  // FACET_RAIL forces a specific rail when set.
  const railArm = chooseRail(
    Deno.env.get("FACET_RAIL") ?? "auto",
    typeof session.default_rail === "string" ? session.default_rail : undefined,
    x402cfg !== undefined,
    boson !== undefined,
  );
  if (railArm === undefined) {
    const advertised = Object.keys(handlers);
    die(`no supported payment rail on this checkout (advertised: ${advertised.join(", ") || "none"}).`, {
      advertised_rails: advertised,
    });
  }
  if (railArm === "x402" && x402cfg !== undefined) {
    // ==== x402-direct settlement path ======================================
    // ONE code path for both planes (FACET_NETWORK selects chain/USDC/domain), a
    // proxy of the mainnet x402 walker scripts/x402-demo/pnp-ucp-2item-mainnet.ts.
    // The buyer's ERC-3009 authorizes USDC straight to the merchant pay_to (no
    // escrow, no buyer protection): Facet custodies neither funds nor keys. The
    // platform RFC 9421 co-signature is added by the origination surface, same as
    // the boson path; only the payment instrument differs.
    const advPayTo = String(x402cfg["pay_to"] ?? "").toLowerCase();
    const advAmount = String(x402cfg["amount_atomic"] ?? "");
    const advDomain = (x402cfg["eip712_domain"] ?? {}) as { name?: string; version?: string };
    const advAsset = String(x402cfg["asset_address"] ?? USDC);
    const advChain = Number(x402cfg["chain_id"] ?? EXPECT_CHAIN);
    // ---- hard guardrails on the server-advertised x402 terms: the choke point
    // before any signature. assertX402Terms is the x402 sibling of
    // assertOfferMatches; it refuses a bad recipient, wrong chain or domain, a
    // swapped asset, or a non-canonical / over-cap amount, so a hostile Terminal
    // cannot redirect or inflate the transfer the buyer is about to sign. ----
    let priceAtomic: number;
    try {
      priceAtomic = assertX402Terms(
        { payTo: advPayTo, amountAtomic: advAmount, domainName: advDomain.name ?? "", asset: advAsset, chainId: advChain },
        { chainId: EXPECT_CHAIN, domainName: TOKEN_DOMAIN_NAME, usdc: USDC, capAtomic, capUsdc },
      );
    } catch (e) {
      die(`GUARDRAIL: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (balance < BigInt(priceAtomic)) {
      die(`insufficient USDC: buyer holds ${Number(balance) / 1e6}, needs ${priceAtomic / 1e6}.`);
    }
    // ---- what the guardrail does NOT bind (the x402-direct recipient), and why
    // that is acceptable ----
    // assertX402Terms binds HOW MUCH, in WHICH token, on WHICH chain and domain.
    // It does not pin WHERE the money goes: unlike a Boson commit (which always
    // settles into the known escrow Diamond), an x402-direct transfer pays the
    // merchant's own pay_to, which is per-merchant and server-advertised, with no
    // authoritative registry the client could check it against. A hostile Terminal
    // could therefore advertise its own address. The residual is bounded and
    // surfaced: bounded because the transfer can never exceed the per-checkout USDC
    // cap, and surfaced because the DRY summary prints pay_to and the exact amount
    // and SETTLE requires an explicit --confirm of that amount, so a human sees the
    // recipient before any money moves. This is inherent to the no-escrow rail (the
    // x402 model has the client trust the server-advertised payTo); the Boson escrow
    // rail is the option for buyer protection.
    // ---- sign the buyer's ERC-3009 TransferWithAuthorization LOCALLY ----
    const nonce = ("0x" +
      Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")) as `0x${string}`;
    const nowSec = Math.floor(Date.now() / 1000);
    const validAfter = String(nowSec - 30);
    const validBefore = String(nowSec + 300);
    const authorization = {
      from: account.address.toLowerCase() as `0x${string}`,
      to: advPayTo as `0x${string}`,
      value: advAmount,
      validAfter,
      validBefore,
      nonce,
    };
    const erc3009Signature = await account.signTypedData({
      domain: {
        // Pin the ENTIRE EIP-712 domain to client-side constants, never the
        // server-advertised values. assertX402Terms already proved advDomain.name
        // and advAsset equal these, so an honest Terminal is unchanged; a hostile
        // one cannot steer the signature onto a different domain (a wrong version,
        // which the term check does not read, would otherwise let it sign a
        // griefing blob). The real USDC contract recomputes this same domain from
        // its own immutable name/version/chain/address, so only a signature over
        // these exact constants is executable.
        name: TOKEN_DOMAIN_NAME,
        version: "2",
        chainId: EXPECT_CHAIN,
        verifyingContract: USDC as `0x${string}`,
      },
      types: {
        TransferWithAuthorization: [
          { name: "from", type: "address" },
          { name: "to", type: "address" },
          { name: "value", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      },
      primaryType: "TransferWithAuthorization",
      message: {
        from: authorization.from,
        to: authorization.to,
        value: BigInt(advAmount),
        validAfter: BigInt(validAfter),
        validBefore: BigInt(validBefore),
        nonce,
      },
    } as Parameters<typeof account.signTypedData>[0]);
    note(
      `buyer commit signed locally (ERC-3009 x402-direct, own wallet -> pay_to ${advPayTo}, ` +
        `domain "${TOKEN_DOMAIN_NAME}" v2)`,
    );
    // The x402 credential + instrument, inlined from @facet-llc/ucp
    // buildX402Credential / buildX402Instrument (that package is repo-local, not
    // published, so it is reproduced byte-for-byte here). instruments[0].kya carries
    // the wallet-bound buyer KYA the dual-auth COMPLETE binds (extractInstrumentKya),
    // exactly as the boson path does.
    const xPaymentBase64 = btoa(
      JSON.stringify({
        x402Version: 1,
        scheme: "exact",
        network: EXPECT_NETWORK,
        payload: { signature: erc3009Signature, authorization },
      }),
    );
    const x402Instrument = {
      id: `instr_x402_${nowSec}`,
      handler_id: X402_HANDLER,
      type: "x402_authorization",
      selected: true,
      kya: buyKya,
      credential: {
        type: "x402_authorization",
        token: xPaymentBase64,
        expiry: new Date(Number(validBefore) * 1000).toISOString(),
        network: EXPECT_NETWORK,
        scheme: "exact",
        x402_version: 1,
      },
      display: { rail: "x402", network: EXPECT_NETWORK, pay_to: advPayTo },
    };
    const summary = {
      checkout_id: session.id,
      chain_id: EXPECT_CHAIN,
      network: EXPECT_NETWORK,
      price_atomic: priceAtomic,
      price_usdc: priceAtomic / 1e6,
      pay_to: advPayTo,
      asset: advAsset,
      buyer: account.address,
      balance_usdc: Number(balance) / 1e6,
      rail: X402_HANDLER,
      items,
      ...(hasOrderAttributes ? { order_attributes: orderAttributes } : {}),
      shipping_email_pref: shippingEmailSignal,
    };
    // ---- DRY (default): stop before COMPLETE. Nothing moved. ----
    if (!settle) {
      emit({
        ok: true,
        mode: "DRY",
        ...summary,
        signed: true,
        settled: false,
        confirm_atomic: priceAtomic,
        confirm_pay_to: advPayTo,
        next: `to settle: buy ... --settle --confirm ${priceAtomic} --confirm-pay-to ${advPayTo}`,
        message: `Ready to buy ${priceAtomic / 1e6} USDC of ${items.length} item(s) via x402-direct ` +
          `to ${advPayTo}. Nothing has moved. Confirm the amount AND the recipient with the user, then ` +
          `settle with --confirm ${priceAtomic} --confirm-pay-to ${advPayTo}.`,
      });
    }
    // ---- SETTLE: requires an exact --confirm of BOTH the live price AND the
    // recipient. pay_to is the one term the guardrail cannot pin (it is per-merchant
    // and server-advertised), so binding it here makes the recipient the human saw
    // at DRY the recipient settled to, closing an honest-at-DRY / swap-at-SETTLE gap. ----
    const confirm = flags.confirm;
    if (typeof confirm !== "string" || Number(confirm) !== priceAtomic) {
      die(
        `settle refused: --confirm must equal the freshly-advertised price ${priceAtomic} (atomic). ` +
          `Run the DRY buy again, show the user ${priceAtomic / 1e6} USDC, then settle with --confirm ${priceAtomic}.`,
        { expected_confirm_atomic: priceAtomic },
      );
    }
    const confirmPayTo = typeof flags["confirm-pay-to"] === "string" ? String(flags["confirm-pay-to"]).toLowerCase() : "";
    if (confirmPayTo !== advPayTo) {
      die(
        `settle refused: --confirm-pay-to must equal the freshly-advertised recipient ${advPayTo}. ` +
          `The x402-direct recipient is not escrow-pinned, so confirm it: run the DRY buy again, show the ` +
          `user ${advPayTo}, then settle with --confirm-pay-to ${advPayTo}.`,
        { expected_confirm_pay_to: advPayTo },
      );
    }
    const paymentInstruments = { instruments: [x402Instrument] };
    const completeUrl = usedPlatform
      ? `${terminalBase(PLATFORM_TERMINAL_URL)}/ucp/v1/originated-checkouts/complete`
      : `${base}/ucp/v1/checkout-sessions/${session.id}/complete`;
    const completeBody = usedPlatform
      ? {
        target: base,
        checkout_id: session.id,
        payment: paymentInstruments,
        ...(hasOrderAttributes ? { order_attributes: orderAttributes } : {}),
      }
      : {
        payment: paymentInstruments,
        ...(hasOrderAttributes ? { order_attributes: orderAttributes } : {}),
      };
    note(`POST ${completeUrl}  (REAL x402-direct settlement${usedPlatform ? ", platform-originated" : ""})`);
    const cRes = await fetch(completeUrl, {
      method: "POST",
      headers: kyaHeaders(buyKya),
      body: JSON.stringify(completeBody),
    });
    const cText = await cRes.text();
    if (cRes.status < 200 || cRes.status >= 300) {
      if ((cRes.status === 401 || cRes.status === 403) && /signature/i.test(errorReason(cText))) {
        die(`this store rejected the checkout co-signature at settlement.`, {
          reason: "platform_cosignature_required",
          http_status: cRes.status,
          via_platform: usedPlatform,
        });
      }
      die(`COMPLETE failed HTTP ${cRes.status}`, { body: cText.slice(0, 600) });
    }
    let completion: Record<string, unknown>;
    try {
      const parsed = JSON.parse(cText);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("settlement response was not a JSON object");
      }
      completion = parsed as Record<string, unknown>;
    } catch {
      die("settlement response could not be parsed", {
        settled: "unconfirmed",
        warning: "the settlement POST was accepted (HTTP 2xx) but its response body was not parseable JSON; " +
          "DO NOT retry --settle. Verify the order and on-chain state before any re-attempt.",
        http_status: cRes.status,
        body: cText.slice(0, 500),
      });
    }
    const settledOrderId = (completion.order as { id?: string } | undefined)?.id ??
      (typeof completion.order_id === "string" ? completion.order_id : null);
    let receipt: ReceiptEntry | null = null;
    if (typeof settledOrderId === "string" && settledOrderId !== "") {
      try {
        const r = await fetchReceipt(base, settledOrderId, buyKya);
        receipt = r.entry;
      } catch {
        // best-effort: the money already moved; a receipt fetch failure is not fatal.
      }
    }
    emit({
      ok: true,
      mode: "SETTLED",
      ...summary,
      settled: true,
      order: completion.order ?? null,
      order_id: settledOrderId,
      settlement_id: completion.settlement_id ?? null,
      settled_at: completion.settled_at ?? null,
      receipt,
      message: `Settled ${priceAtomic / 1e6} USDC via x402-direct to ${advPayTo}.`,
    });
  }
  // railArm is "boson" here: the x402 branch above emits and exits, and chooseRail
  // returns "boson" only when the Boson handler is present, so boson is defined.
  if (boson === undefined) {
    die(`internal: Boson rail selected but no Boson handler on this checkout.`);
  }

  const requirements = boson["offer"] as Record<string, unknown> | undefined;
  // Validate the display scalars before they gate the balance check or feed
  // BigInt(priceAtomic) downstream. A fractional price (e.g. "5.5") is finite
  // under Number() and would clear the (0, cap] check, then blow up as an
  // uncaught RangeError at BigInt(priceAtomic). assertDisplayScalarsSane refuses
  // any non-canonical form first. Same never-typed try/catch-die shape the SDK
  // sink and the --items/--ship parses use, so it type-checks.
  let priceAtomic: number;
  let chainId: number;
  try {
    const s = assertDisplayScalarsSane(boson);
    priceAtomic = s.priceAtomic;
    chainId = s.chainId;
  } catch (e) {
    die(`GUARDRAIL: ${e instanceof Error ? e.message : String(e)}`);
  }
  const network = String(boson["network"] ?? "");
  const sellerId = String(boson["seller_id"] ?? "");
  if (requirements === undefined) die("checkout advertised no seller-signed offer to commit against.");

  // ---- hard guardrails on the server-advertised terms ----
  if (network !== EXPECT_NETWORK || chainId !== EXPECT_CHAIN) {
    die(`GUARDRAIL: offer is ${network}/${chainId}, expected ${EXPECT_NETWORK}/${EXPECT_CHAIN}. Refusing.`);
  }
  if (!Number.isFinite(priceAtomic) || priceAtomic <= 0 || priceAtomic > capAtomic) {
    die(`GUARDRAIL: price ${priceAtomic / 1e6} USDC outside (0, ${capUsdc}] cap. Raise --max-usdc only if intended.`);
  }
  if (balance < BigInt(priceAtomic)) {
    die(
      `insufficient funds: wallet holds ${Number(balance) / 1e6} USDC, checkout needs ${priceAtomic / 1e6}. ` +
        `Fund ${account.address} on ${EXPECT_NETWORK} first.`,
      { need_atomic: priceAtomic, have_atomic: balance.toString() },
    );
  }

  // ---- authoritative check on the SELLER-SIGNED offer object ----
  // The guardrails above read the checkout's sibling DISPLAY scalars. The
  // artifact the SDK actually signs and settles is this `requirements` offer
  // object, whose own amount / asset / network are what ERC-3009 binds. Verify
  // those directly against the same terms we displayed, capped, and will
  // confirm, or a hostile Terminal could show one price and sign another (or a
  // different token, or a different chain). This is the choke point before any
  // signature is produced.
  try {
    assertOfferMatches(requirements, { priceAtomic, capAtomic, usdc: USDC, chainId: EXPECT_CHAIN, escrow: BOSON_ESCROW });
  } catch (e) {
    die(`GUARDRAIL: ${e instanceof Error ? e.message : String(e)}`);
  }

  // ---- what the escrow pin does NOT bind, and why that is acceptable ----
  // The pin above binds WHERE the money goes (the Boson escrow Diamond), how
  // MUCH, in WHICH token, on WHICH chain. It does not bind WHICH seller account
  // inside that shared network Diamond the commit routes to: Boson identifies
  // the seller by the opaque `fullOffer` + `sellerSig` the SDK forwards verbatim
  // (no SDK schema over `fullOffer`), and the sibling `seller_id` scalar is
  // display-only. A hostile Terminal controls both the offer blob and that
  // scalar, so a `seller_id` equality check would pass while the offer named the
  // attacker; it would be theater, not a control. The residual is instead
  // bounded and surfaced. Bounded: funds settle into Boson escrow, never to a
  // seller EOA, and a wrong or non-performing seller is recoverable through the
  // Boson cancel / dispute / refund window (proven on mainnet), all under the
  // per-checkout USDC cap. Surfaced: the DRY summary prints seller_id,
  // escrow_address, and asset so a human sees the routing before confirming.

  // ---- sign the buyer's ERC-3009 commit authorization LOCALLY ----
  const signer: Signer = {
    getAddress: () => Promise.resolve(account.address),
    signTypedData: (a) => account.signTypedData(a as Parameters<typeof account.signTypedData>[0]),
  };
  const client = createX402bClient({
    signer,
    subgraphUrls: { [chainId]: "https://boson-subgraph.invalid/placeholder" },
    tokenDomainResolver: (asset: string, cid: number) => ({
      name: TOKEN_DOMAIN_NAME,
      version: "2",
      chainId: cid,
      verifyingContract: asset as `0x${string}`,
    }),
    // maxAmount is the SDK-level backstop on the exact field it signs: even if
    // the check above were bypassed, the SDK refuses to sign an offer whose
    // amount exceeds the cap. Defense in depth on the same atomic value.
    policy: { tokenAuthStrategy: "erc3009", redeemMode: "commit-only", maxAmount: String(capAtomic) },
  });
  const xPayment = await client.handle402(requirements);
  note(`buyer commit signed locally (ERC-3009, own wallet, domain "${TOKEN_DOMAIN_NAME}" v2)`);

  const summary = {
    checkout_id: session.id,
    seller_id: sellerId,
    chain_id: chainId,
    network,
    price_atomic: priceAtomic,
    price_usdc: priceAtomic / 1e6,
    // The recipient and token the buyer's signature actually authorizes, read
    // from the seller-signed offer the SDK settles and already validated above.
    // Surfaced so a human sees WHERE the money goes, and in WHICH token, before
    // confirming a settlement, not just the display price.
    escrow_address: String(requirements["escrowAddress"] ?? ""),
    asset: String(requirements["asset"] ?? ""),
    buyer: account.address,
    balance_usdc: Number(balance) / 1e6,
    rail: BOSON_HANDLER,
    items,
    ...(hasOrderAttributes ? { order_attributes: orderAttributes } : {}),
    // The throwaway shipping-email preference state, for the agent: "unset" means
    // never asked, so ask the buyer once before settling, then store the answer
    // with `email-pref set ...` and it is reused on every future order.
    shipping_email_pref: shippingEmailSignal,
  };

  // ---- DRY (default): stop before COMPLETE. Nothing moved. ----
  if (!settle) {
    emit({
      ok: true,
      mode: "DRY",
      ...summary,
      signed: true,
      settled: false,
      confirm_atomic: priceAtomic,
      next: `to settle: buy ... --settle --confirm ${priceAtomic}`,
      message: `Ready to buy ${priceAtomic / 1e6} USDC of ${items.length} item(s). Nothing has moved. ` +
        `Confirm with the user, then settle with --confirm ${priceAtomic}.`,
    });
  }

  // ---- SETTLE: requires an exact --confirm matching the live price ----
  const confirm = flags.confirm;
  // Bind the confirmation to BOTH the advertised price and the seller-signed
  // offer amount. assertOfferMatches already proved priceAtomic equals the
  // offer's own amount earlier in this same process, so this settle gate is
  // bound to the artifact that actually moves money, not just a display scalar.
  const signedAmount = Number(requirements["amount"]);
  if (typeof confirm !== "string" || Number(confirm) !== priceAtomic || Number(confirm) !== signedAmount) {
    die(
      `settle refused: --confirm must equal the freshly-advertised price ${priceAtomic} (atomic), ` +
        `which is bound to the seller-signed offer amount. ` +
        `Run the DRY buy again, show the user ${priceAtomic / 1e6} USDC, then settle with --confirm ${priceAtomic}.`,
      { expected_confirm_atomic: priceAtomic },
    );
  }

  // The Terminal binds identity at settlement to the instrument itself, not just
  // the Authorization header: instruments[0].kya must echo the buyer KYA or the
  // complete step 403s. buyKya is the same self-issued, wallet-bound token.
  const paymentInstruments = {
    instruments: [{ kya: buyKya, credential: { type: "boson_commit_authorization", x_payment: xPayment, requirements } }],
  };
  // Settle on the same path CREATE used. Through the platform origination surface
  // the request carries the target + checkout id and the platform re-signs the
  // outbound COMPLETE; buyer-direct posts straight to the merchant. The payment
  // instrument (the buyer's client-side ERC-3009 authorization) is identical.
  const completeUrl = usedPlatform
    ? `${terminalBase(PLATFORM_TERMINAL_URL)}/ucp/v1/originated-checkouts/complete`
    : `${base}/ucp/v1/checkout-sessions/${session.id}/complete`;
  const completeBody = usedPlatform
    ? {
      target: base,
      checkout_id: session.id,
      payment: paymentInstruments,
      ...(hasOrderAttributes ? { order_attributes: orderAttributes } : {}),
    }
    : {
      payment: paymentInstruments,
      ...(hasOrderAttributes ? { order_attributes: orderAttributes } : {}),
    };
  note(`POST ${completeUrl}  (REAL settlement${usedPlatform ? ", platform-originated" : ""})`);
  const cRes = await fetch(completeUrl, { method: "POST", headers: kyaHeaders(buyKya), body: JSON.stringify(completeBody) });
  const cText = await cRes.text();
  if (cRes.status < 200 || cRes.status >= 300) {
    if ((cRes.status === 401 || cRes.status === 403) && /signature/i.test(errorReason(cText))) {
      die(
        `this store rejected the checkout co-signature at settlement.`,
        { reason: "platform_cosignature_required", http_status: cRes.status, via_platform: usedPlatform },
      );
    }
    die(`COMPLETE failed HTTP ${cRes.status}`, { body: cText.slice(0, 600) });
  }
  // This parse runs AFTER the buyer's ERC-3009 authorization was delivered and
  // the Terminal returned 2xx, so money may already have moved. A shared
  // die()-on-bad-JSON here would read like "nothing happened" and invite a naive
  // --settle retry, risking a double authorization. Instead report an explicit
  // unconfirmed terminal state that tells the caller NOT to retry and to verify
  // on-chain first. This is deliberately its own handler, not parseJsonObjOrDie.
  let completion: Record<string, unknown>;
  try {
    const parsed = JSON.parse(cText);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("settlement response was not a JSON object");
    }
    completion = parsed as Record<string, unknown>;
  } catch {
    die(
      "settlement response could not be parsed",
      {
        settled: "unconfirmed",
        warning:
          "the settlement POST was accepted (HTTP 2xx) but its response body was not parseable JSON; " +
          "DO NOT retry --settle. Verify the order and on-chain state before any re-attempt.",
        http_status: cRes.status,
        body: cText.slice(0, 500),
      },
    );
  }
  // The receipt: the settled order now has a signed, portable proof on the Facet
  // ledger (the ledger append is awaited before COMPLETE returns, so it is durable
  // by now). Fetch it, verify it OFFLINE against the merchant Terminal's JWKS, and
  // archive it, so the buy result already carries evidence the buyer can hand to
  // anyone. Strictly best-effort: the money already moved, so nothing here changes
  // the settled outcome. A deferred-settlement rail may not anchor until a later
  // leg; then this reports { available:false } and `receipt --order-id` fetches it
  // later.
  const settledOrderId = (completion.order as { id?: string } | undefined)?.id ??
    (typeof completion.order_id === "string" ? completion.order_id : null);
  let receipt: Record<string, unknown> | null = null;
  if (typeof settledOrderId === "string" && settledOrderId !== "") {
    let { entry, note: rnote, status } = await fetchReceipt(base, settledOrderId, buyKya);
    // On an originated (platform-signed) checkout the settled order is owned by the
    // origin aid (`ucp-origin:<origin>`), not the buyer's ephemeral purchase KYA, so
    // the aid-scoped fetch 403s even though the buyer just paid. Re-authorize by
    // proving control of the order's durable payer wallet, the same wallet that
    // signed this payment, exactly as the `receipt` subcommand does. The key never
    // leaves this process; only the signature, the nonce, and the issued-at leave it.
    if (entry === null && status === 403) {
      const walletAuth = await walletReceiptAuth(wallet.key, settledOrderId);
      ({ entry, note: rnote, status } = await fetchReceipt(base, settledOrderId, buyKya, walletAuth));
    }
    if (entry !== null) {
      const v = await verifyReceipt(entry, base);
      const saved = saveReceipt(base, settledOrderId, entry, v.verified === true);
      receipt = {
        jws: entry.jws,
        kid: entry.kid,
        provider_jwks: entry.provider_jwks,
        ...v,
        saved: saved.saved,
        ...(saved.path !== undefined ? { saved_path: saved.path } : {}),
      };
    } else {
      receipt = { available: false, note: rnote };
    }
  }
  emit({
    ok: true,
    mode: "SETTLE",
    ...summary,
    settled: true,
    status: completion.status ?? null,
    order_id: settledOrderId,
    settlement_id: completion.settlement_id ?? null,
    receipt,
    settlement: completion,
  });
}

// ---- post-purchase lifecycle: redeem / cancel / withdraw / dispute / refund -
//   The buyer-initiated settlement actions after a purchase. redeem, cancel, and
//   dispute are Boson escrow actions: the buyer signs the Boson meta-transaction
//   (redeemVoucher / cancelVoucher / raiseDispute) LOCALLY and gasless with their
//   OWN wallet, and the Terminal relays it. The wallet key never leaves this
//   process, and only the wallet that owns the on-chain voucher can produce a
//   signature Boson accepts, so an agent cannot act on an exchange it does not
//   hold the key for. `withdraw` is the same shape for the post-cancel cash-out:
//   the buyer signs a Boson withdrawFunds MetaTxFund locally and a gas-only relayer
//   moves the returned escrow to the buyer's own wallet (self-binding on-chain).
//   `refund` is the x402-rail path and needs no signature: the order id plus the
//   buyer's KYA. The `--exchange-id` is the `settlement_id` the buy receipt
//   returned; `--order-id` is the buy receipt's order id.

// Sign a Boson lifecycle meta-tx locally with the wallet and return the opaque
// signed payload. The client + signer mirror buy's; the cast pins the one method
// used so the skill does not depend on the client's exported action types.
// Build a Boson x402b signing client for the buyer's wallet. The wallet key signs
// locally and never leaves this process; the client only produces signed meta-tx
// payloads (signing is pure, no network). Shared by the single-factor boson actions
// and the mutual resolveDispute, which carries two extra signed fields.
function bosonSignClient(walletKey: string): {
  signAction(a: Record<string, unknown>): Promise<{ signedPayload: string }>;
} {
  if (BOSON_ESCROW === "") {
    die(`no Boson escrow Diamond configured for chain ${EXPECT_CHAIN}; set FACET_BOSON_ESCROW.`);
  }
  const account = privateKeyToAccount(walletKey as `0x${string}`);
  const signer: Signer = {
    getAddress: () => Promise.resolve(account.address),
    signTypedData: (a) => account.signTypedData(a as Parameters<typeof account.signTypedData>[0]),
  };
  return createX402bClient({
    signer,
    subgraphUrls: { [EXPECT_CHAIN]: "https://boson-subgraph.invalid/placeholder" },
    tokenDomainResolver: (asset: string, cid: number) => ({
      name: TOKEN_DOMAIN_NAME,
      version: "2",
      chainId: cid,
      verifyingContract: asset as `0x${string}`,
    }),
    policy: { tokenAuthStrategy: "erc3009", redeemMode: "commit-only" },
  }) as unknown as {
    signAction(a: Record<string, unknown>): Promise<{ signedPayload: string }>;
  };
}

// Sign a single-factor Boson action (redeem, cancel, raise/retract/escalate) as a
// gasless buyer meta-tx.
async function signBosonAction(
  walletKey: string,
  actionId: string,
  exchangeId: string,
): Promise<string> {
  const { signedPayload } = await bosonSignClient(walletKey).signAction({
    actionId,
    exchangeId,
    network: `eip155:${EXPECT_CHAIN}`,
    escrowAddress: BOSON_ESCROW,
  });
  return signedPayload;
}

// Sign the BUYER half of a mutual Boson resolveDispute at the merchant-offered split.
// Unlike raise/retract/escalate (one buyer meta-tx), resolve binds the SELLER's
// counter-signature (the Resolution EIP-712 sig the merchant offered at approve) and
// the buyer percent in basis points into the buyer's signed MetaTxDisputeResolution.
// The Terminal re-derives both from the stored offer and re-validates the payload
// before relaying, so a wrong split is refused server-side, never on-chain.
async function signBosonResolve(
  walletKey: string,
  exchangeId: string,
  buyerPercentBps: number,
  counterpartySig: string,
): Promise<string> {
  const { signedPayload } = await bosonSignClient(walletKey).signAction({
    actionId: "boson-resolveDispute",
    exchangeId,
    network: `eip155:${EXPECT_CHAIN}`,
    escrowAddress: BOSON_ESCROW,
    buyerPercent: buyerPercentBps,
    counterpartySig,
  });
  return signedPayload;
}

// Resolve a trusted, wallet-bound KYA for a wallet, self-serve minting one if the
// env or cached token is stale, untrusted, or absent. Mirrors buy's identity
// self-heal so every lifecycle action authenticates as the same wallet-bound agent.
async function walletBoundKya(wallet: ResolvedWallet): Promise<string> {
  let kya = kyaUsable(wallet.kya, wallet.address) ? wallet.kya : "";
  if (kya === "") {
    const cached = readCachedKya(wallet.label);
    if (kyaUsable(cached, wallet.address)) kya = cached as string;
  }
  if (kya === "") {
    note(
      `no trusted wallet-bound KYA for [${wallet.label}] ${wallet.address}; minting one from the ` +
        `Facet issuer (self-serve, wallet-bound, no key leaves this process)`,
    );
    try {
      kya = (await provisionKya(wallet.key, { cacheKey: wallet.label })).token;
    } catch (e) {
      die(`could not provision a wallet-bound KYA: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return kya;
}

// The result of a lifecycle POST, WITHOUT emitting: either the parsed JSON on
// success, or the failure pieces (co-signature detection, status, truncated body).
// tryPostLifecycle NEVER dies, so a caller that must preserve context across two
// legs (cancel then withdraw) can assemble one combined result; submitLifecycle
// wraps it for the single-action commands and dies on failure exactly as before.
type LifecyclePost =
  | { ok: true; json: Record<string, unknown> }
  | { ok: false; http_status: number; reason: string; body: string; cosig: boolean };

async function tryPostLifecycle(
  base: string,
  path: string,
  body: Record<string, unknown>,
  kya: string,
): Promise<LifecyclePost> {
  note(`POST ${base}${path}`);
  const r = await fetch(`${base}${path}`, {
    method: "POST",
    headers: kyaHeaders(kya),
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (r.status < 200 || r.status >= 300) {
    const cosig = (r.status === 401 || r.status === 403) && /signature/i.test(errorReason(text));
    return {
      ok: false,
      http_status: r.status,
      reason: cosig ? "platform_cosignature_required" : `HTTP ${r.status}`,
      body: text.slice(0, 500),
      cosig,
    };
  }
  return { ok: true, json: parseJsonObjOrDie(text, path) };
}

// Turn a failed lifecycle POST into the same structured die the single-action
// commands have always produced (co-signature message, else the HTTP failure).
function dieLifecycle(path: string, r: Extract<LifecyclePost, { ok: false }>): never {
  if (r.cosig) {
    die(
      `this store requires a platform co-signature for this action; a buyer-only client cannot supply it.`,
      { reason: "platform_cosignature_required", http_status: r.http_status },
    );
  }
  die(`${path} failed HTTP ${r.http_status}`, { body: r.body });
}

// POST a lifecycle action to the Terminal on the buyer's KYA and emit the result.
async function submitLifecycle(
  base: string,
  path: string,
  body: Record<string, unknown>,
  kya: string,
): Promise<never> {
  const r = await tryPostLifecycle(base, path, body, kya);
  if (!r.ok) dieLifecycle(path, r);
  emit({ ok: true, ...r.json });
}

// Same as submitLifecycle, but after the action confirms it also fetches, verifies,
// and archives the action's signed reversal receipt (facet-lifecycle+jws) and folds
// it into the result under `receipt`. Best-effort: the reversal already committed
// on-chain, so a receipt problem never fails the command, and the fetch runs on the
// SAME KYA that performed the reversal (the reliable owner-scoped path). Used by
// cancel / withdraw / dispute so a reversal leaves the same portable, verifiable
// proof a purchase does.
async function submitLifecycleWithReceipt(
  base: string,
  path: string,
  body: Record<string, unknown>,
  kya: string,
  lookup: LifecycleLookup,
): Promise<never> {
  const r = await tryPostLifecycle(base, path, body, kya);
  if (!r.ok) dieLifecycle(path, r);
  const receipt = await fetchVerifySaveLifecycle(base, lookup, kya);
  emit({ ok: true, ...r.json, receipt });
}

// ---- redeem: confirm receipt, release the escrow to the seller -------------
async function cmdRedeem(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const exchangeId = requireFlag(flags, "exchange-id");
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const kya = await walletBoundKya(wallet);
  note(`signing boson-redeem for exchange ${exchangeId} locally (gasless; no key leaves this process)`);
  const signedPayload = await signBosonAction(wallet.key, "boson-redeem", exchangeId);
  return submitLifecycle(
    base,
    "/ucp/v1/checkout-sessions/redeem",
    { exchange_id: exchangeId, signed_payload: signedPayload },
    kya,
  );
}

// ---- cancel: pre-redeem cancel, the full escrow returns to the buyer -------
//   With --withdraw, chain straight into the gasless cash-out: cancel returns the
//   escrow to the buyer's Boson available-funds, then withdraw moves it to the
//   buyer's own wallet, in one command (the operator's requested UX). Cancel
//   behavior is byte-identical to before when --withdraw is absent.
async function cmdCancel(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const exchangeId = requireFlag(flags, "exchange-id");
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const kya = await walletBoundKya(wallet);
  note(`signing boson-cancelVoucher for exchange ${exchangeId} locally (gasless; no key leaves this process)`);
  const signedPayload = await signBosonAction(wallet.key, "boson-cancelVoucher", exchangeId);
  const cancelBody = { exchange_id: exchangeId, signed_payload: signedPayload };

  if (flags.withdraw !== true) {
    return submitLifecycleWithReceipt(base, "/ucp/v1/checkout-sessions/cancel", cancelBody, kya, {
      kind: "cancel",
      exchangeId,
    });
  }

  // --withdraw: post the cancel first and only proceed once it is confirmed; the
  // escrow is then credited to the buyer's protocol available-funds and the
  // withdraw can move it to the wallet. Keep the cancel receipt so a withdraw-leg
  // problem never reads as "nothing happened".
  const cancel = await tryPostLifecycle(base, "/ucp/v1/checkout-sessions/cancel", cancelBody, kya);
  if (!cancel.ok) dieLifecycle("/ucp/v1/checkout-sessions/cancel", cancel);
  note(`cancel confirmed; preparing the gasless withdraw of the returned escrow`);
  // Archive the cancel's signed reversal receipt now, on the same KYA that cancelled,
  // so a withdraw-leg problem never leaves the refund without portable proof.
  const cancelReceipt = await fetchVerifySaveLifecycle(base, { kind: "cancel", exchangeId }, kya);

  const amountOverride = typeof flags.amount === "string" ? flags.amount : undefined;
  const walletArg = typeof flags.wallet === "string" && flags.wallet !== ""
    ? ` --wallet ${flags.wallet}`
    : "";
  const built = await buildWithdrawPlan(wallet, exchangeId, amountOverride);
  if (built.kind === "no_funds") {
    emit({
      ok: true,
      mode: "CANCEL_THEN_WITHDRAW",
      cancel: cancel.json,
      withdraw: null,
      withdraw_pending: true,
      cancel_receipt: cancelReceipt,
      entity_id: built.entityId.toString(),
      next: `withdraw --terminal ${base}${walletArg} --exchange-id ${exchangeId}`,
      message:
        `Cancelled. The escrow was returned to your protocol available-funds, but the ` +
        `on-chain credit is not yet visible to read, so the withdraw was not signed. Run ` +
        `the withdraw shortly to cash out.`,
    });
  }
  const plan = built.plan;
  const withdraw = await tryPostLifecycle(
    base,
    "/ucp/v1/checkout-sessions/withdraw",
    plan.body,
    kya,
  );
  // The withdraw leg's own signed receipt (the gasless cash-out), archived when it lands.
  const withdrawReceipt = withdraw.ok
    ? await fetchVerifySaveLifecycle(base, { kind: "withdraw", exchangeId }, kya)
    : null;
  emit({
    ok: withdraw.ok,
    mode: "CANCEL_THEN_WITHDRAW",
    cancel: cancel.json,
    withdraw: withdraw.ok ? withdraw.json : null,
    cancel_receipt: cancelReceipt,
    ...(withdrawReceipt !== null ? { withdraw_receipt: withdrawReceipt } : {}),
    ...withdrawSummary(plan),
    ...(withdraw.ok ? {} : {
      withdraw_error: withdraw.reason,
      withdraw_http_status: withdraw.http_status,
      next: `withdraw --terminal ${base}${walletArg} --exchange-id ${exchangeId}`,
    }),
    message: withdraw.ok
      ? `Cancelled and cashed out ${Number(plan.amount) / 1e6} USDC to ${plan.from}.`
      : `Cancelled successfully, but the withdraw could not be relayed (${withdraw.reason}). ` +
        `The escrow is safe in your protocol available-funds; retry the withdraw.`,
  });
}

// ---- dispute: raise / retract / escalate a dispute -------------------------
const DISPUTE_ACTION_ID: Record<string, string> = {
  raise: "boson-raiseDispute",
  retract: "boson-retractDispute",
  escalate: "boson-escalateDispute",
};
async function cmdDispute(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const exchangeId = requireFlag(flags, "exchange-id");
  const action = typeof flags.action === "string" ? flags.action : "raise";
  const actionId = DISPUTE_ACTION_ID[action];
  if (actionId === undefined) {
    die(
      `--action must be one of raise, retract, escalate. (To complete a partial-refund ` +
        `split, use the \`resolve\` subcommand: it carries the seller's counter-signature.)`,
    );
  }
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const kya = await walletBoundKya(wallet);
  note(`signing ${actionId} for exchange ${exchangeId} locally (gasless; no key leaves this process)`);
  const signedPayload = await signBosonAction(wallet.key, actionId, exchangeId);
  return submitLifecycleWithReceipt(
    base,
    "/ucp/v1/checkout-sessions/dispute",
    { exchange_id: exchangeId, signed_payload: signedPayload, action },
    kya,
    { kind: "dispute", exchangeId },
  );
}

// ---- refund: open a refund ticket for a settled order ----------------------
//   REQUEST only: it opens the ticket and moves NO money. A --reason is required
//   (the merchant reviews it). The taxed amount is derived and capped server-side,
//   and the send-back dispatches only when the merchant approves. Passing --items
//   makes it a PARTIAL refund of just those lines (shipping is not a line item, so
//   it is retained); omitting --items requests the whole order. The rail is chosen
//   at the merchant's approve from live on-chain state: an x402 order sends USDC
//   back from the merchant wallet; a Boson escrow order settles the partial as a
//   mutual resolveDispute split the buyer then completes with `resolve`.
export type RefundBody = {
  order_id: string;
  reason: string;
  refund_line_items?: { product_id: string; qty: number }[];
};

// Pure: assemble the refund_request body. A null selection is a whole-order request
// (no refund_line_items key); a selection maps each cart {id, qty} to the server's
// {product_id, qty}. Exported for an offline unit test with no secrets or network.
export function buildRefundBody(
  orderId: string,
  reason: string,
  items: CartItem[] | null,
): RefundBody {
  const body: RefundBody = { order_id: orderId, reason };
  if (items !== null) {
    body.refund_line_items = items.map((c) => ({ product_id: c.id, qty: c.qty }));
  }
  return body;
}

// The EIP-191 message a buyer signs to authorize a refund request by proof of control
// of the paying wallet, byte-for-byte the Terminal's refund-request challenge. On a
// dual-auth store the Terminal recovers this to the wallet-bound KYA's payer_wallet to
// open the ticket WITHOUT a platform co-signature (the autonomous dual-key path); a
// single-factor store ignores it. Exported so an offline test pins the exact wire
// format the Terminal verifies.
export function refundAuthMessage(
  orderId: string,
  wallet: string,
  issuedAt: number,
  nonce: string,
): string {
  return `Facet refund request\norder: ${orderId}\nwallet: ${wallet}\nissued_at: ${issuedAt}\nnonce: ${nonce}`;
}

// Sign the refund authorization with the buyer's wallet (locally; the key never leaves
// the process, only the signature does). A fresh single-use nonce and issued_at bound
// the attestation: the Terminal caps freshness at a few minutes and consumes the nonce
// exactly once, so a captured signature cannot be replayed.
async function signRefundAuth(
  walletKey: string,
  orderId: string,
): Promise<{ wallet: string; issued_at: number; nonce: string; signature: string }> {
  const account = privateKeyToAccount(walletKey as `0x${string}`);
  const issued_at = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const signature = await account.signMessage({
    message: refundAuthMessage(orderId, account.address, issued_at, nonce),
  });
  return { wallet: account.address, issued_at, nonce, signature };
}

async function cmdRefund(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const orderId = requireFlag(flags, "order-id");
  const reason = requireFlag(flags, "reason");
  let items: CartItem[] | null = null;
  if (typeof flags.items === "string") {
    try {
      items = JSON.parse(flags.items) as CartItem[];
    } catch {
      die("--items must be valid JSON: an array of {id, qty} for a partial refund.");
    }
    if (!Array.isArray(items) || items.length === 0) {
      die("--items must be a non-empty JSON array of {id, qty}.");
    }
    for (const c of items) {
      if (typeof c?.id !== "string" || c.id === "") {
        die("each --items entry needs a non-empty string id.");
      }
      if (!Number.isInteger(c?.qty) || c.qty <= 0) {
        die(`--items qty for "${c?.id}" must be a positive integer.`);
      }
    }
  }
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const kya = await walletBoundKya(wallet);
  // Attach the buyer wallet attestation so a dual-auth store can authorize the refund
  // request without a platform co-signature (the autonomous dual-key path). A single-
  // factor store ignores it; nothing here moves money (the ticket opens only).
  const buyer_auth = await signRefundAuth(wallet.key, orderId);
  return submitLifecycle(
    base,
    "/ucp/v1/checkout-sessions/refund",
    { ...buildRefundBody(orderId, reason, items), buyer_auth },
    kya,
  );
}

// ---- resolve: complete a Boson partial-refund split (mutual resolveDispute) --
//   After the merchant APPROVES a partial refund on a disputed Boson order, it
//   offers a seller-signed split: the seller's Resolution counter-signature plus
//   the buyer percent (basis points). This signs the buyer half locally and submits
//   it to the dispute route with action=resolve; the Terminal validates the split
//   against the stored offer, relays it gaslessly, and the escrow settles. Two ways
//   to supply the offer:
//     auto     `resolve --refund-id <id>` reads it from the buyer's own refund
//              ticket (get_refund), populated once the merchant approves.
//     explicit `resolve --exchange-id <id> --buyer-percent-bps <n> --seller-sig <hex>`.
export type ResolveBody = {
  exchange_id: string;
  action: "resolve";
  signed_payload: string;
};

// Pure: the dispute-route body for a resolve. The buyer percent and seller sig are
// NOT in the body (the Terminal re-derives them from the stored offer); only the
// buyer's signed resolveDispute meta-tx travels. Exported for an offline unit test.
export function buildResolveBody(exchangeId: string, signedPayload: string): ResolveBody {
  return { exchange_id: exchangeId, action: "resolve", signed_payload: signedPayload };
}

// Read the merchant-approved split off the buyer's own refund ticket (owner-scoped
// get_refund). Dies with an actionable message if the merchant has not approved yet
// (no offer on the ticket) or the ticket is not the caller's, pointing at the
// explicit-flag path so a valid offer obtained out of band is never a dead end.
async function fetchResolutionOffer(
  base: string,
  refundId: string,
  kya: string,
): Promise<{ exchangeId: string; buyerPercentBps: number; sellerSig: string }> {
  note(`POST ${base}/v1/get_refund (${refundId})`);
  const r = await fetch(`${base}/v1/get_refund`, {
    method: "POST",
    headers: kyaHeaders(kya),
    body: JSON.stringify({ refund_id: refundId }),
  });
  const text = await r.text();
  if (r.status < 200 || r.status >= 300) {
    die(
      `get_refund failed HTTP ${r.status}. If you already have the offer, pass it explicitly with ` +
        `--exchange-id --buyer-percent-bps --seller-sig.`,
      { body: text.slice(0, 500) },
    );
  }
  const refund = parseJsonObjOrDie(text, "/v1/get_refund");
  const sellerSig = refund["seller_resolution_signature"];
  const bps = refund["buyer_percent_bps"];
  const exchangeId = refund["boson_exchange_id"];
  if (
    typeof sellerSig !== "string" || sellerSig === "" ||
    typeof bps !== "number" || !Number.isInteger(bps) ||
    typeof exchangeId !== "string" || exchangeId === ""
  ) {
    die(
      `refund ${refundId} has no merchant-approved split offer yet. The merchant must approve the ` +
        `partial refund first (which offers the seller's counter-signature), or pass the offer ` +
        `explicitly with --exchange-id --buyer-percent-bps --seller-sig.`,
      { reason: "no_resolution_offer" },
    );
  }
  return { exchangeId, buyerPercentBps: bps, sellerSig };
}

async function cmdResolve(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const kya = await walletBoundKya(wallet);

  let exchangeId: string;
  let buyerPercentBps: number;
  let sellerSig: string;
  // Explicit offer when either the seller sig or the bps is supplied; then all three
  // are required together. Otherwise auto-fetch from the buyer's own refund ticket.
  if (typeof flags["seller-sig"] === "string" || typeof flags["buyer-percent-bps"] === "string") {
    exchangeId = requireFlag(flags, "exchange-id");
    sellerSig = requireFlag(flags, "seller-sig");
    buyerPercentBps = Number(requireFlag(flags, "buyer-percent-bps"));
    if (!Number.isInteger(buyerPercentBps) || buyerPercentBps < 0 || buyerPercentBps > 10000) {
      die("--buyer-percent-bps must be an integer 0..10000 (basis points).");
    }
  } else {
    const offer = await fetchResolutionOffer(base, requireFlag(flags, "refund-id"), kya);
    exchangeId = offer.exchangeId;
    buyerPercentBps = offer.buyerPercentBps;
    sellerSig = offer.sellerSig;
  }

  note(
    `signing boson-resolveDispute for exchange ${exchangeId} at ${buyerPercentBps}bps locally ` +
      `(gasless; no key leaves this process)`,
  );
  const signedPayload = await signBosonResolve(wallet.key, exchangeId, buyerPercentBps, sellerSig);
  return submitLifecycle(
    base,
    "/ucp/v1/checkout-sessions/dispute",
    buildResolveBody(exchangeId, signedPayload),
    kya,
  );
}

// ---- withdraw: gasless cash-out of Boson available-funds to the buyer wallet -
//   After a cancel (or a seller revoke) the escrowed USDC returns to the buyer's
//   Boson PROTOCOL available-funds, credited to the buyer's own entity. Moving it
//   to the wallet is a separate Boson `withdrawFunds`, which the buyer would
//   normally submit and pay gas for. This signs the buyer's `MetaTxFund` withdraw
//   meta-tx LOCALLY with their own wallet and posts it to the Terminal's gas-only
//   relayer, which pays the gas. withdrawFunds is self-binding on-chain (only the
//   entity's own signer can withdraw, and Boson sends the funds to that entity's
//   own wallet), so the relayer can neither redirect nor skim; a wrong signature,
//   stale nonce, or over-withdraw reverts at Boson simulate before any gas or money
//   moves. The wallet key signs locally and never leaves this process.

// The Boson function whose calldata the Terminal relayer re-encodes, and whose name
// is bound into the MetaTxFund the buyer signs. Must match the SDK + relayer verbatim.
const WITHDRAW_FUNCTION_NAME = "withdrawFunds(uint256,address[],uint256[])";

// The minimal Boson Diamond views the withdraw needs, from the @bosonprotocol/common
// ABIs: the exchange's buyer entity (IBosonExchangeHandler.getExchange), that
// entity's wallet for a self-binding pre-check (IBosonAccountHandler.getBuyer), its
// USDC available-funds (IBosonFundsHandler.getAvailableFunds), and meta-tx nonce
// usage (IBosonMetaTransactionsHandler.isUsedNonce). One Diamond serves every facet.
const BOSON_READ_ABI = [
  {
    type: "function",
    name: "getExchange",
    stateMutability: "view",
    inputs: [{ name: "_exchangeId", type: "uint256" }],
    outputs: [
      { name: "exists", type: "bool" },
      {
        name: "exchange",
        type: "tuple",
        components: [
          { name: "id", type: "uint256" },
          { name: "offerId", type: "uint256" },
          { name: "buyerId", type: "uint256" },
          { name: "finalizedDate", type: "uint256" },
          { name: "state", type: "uint8" },
          { name: "mutualizerAddress", type: "address" },
        ],
      },
      {
        name: "voucher",
        type: "tuple",
        components: [
          { name: "committedDate", type: "uint256" },
          { name: "validUntilDate", type: "uint256" },
          { name: "redeemedDate", type: "uint256" },
          { name: "expired", type: "bool" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "getBuyer",
    stateMutability: "view",
    inputs: [{ name: "_buyerId", type: "uint256" }],
    outputs: [
      { name: "exists", type: "bool" },
      {
        name: "buyer",
        type: "tuple",
        components: [
          { name: "id", type: "uint256" },
          { name: "wallet", type: "address" },
          { name: "active", type: "bool" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "getAvailableFunds",
    stateMutability: "view",
    inputs: [
      { name: "_entityId", type: "uint256" },
      { name: "_tokenList", type: "address[]" },
    ],
    outputs: [
      {
        name: "availableFunds",
        type: "tuple[]",
        components: [
          { name: "tokenAddress", type: "address" },
          { name: "tokenName", type: "string" },
          { name: "availableAmount", type: "uint256" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "isUsedNonce",
    stateMutability: "view",
    inputs: [
      { name: "_associatedAddress", type: "address" },
      { name: "_nonce", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

function withdrawErrMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// A minimal viem Chain for the read client. readContract needs only the chain id
// and an RPC transport; the escrow, token, and relayer are all env-pinned above.
function withdrawChain(): Chain {
  return {
    id: EXPECT_CHAIN,
    name: EXPECT_NETWORK,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [RPC] } },
  };
}

// The EXACT EIP-712 the Boson protocol verifies for a gasless withdrawFunds meta-tx,
// replicated from @bosonprotocol/core-sdk@1.48.0:
//   domain (utils/signature.js prepareDataSignatureParameters):
//     { name:"Boson Protocol", version:"V2", verifyingContract:<Diamond>,
//       salt:<chainId left-padded to bytes32> }. NOTE: there is NO chainId field;
//     the chain is bound through `salt`, so the domain here carries exactly
//     [name, version, verifyingContract, salt] and viem derives that same
//     EIP712Domain from these four keys, matching the SDK's domainType.
//   types + message (meta-tx/handler.js signMetaTxWithdrawFunds): primaryType
//     MetaTxFund wraps MetaTxFundDetails{entityId, tokenList, tokenAmounts}; the
//     message pins contractAddress to the Diamond and functionName to
//     withdrawFunds(...). The Terminal relayer re-encodes the SAME calldata, so a
//     mismatch cannot land. Pure and secret-free so an offline test can pin the recipe.
export function buildWithdrawTypedData(p: {
  diamond: string;
  chainId: number;
  from: string;
  entityId: bigint;
  token: string;
  amount: bigint;
  nonce: bigint;
}) {
  return {
    domain: {
      name: "Boson Protocol",
      version: "V2",
      verifyingContract: p.diamond as `0x${string}`,
      salt: ("0x" + p.chainId.toString(16).padStart(64, "0")) as `0x${string}`,
    },
    types: {
      MetaTxFund: [
        { name: "nonce", type: "uint256" },
        { name: "from", type: "address" },
        { name: "contractAddress", type: "address" },
        { name: "functionName", type: "string" },
        { name: "fundDetails", type: "MetaTxFundDetails" },
      ],
      MetaTxFundDetails: [
        { name: "entityId", type: "uint256" },
        { name: "tokenList", type: "address[]" },
        { name: "tokenAmounts", type: "uint256[]" },
      ],
    },
    primaryType: "MetaTxFund" as const,
    message: {
      nonce: p.nonce.toString(),
      from: p.from as `0x${string}`,
      contractAddress: p.diamond as `0x${string}`,
      functionName: WITHDRAW_FUNCTION_NAME,
      fundDetails: {
        entityId: p.entityId.toString(),
        tokenList: [p.token as `0x${string}`],
        tokenAmounts: [p.amount.toString()],
      },
    },
  };
}

interface WithdrawPlan {
  from: string;
  entityId: bigint;
  token: string;
  amount: bigint;
  available: bigint;
  nonce: bigint;
  signature: string;
  body: Record<string, string>;
}
type WithdrawBuild =
  | { kind: "plan"; plan: WithdrawPlan }
  | { kind: "no_funds"; entityId: bigint; available: bigint };

// Read the Boson state the withdraw needs and sign the MetaTxFund LOCALLY. Returns
// the ready-to-post request body, or `no_funds` when the entity has no USDC
// available (a soft state the caller surfaces). Hard problems (bad exchange id, RPC
// failure, wallet not the funds owner, an over-withdraw override) die cleanly.
async function buildWithdrawPlan(
  wallet: ResolvedWallet,
  exchangeId: string,
  amountOverride?: string,
): Promise<WithdrawBuild> {
  if (BOSON_ESCROW === "") {
    die(`no Boson escrow Diamond configured for chain ${EXPECT_CHAIN}; set FACET_BOSON_ESCROW.`);
  }
  if (!/^\d+$/.test(exchangeId)) {
    die(`--exchange-id must be a numeric Boson exchange id.`);
  }
  const diamond = getAddress(BOSON_ESCROW as `0x${string}`);
  const usdc = getAddress(USDC as `0x${string}`);
  const buyer = getAddress(wallet.address as `0x${string}`);
  const pub = createPublicClient({ chain: withdrawChain(), transport: http(RPC) });
  const exId = BigInt(exchangeId);

  // entity_id: the buyer entity of THIS exchange (getExchange.exchange.buyerId).
  // There is no wallet->buyerId view on the Diamond, and anchoring on the exchange
  // ties the withdraw to the same exchange the Terminal authorizes against the site.
  let entityId: bigint;
  try {
    const ex = await pub.readContract({
      address: diamond,
      abi: BOSON_READ_ABI,
      functionName: "getExchange",
      args: [exId],
    }) as readonly [boolean, { buyerId: bigint }, unknown];
    if (!ex[0]) die(`Boson exchange ${exchangeId} does not exist on chain ${EXPECT_CHAIN}.`);
    entityId = ex[1].buyerId;
  } catch (e) {
    die(`could not read Boson exchange ${exchangeId} on chain ${EXPECT_CHAIN}: ${withdrawErrMsg(e)}`);
  }

  // Self-binding pre-check: the entity's wallet MUST be this wallet, or the
  // MetaTxFund signature will not verify at Boson simulate. Fail early and clearly.
  // A read failure here is non-fatal (simulate is the real gate); a definite
  // mismatch is fatal.
  try {
    const bu = await pub.readContract({
      address: diamond,
      abi: BOSON_READ_ABI,
      functionName: "getBuyer",
      args: [entityId],
    }) as readonly [boolean, { wallet: string }];
    if (bu[0] && getAddress(bu[1].wallet as `0x${string}`) !== buyer) {
      die(
        `wallet ${wallet.address} is not the owner of Boson entity ${entityId} ` +
          `(exchange ${exchangeId} belongs to ${bu[1].wallet}). Only the funds owner can withdraw.`,
      );
    }
  } catch (e) {
    note(
      `could not pre-check the buyer wallet on-chain (${withdrawErrMsg(e)}); ` +
        `relying on Boson simulate to reject a wrong signer`,
    );
  }

  // amount: default to the FULL USDC available for this entity; --amount overrides.
  let available: bigint;
  try {
    const funds = await pub.readContract({
      address: diamond,
      abi: BOSON_READ_ABI,
      functionName: "getAvailableFunds",
      args: [entityId, [usdc]],
    }) as readonly { tokenAddress: string; availableAmount: bigint }[];
    const entry = funds.find((f) => getAddress(f.tokenAddress as `0x${string}`) === usdc);
    available = entry !== undefined ? entry.availableAmount : 0n;
  } catch (e) {
    die(`could not read available funds for Boson entity ${entityId}: ${withdrawErrMsg(e)}`);
  }

  let amount: bigint;
  if (amountOverride !== undefined && amountOverride !== "") {
    if (!/^\d+$/.test(amountOverride)) {
      die(`--amount must be a decimal atomic amount (USDC has 6 decimals).`);
    }
    amount = BigInt(amountOverride);
    if (amount <= 0n) die(`--amount must be positive.`);
    if (amount > available) {
      die(
        `--amount ${amount} exceeds the ${available} atomic ` +
          `(${Number(available) / 1e6} USDC) available for entity ${entityId}.`,
        { available_atomic: available.toString() },
      );
    }
  } else if (available <= 0n) {
    return { kind: "no_funds", entityId, available };
  } else {
    amount = available;
  }

  // nonce: Boson meta-tx nonces are client-chosen and replay-guarded by isUsedNonce
  // (the protocol meta-tx handler has no sequential getNonce). Start from a
  // millisecond timestamp and bump past any collision.
  let nonce = BigInt(Date.now());
  try {
    for (let i = 0; i < 32; i++) {
      const used = await pub.readContract({
        address: diamond,
        abi: BOSON_READ_ABI,
        functionName: "isUsedNonce",
        args: [buyer, nonce],
      }) as boolean;
      if (!used) break;
      nonce += 1n;
    }
  } catch (e) {
    note(
      `could not check nonce usage on-chain (${withdrawErrMsg(e)}); using timestamp nonce ` +
        `${nonce} (Boson still rejects a reused nonce at simulate)`,
    );
  }

  const account = privateKeyToAccount(wallet.key as `0x${string}`);
  const typedData = buildWithdrawTypedData({
    diamond,
    chainId: EXPECT_CHAIN,
    from: account.address,
    entityId,
    token: usdc,
    amount,
    nonce,
  });
  const signature = await account.signTypedData(
    typedData as Parameters<typeof account.signTypedData>[0],
  );

  const body: Record<string, string> = {
    exchange_id: exchangeId,
    from: account.address,
    entity_id: entityId.toString(),
    token: usdc,
    amount_atomic: amount.toString(),
    nonce: nonce.toString(),
    signature,
  };
  return {
    kind: "plan",
    plan: { from: account.address, entityId, token: usdc, amount, available, nonce, signature, body },
  };
}

// The non-secret withdraw fields surfaced on a result (never the signature key).
function withdrawSummary(plan: WithdrawPlan): Record<string, unknown> {
  return {
    buyer: plan.from,
    entity_id: plan.entityId.toString(),
    token: plan.token,
    amount_atomic: plan.amount.toString(),
    amount_usdc: Number(plan.amount) / 1e6,
    available_atomic: plan.available.toString(),
    available_usdc: Number(plan.available) / 1e6,
    nonce: plan.nonce.toString(),
  };
}

async function cmdWithdraw(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const exchangeId = requireFlag(flags, "exchange-id");
  const dryRun = flags["dry-run"] === true;
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const amountOverride = typeof flags.amount === "string" ? flags.amount : undefined;
  note(
    `preparing gasless withdraw for exchange ${exchangeId} (reads Boson state on-chain, ` +
      `signs a MetaTxFund locally; no key leaves this process)`,
  );
  const built = await buildWithdrawPlan(wallet, exchangeId, amountOverride);
  if (built.kind === "no_funds") {
    if (dryRun) {
      emit({
        ok: true,
        mode: "DRY",
        action: "withdraw",
        terminal: base,
        entity_id: built.entityId.toString(),
        available_atomic: "0",
        available_usdc: 0,
        message:
          `Dry run: Boson entity ${built.entityId} has no USDC available to withdraw right now. ` +
          `Nothing to sign.`,
      });
    }
    die(
      `no USDC available to withdraw for entity ${built.entityId} on chain ${EXPECT_CHAIN}. ` +
        `If you just cancelled, the on-chain credit may still be settling; retry shortly.`,
      { entity_id: built.entityId.toString(), available_atomic: "0" },
    );
  }
  const plan = built.plan;
  if (dryRun) {
    emit({
      ok: true,
      mode: "DRY",
      action: "withdraw",
      terminal: base,
      ...withdrawSummary(plan),
      request_body: plan.body,
      signed: true,
      settled: false,
      message:
        `Dry run: signed a MetaTxFund to withdraw ${Number(plan.amount) / 1e6} USDC ` +
        `(of ${Number(plan.available) / 1e6} available) from entity ${plan.entityId} to ` +
        `${plan.from}. Nothing was posted. Inspect request_body, then run withdraw again ` +
        `without --dry-run to cash out.`,
    });
  }
  const kya = await walletBoundKya(wallet);
  note(`posting gasless withdraw (the relayer pays gas; withdrawFunds is self-binding to your wallet)`);
  return submitLifecycleWithReceipt(base, "/ucp/v1/checkout-sessions/withdraw", plan.body, kya, {
    kind: "withdraw",
    exchangeId,
  });
}

// ---- reorder: buy a past order again ---------------------------------------
//   Pure orchestration of calls that already exist: read the buyer's own
//   order_history (owner-scoped by the KYA aid at the Terminal), then for each
//   past line item read the CURRENT price and availability from get_product,
//   and hand the available items to the SAME dry-run to confirm to --settle
//   flow that `buy` uses. Reorder itself NEVER settles and adds no new money
//   path: it surfaces candidates and a buy plan, and the actual purchase runs
//   through cmdBuy unchanged (DRY, explicit confirmation, then --settle). A SKU
//   that is gone or out of stock is reported unavailable and skipped, never
//   fatal to the whole reorder.

// One past line item, as read from order_history. unit_price is the price PAID
// then; it is surfaced only for a price-changed comparison, never used to buy.
export interface ReorderLineItem {
  product_id: string;
  qty: number;
  unit_price?: number;
}

// The CURRENT state of a product, resolved from get_product at reorder time.
// `found` is false when the SKU no longer exists (get_product 404 / any error),
// which the resolver turns into an unavailable, skipped candidate.
export interface CurrentProduct {
  found: boolean;
  name?: string;
  price?: number;
  currency?: string;
  in_stock?: boolean;
}

export type CurrentProductResolver = (productId: string) => Promise<CurrentProduct>;

// A reorder candidate: one past line item joined to its current price and
// availability. `available` gates whether it enters the buy plan; when false,
// `reason` says why (gone or out of stock) and it is skipped, not errored.
export interface ReorderCandidate {
  product_id: string;
  qty: number;
  available: boolean;
  name?: string;
  current_price?: number;
  currency?: string;
  in_stock?: boolean;
  original_unit_price: number | null;
  price_changed?: boolean;
  reason?: "not_found" | "out_of_stock";
}

// The handoff to the existing checkout flow. Reorder produces the AVAILABLE
// items only and, by construction, settles nothing: the flags record that the
// purchase must go through buy's DRY quote, an explicit user confirmation, and
// only then buy --settle --confirm. This is the no-auto-buy property, made
// explicit so an offline test can assert it.
export interface ReorderPlan {
  items: CartItem[];
  settles: false;
  requires_dry_then_confirm: true;
}

// Join each past line item to its CURRENT price and availability. The product
// resolver is injected so this is exercised offline with no network or secrets.
// A resolver that reports the SKU gone (found:false) or out of stock
// (in_stock:false) yields an unavailable candidate that is skipped, never a
// throw, so one dead SKU cannot fail the whole reorder.
export async function resolveReorderCandidates(
  lineItems: ReorderLineItem[],
  getCurrent: CurrentProductResolver,
): Promise<ReorderCandidate[]> {
  const out: ReorderCandidate[] = [];
  for (const li of lineItems) {
    const orig = typeof li.unit_price === "number" ? li.unit_price : null;
    let cur: CurrentProduct;
    try {
      cur = await getCurrent(li.product_id);
    } catch {
      // A failed lookup is treated as "cannot confirm availability": skip this
      // SKU rather than erroring the whole reorder.
      cur = { found: false };
    }
    if (!cur.found) {
      out.push({
        product_id: li.product_id,
        qty: li.qty,
        available: false,
        reason: "not_found",
        original_unit_price: orig,
      });
      continue;
    }
    if (cur.in_stock === false) {
      out.push({
        product_id: li.product_id,
        qty: li.qty,
        available: false,
        reason: "out_of_stock",
        original_unit_price: orig,
        ...(cur.name !== undefined ? { name: cur.name } : {}),
        ...(typeof cur.price === "number" ? { current_price: cur.price } : {}),
        ...(cur.currency !== undefined ? { currency: cur.currency } : {}),
        in_stock: false,
      });
      continue;
    }
    const priced = typeof cur.price === "number";
    out.push({
      product_id: li.product_id,
      qty: li.qty,
      available: true,
      original_unit_price: orig,
      in_stock: true,
      ...(cur.name !== undefined ? { name: cur.name } : {}),
      ...(priced ? { current_price: cur.price } : {}),
      ...(cur.currency !== undefined ? { currency: cur.currency } : {}),
      ...(orig !== null && priced ? { price_changed: orig !== cur.price } : {}),
    });
  }
  return out;
}

// Turn resolved candidates into the buy handoff: the AVAILABLE items only, plus
// the flags that pin reorder to buy's confirm-then-settle path. Unavailable
// candidates are dropped here, so a gone or out-of-stock SKU never reaches the
// checkout. Exported for an offline test of the no-auto-buy property.
export function buildReorderPlan(candidates: ReorderCandidate[]): ReorderPlan {
  const items = candidates
    .filter((c) => c.available)
    .map((c) => ({ id: c.product_id, qty: c.qty }));
  return { items, settles: false, requires_dry_then_confirm: true };
}

// ---- revise: change a multi-item order before fulfillment -------------------
//   Boson cannot partially refund a COMMITTED escrow (raiseDispute requires a
//   REDEEMED exchange, and resolveDispute needs a DISPUTED one), so "remove one
//   line before it ships" is not a single on-chain move. The non-custodial
//   equivalent is cancel-and-rebuy: cancel the WHOLE order (the full escrow returns
//   to the buyer, cashed back to the wallet with --withdraw) then re-buy only the
//   kept items as a fresh signed purchase. This planner is PURE: it constructs the
//   two commands and moves NO money on its own, exactly like `reorder`. Each leg
//   leaves a signed receipt (the cancel a facet-lifecycle+jws, the rebuy a
//   settlement receipt), so the revision is fully auditable.
export interface RevisePlanStep {
  readonly step: number;
  readonly action: "cancel" | "buy";
  readonly command: string;
  readonly effect: string;
}
export interface RevisePlan {
  readonly mode: "REVISE_PLAN";
  readonly exchange_id: string;
  readonly kept_items: CartItem[];
  readonly steps: RevisePlanStep[];
  readonly settled: false;
  readonly auto_executed: false;
}

export function buildRevisePlan(
  base: string,
  exchangeId: string,
  keptItems: CartItem[],
  walletLabel?: string,
): RevisePlan {
  const walletArg = walletLabel !== undefined && walletLabel !== "" ? `--wallet ${walletLabel} ` : "";
  const cancelCmd = `cancel --terminal ${base} ${walletArg}--exchange-id ${exchangeId} --withdraw`;
  const buyCmd = `buy --terminal ${base} ${walletArg}--items '${JSON.stringify(keptItems)}' --ship '<json>'`;
  return {
    mode: "REVISE_PLAN",
    exchange_id: exchangeId,
    kept_items: keptItems,
    steps: [
      {
        step: 1,
        action: "cancel",
        command: cancelCmd,
        effect:
          "cancels the WHOLE order and cashes the full escrow back to your wallet (gasless), " +
          "archiving the signed cancel receipt",
      },
      {
        step: 2,
        action: "buy",
        command: buyCmd,
        effect:
          "re-buys only the kept items as a fresh signed purchase, archiving the settlement " +
          "receipt; run buy DRY, confirm the seller-signed quote, then --settle",
      },
    ],
    settled: false,
    auto_executed: false,
  };
}

// Non-async on purpose: revise is a PURE planner (no network), so it has nothing to
// await. The dispatch still `await`s it uniformly, which is a harmless no-op.
function cmdRevise(flags: Record<string, string | boolean>): never {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const exchangeId = requireFlag(flags, "exchange-id");
  const keepRaw = requireFlag(flags, "keep");
  let kept: CartItem[];
  try {
    kept = JSON.parse(keepRaw) as CartItem[];
  } catch {
    die("--keep must be valid JSON: an array of {id, qty} for the items to keep and re-buy.");
  }
  if (!Array.isArray(kept) || kept.length === 0) {
    die("--keep must be a non-empty JSON array of {id, qty} (the items to keep).");
  }
  for (const c of kept) {
    if (typeof c?.id !== "string" || c.id === "") {
      die("each --keep entry needs a non-empty string id.");
    }
    if (!Number.isInteger(c?.qty) || c.qty <= 0) {
      die(`--keep qty for "${c?.id}" must be a positive integer.`);
    }
  }
  const walletLabel = typeof flags.wallet === "string" && flags.wallet !== "" ? flags.wallet : undefined;
  const plan = buildRevisePlan(base, exchangeId, kept, walletLabel);
  emit({
    ok: true,
    ...plan,
    message:
      `Boson cannot partially refund a committed escrow, so revising before fulfillment is a ` +
      `cancel-and-rebuy: step 1 cancels the whole order (full refund to your wallet), step 2 ` +
      `re-buys the ${kept.length} kept item(s). Both legs leave a signed receipt. This plan ` +
      `moves no money on its own; run the two commands, confirming each.`,
  });
}

async function cmdReorder(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const wf = flags.wallet;
  const walletLabel = typeof wf === "string" && wf !== "" ? wf : undefined;
  const limit = flags.limit !== undefined ? Number(flags.limit) : 50;

  // Resolve a trusted, wallet-bound KYA once (minting if needed), then reuse the
  // token across order_history and every get_product. The Terminal scopes
  // order_history to this identity's aid, so the buyer only ever reads back
  // their OWN orders. kyaHeaders() stamps a fresh idempotency-key per request.
  const headers = await browseKyaHeaders(flags);
  const kyaTok = String(headers.authorization ?? "").replace(/^Bearer\s+/i, "");

  note(`POST ${base}/v1/order_history`);
  const hRes = await fetch(`${base}/v1/order_history`, {
    method: "POST",
    headers,
    body: JSON.stringify({ limit: Number.isFinite(limit) && limit > 0 ? limit : 50 }),
  });
  const hText = await hRes.text();
  if (hRes.status === 401 || hRes.status === 402 || hRes.status === 403) {
    die(`order_history is identity-gated; a wallet-bound KYA is required (HTTP ${hRes.status}).`, {
      http_status: hRes.status,
    });
  }
  if (!hRes.ok) die(`order_history failed HTTP ${hRes.status}`, { body: hText.slice(0, 400) });
  const hist = parseJsonObjOrDie(hText, "order_history") as {
    orders?: Array<Record<string, unknown>>;
  };
  const orders = hist.orders ?? [];
  if (orders.length === 0) {
    die(`no past orders for this identity at ${base}; nothing to reorder.`);
  }

  // Select the source order: an explicit --order-id from the fetched window, or
  // the most recent order (order_history returns newest first).
  const wantId = typeof flags["order-id"] === "string" ? flags["order-id"] : undefined;
  let order: Record<string, unknown>;
  if (wantId !== undefined && wantId !== "") {
    const found = orders.find((o) => String(o.order_id ?? "") === wantId);
    if (found === undefined) {
      die(
        `order ${wantId} was not in the ${orders.length} most recent orders; ` +
          `it may be older than the fetched window. Raise --limit or omit --order-id ` +
          `to reorder the most recent order.`,
        { fetched: orders.length },
      );
    }
    order = found;
  } else {
    order = orders[0];
  }
  const orderId = String(order.order_id ?? "");

  const orderItems = order.line_items;
  const rawItems = Array.isArray(orderItems) ? orderItems as Array<Record<string, unknown>> : [];
  const lineItems: ReorderLineItem[] = rawItems
    .filter((li) => typeof li.product_id === "string" && li.product_id !== "")
    .map((li) => ({
      product_id: String(li.product_id),
      qty: Number.isInteger(li.qty) && (li.qty as number) > 0 ? li.qty as number : 1,
      ...(typeof li.unit_price === "number" ? { unit_price: li.unit_price } : {}),
    }));
  if (lineItems.length === 0) {
    die(`order ${orderId} has no line items to reorder.`);
  }

  // Read the CURRENT price and availability per SKU from get_product. A 404
  // (SKU gone), a non-2xx, or an unparseable body all resolve to found:false so
  // the SKU is skipped as unavailable, never fatal to the reorder.
  const getCurrent: CurrentProductResolver = async (productId) => {
    note(`POST ${base}/v1/get_product (${productId})`);
    const r = await fetch(`${base}/v1/get_product`, {
      method: "POST",
      headers: kyaHeaders(kyaTok),
      body: JSON.stringify({ product_id: productId }),
    });
    const text = await r.text();
    if (!r.ok) return { found: false };
    let p: Record<string, unknown> | null;
    try {
      const v = JSON.parse(text);
      p = v !== null && typeof v === "object" && !Array.isArray(v)
        ? v as Record<string, unknown>
        : null;
    } catch {
      p = null;
    }
    if (p === null) return { found: false };
    const pricing = (typeof p.pricing === "object" && p.pricing !== null ? p.pricing : {}) as {
      currency?: unknown;
      per_case?: unknown;
    };
    return {
      found: true,
      ...(typeof p.name === "string" ? { name: p.name } : {}),
      ...(typeof pricing.per_case === "number" ? { price: pricing.per_case } : {}),
      ...(typeof pricing.currency === "string" ? { currency: pricing.currency } : {}),
      in_stock: p.in_stock === true,
    };
  };

  const candidates = await resolveReorderCandidates(lineItems, getCurrent);
  const plan = buildReorderPlan(candidates);
  const availableCount = plan.items.length;
  const unavailableCount = candidates.length - availableCount;

  // An informational sum of the current prices, when every available candidate
  // priced. This is a preview only; the authoritative total is the price the
  // seller-signed offer advertises inside the buy DRY quote, which is what the
  // user confirms before any settlement.
  let currentTotal = 0;
  let allPriced = availableCount > 0;
  let currency: string | undefined;
  for (const c of candidates) {
    if (!c.available) continue;
    if (typeof c.current_price === "number") {
      currentTotal += c.current_price * c.qty;
      if (currency === undefined && c.currency !== undefined) currency = c.currency;
    } else {
      allPriced = false;
    }
  }

  const items = plan.items;
  const itemsJson = JSON.stringify(items);
  const walletArg = walletLabel !== undefined ? `--wallet ${walletLabel} ` : "";
  const buyHint = `buy --terminal ${base} ${walletArg}--items '${itemsJson}' --ship '<json>'`;
  emit({
    ok: true,
    mode: "RESOLVE",
    terminal: base,
    source_order_id: orderId,
    wallet: walletLabel ?? null,
    candidate_count: candidates.length,
    available_count: availableCount,
    unavailable_count: unavailableCount,
    candidates,
    // The handoff to the EXISTING buy flow. Reorder resolves the cart and stops:
    // it settles nothing (settled:false) and buys nothing on its own
    // (auto_bought:false). The purchase runs through buy DRY, an explicit user
    // confirmation, then buy --settle --confirm, exactly like any other buy.
    settled: false,
    auto_bought: false,
    reorder: availableCount > 0
      ? {
        items,
        ...(allPriced ? { current_total: currentTotal } : {}),
        ...(currency !== undefined ? { currency } : {}),
        buy_is_dry: true,
        requires_confirmation: true,
      }
      : null,
    next: availableCount > 0
      ? `Review the ${availableCount} available item(s), then reorder via the buy flow (DRY ` +
        `first): ${buyHint}. Show the user the DRY total, get an explicit yes, then settle ` +
        `with --settle --confirm <atomic>. Reorder never settles on its own.`
      : `No available items to reorder from order ${orderId}` +
        (unavailableCount > 0 ? ` (${unavailableCount} SKU(s) gone or out of stock).` : "."),
    message: availableCount > 0
      ? `Resolved ${availableCount} available item(s) at current prices from order ${orderId}` +
        (unavailableCount > 0 ? `; skipped ${unavailableCount} unavailable SKU(s).` : ".") +
        ` Nothing has been bought. Confirm the buy DRY total before settling.`
      : `Order ${orderId} has no items available to reorder right now. Nothing has been bought.`,
  });
}

// ---- receipt: the portable, self-verifying settlement proof ----------------
//   POST /v1/get_receipt {order_id} returns { receipt: { format, jws, kid,
//   provider_jwks } }, where `jws` is a compact Ed25519 JWS (RFC 7515) the Facet
//   ledger signs over the settled order. Shape:
//     header  { alg:"EdDSA", typ:"facet-receipt+jws", kid }
//     payload { iss, sub:<agent aid>, iat, jti:<order id>,
//               settlement:{ rail, amount_minor, currency, settled_at, livemode },
//               chain:{ this_hash, prev_hash },   // link into the tamper-evident ledger
//               attestations:[{ party:"merchant"|"agent", says, signed_at }],
//               split?:{ goods_minor, tax_minor, shipping_minor, duty_minor, discount_minor } }
//   The receipt is anchored server-side BEFORE the checkout COMPLETE response
//   returns (the ledger append is awaited during response signing), so a fetch
//   right after a settled buy is race-free. A deferred-settlement rail (escrow
//   that settles at redeem) may not anchor until a later leg; then get_receipt
//   answers 404 and this reports { available:false } rather than an error.

interface ReceiptEntry {
  readonly format?: string;
  readonly jws?: string;
  readonly kid?: string;
  readonly provider_jwks?: string;
}

// Decode one base64url JWS segment to a JSON object. Tolerates missing padding.
export function b64urlToJson(seg: string): Record<string, unknown> {
  const pad = seg.length % 4 === 0 ? "" : "=".repeat(4 - (seg.length % 4));
  const bin = atob(seg.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

// Fetch the signed receipt for a settled order on the buyer's KYA. Never throws:
// a receipt is proof of a payment that already happened, so a fetch problem must
// never read like the payment failed. Returns { entry:null } when the ledger has
// not anchored a receipt yet (404) or on any transport error, with a human note.
// An optional walletAuth block re-authorizes by the payer wallet when the buy KYA
// has expired (see walletReceiptAuth). Returns the HTTP status so the caller can
// decide whether that fallback is worth trying.
async function fetchReceipt(
  base: string,
  orderId: string,
  kya: string,
  walletAuth?: Record<string, unknown>,
): Promise<{ entry: ReceiptEntry | null; note: string; status: number }> {
  try {
    const r = await fetch(`${base}/v1/get_receipt`, {
      method: "POST",
      headers: kyaHeaders(kya),
      body: JSON.stringify(
        walletAuth !== undefined
          ? { order_id: orderId, wallet_auth: walletAuth }
          : { order_id: orderId },
      ),
    });
    const text = await r.text();
    if (r.status === 404) {
      return {
        entry: null,
        note: "no receipt anchored yet; try `receipt --order-id` again shortly",
        status: 404,
      };
    }
    if (r.status < 200 || r.status >= 300) {
      return {
        entry: null,
        note: `get_receipt failed HTTP ${r.status}: ${text.slice(0, 200)}`,
        status: r.status,
      };
    }
    let body: { receipt?: ReceiptEntry };
    try {
      body = JSON.parse(text) as { receipt?: ReceiptEntry };
    } catch {
      return { entry: null, note: "get_receipt returned unparseable JSON", status: r.status };
    }
    const entry = body?.receipt ?? null;
    if (entry === null || typeof entry.jws !== "string" || entry.jws === "") {
      return { entry: null, note: "get_receipt returned no receipt jws", status: r.status };
    }
    return { entry, note: "ok", status: r.status };
  } catch (e) {
    return {
      entry: null,
      note: `get_receipt error: ${e instanceof Error ? e.message : String(e)}`,
      status: 0,
    };
  }
}

// Sign the canonical receipt-refetch challenge locally with the wallet, proving
// control of the order's payer wallet WITHOUT the (expired) purchase KYA. The
// address is derived from the key, so it is always the checksummed form the
// Terminal reconstructs. The key never leaves this process; only the signature,
// the nonce, and the issued-at leave it. Mirrors the Terminal's receiptRefetch
// challenge exactly.
async function walletReceiptAuth(
  walletKey: string,
  orderId: string,
): Promise<Record<string, unknown>> {
  const account = privateKeyToAccount(walletKey as `0x${string}`);
  const wallet = account.address;
  const issued_at = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const message =
    `Facet receipt refetch\norder: ${orderId}\nwallet: ${wallet}\nissued_at: ${issued_at}\nnonce: ${nonce}`;
  const signature = await account.signMessage({ message });
  return { wallet, issued_at, nonce, signature };
}

// Verify a receipt OFFLINE with a stock JOSE library. The trust anchor is the
// host you transacted with (`trustedOrigin`), NOT the receipt: we require the
// SIGNED `iss` to equal that origin and pin the JWKS to it, so a receipt can
// never nominate the key that validates it (the entry's provider_jwks hint sits
// outside the signature and is deliberately ignored). No call to Facet beyond
// fetching the issuer's public keys. Returns the claims either way, so a failure
// still shows what the receipt asserts and the reason it did not verify.
export async function verifyReceipt(
  entry: ReceiptEntry,
  trustedOrigin: string,
  expectedTyp: string = FACET_RECEIPT_TYP,
): Promise<Record<string, unknown>> {
  const jws = entry.jws ?? "";
  const parts = jws.split(".");
  if (parts.length !== 3) return { verified: false, reason: "malformed" };
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = b64urlToJson(parts[0]);
    claims = b64urlToJson(parts[1]);
  } catch {
    return { verified: false, reason: "malformed" };
  }
  if (header.typ !== expectedTyp) {
    return { verified: false, reason: "typ_mismatch", header, claims };
  }
  if (header.alg !== "EdDSA") {
    return { verified: false, reason: "alg_mismatch", header, claims };
  }
  const origin = trustedOrigin.replace(/\/+$/, "");
  const iss = typeof claims.iss === "string" ? claims.iss.replace(/\/+$/, "") : "";
  if (iss !== origin) {
    return { verified: false, reason: "issuer_mismatch", iss, expected: origin, header, claims };
  }
  let jwks: unknown;
  try {
    const jr = await fetch(`${origin}/.well-known/jwks.json`);
    if (!jr.ok) return { verified: false, reason: `jwks_http_${jr.status}`, header, claims };
    jwks = await jr.json();
  } catch (e) {
    return {
      verified: false,
      reason: "jwks_fetch_error",
      detail: e instanceof Error ? e.message : String(e),
      header,
      claims,
    };
  }
  try {
    const keySet = createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]);
    const { payload } = await compactVerify(jws, keySet);
    const verified = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;
    return { verified: true, header, claims: verified };
  } catch (e) {
    return {
      verified: false,
      reason: "bad_signature",
      detail: e instanceof Error ? e.message : String(e),
      header,
      claims,
    };
  }
}

// ---- receipt archive: durable, tracked, like the wallet -------------------
//   Every fetched receipt is saved to a receipts folder (default
//   ~/.facet/receipts, overridable with FACET_RECEIPTS_DIR) so a purchase leaves
//   a permanent, independently verifiable record. One <order_id>.json per order
//   (the full receipt: jws, kid, decoded claims, verified flag) plus an
//   append-only index.jsonl that the `receipts` subcommand lists. Saving needs
//   --allow-write to that dir (see SKILL.md); without it the save is skipped with
//   a note and the receipt is still returned, since a receipt is proof of a
//   payment that already happened and its persistence must never block the flow.

export function receiptsDir(): string {
  const override = Deno.env.get("FACET_RECEIPTS_DIR");
  if (override !== undefined && override.trim() !== "") return override.replace(/\/+$/, "");
  const home = Deno.env.get("HOME") ?? ".";
  return `${home}/.facet/receipts`;
}

// Parse an index.jsonl body into the tracked receipts, newest first, deduped by
// order_id (a re-fetch appends a fresh line; the latest save wins). Corrupt lines
// are skipped rather than failing the whole listing. Pure, so it is unit-tested.
export function dedupReceiptIndex(raw: string): Record<string, unknown>[] {
  const byOrder = new Map<string, Record<string, unknown>>();
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    try {
      const r = JSON.parse(line) as Record<string, unknown>;
      if (typeof r.order_id === "string") byOrder.set(r.order_id, r);
    } catch {
      // Skip a corrupt line rather than fail the whole listing.
    }
  }
  return [...byOrder.values()].sort((a, b) =>
    String(b.saved_at ?? "").localeCompare(String(a.saved_at ?? ""))
  );
}

// Persist one fetched receipt. Best-effort and never throws: returns whether it
// saved and where. `verified` is the offline-verification result (null when
// skipped). Claims are decoded from the jws so the record and the index summary
// are self-contained.
function saveReceipt(
  terminal: string,
  orderId: string,
  entry: ReceiptEntry,
  verified: boolean | null,
): { saved: boolean; path?: string; note?: string } {
  const dir = receiptsDir();
  let claims: Record<string, unknown> = {};
  try {
    claims = b64urlToJson((entry.jws ?? "").split(".")[1] ?? "");
  } catch {
    // A payload that will not decode is still saved verbatim; the index summary
    // just carries nulls for its settlement fields.
  }
  const settlement = (claims.settlement ?? {}) as Record<string, unknown>;
  const savedAt = new Date().toISOString();
  const record = {
    order_id: orderId,
    terminal,
    jws: entry.jws,
    kid: entry.kid,
    provider_jwks: entry.provider_jwks,
    verified,
    claims,
    saved_at: savedAt,
  };
  try {
    Deno.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = `${dir}/${orderId}.json`;
    Deno.writeTextFileSync(file, JSON.stringify(record, null, 2), { mode: 0o600 });
    const idx = {
      order_id: orderId,
      terminal,
      rail: settlement.rail ?? null,
      amount_minor: settlement.amount_minor ?? null,
      currency: settlement.currency ?? null,
      settled_at: settlement.settled_at ?? null,
      verified,
      file: `${orderId}.json`,
      saved_at: savedAt,
    };
    Deno.writeTextFileSync(`${dir}/index.jsonl`, JSON.stringify(idx) + "\n", {
      append: true,
      mode: 0o600,
    });
    return { saved: true, path: file };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    note(`receipt not saved to ${dir}: ${msg} (grant --allow-write to the receipts dir)`);
    return { saved: false, note: msg };
  }
}

// The reversal-receipt lookup: a caller-held handle plus the reversal kind. The
// handle is the order_id for a refund, or the Boson exchange_id for cancel /
// withdraw / dispute (those have no Facet order uuid). One of orderId / exchangeId
// is required.
interface LifecycleLookup {
  readonly kind: "cancel" | "refund" | "withdraw" | "dispute";
  readonly orderId?: string;
  readonly exchangeId?: string;
}

// Fetch the signed lifecycle (reversal) receipt for a cancel / withdraw / dispute /
// refund. Mirrors fetchReceipt: never throws, returns { entry:null } with a human
// note on a 404 (the reversal's event row has not anchored yet, or the caller is not
// its owner) or any transport error, so a receipt hiccup never reads as a failed
// reversal. The Terminal owner-scopes this to a 404 with NO existence oracle and NO
// wallet-auth fallback (stricter than get_receipt), so the reliable path is to fetch
// it in the same session that performed the reversal (same KYA) and archive it then.
async function fetchLifecycleReceipt(
  base: string,
  lookup: LifecycleLookup,
  kya: string,
): Promise<{ entry: ReceiptEntry | null; note: string; status: number }> {
  const body: Record<string, unknown> = { kind: lookup.kind };
  if (lookup.orderId !== undefined) body.order_id = lookup.orderId;
  if (lookup.exchangeId !== undefined) body.exchange_id = lookup.exchangeId;
  try {
    const r = await fetch(`${base}/v1/get_lifecycle_receipt`, {
      method: "POST",
      headers: kyaHeaders(kya),
      body: JSON.stringify(body),
    });
    const text = await r.text();
    if (r.status === 404) {
      return {
        entry: null,
        note: "no lifecycle receipt anchored for that reference yet; retry shortly",
        status: 404,
      };
    }
    if (r.status < 200 || r.status >= 300) {
      return {
        entry: null,
        note: `get_lifecycle_receipt failed HTTP ${r.status}: ${text.slice(0, 200)}`,
        status: r.status,
      };
    }
    let parsed: { receipt?: ReceiptEntry };
    try {
      parsed = JSON.parse(text) as { receipt?: ReceiptEntry };
    } catch {
      return {
        entry: null,
        note: "get_lifecycle_receipt returned unparseable JSON",
        status: r.status,
      };
    }
    const entry = parsed?.receipt ?? null;
    if (entry === null || typeof entry.jws !== "string" || entry.jws === "") {
      return { entry: null, note: "get_lifecycle_receipt returned no receipt jws", status: r.status };
    }
    return { entry, note: "ok", status: r.status };
  } catch (e) {
    return {
      entry: null,
      note: `get_lifecycle_receipt error: ${e instanceof Error ? e.message : String(e)}`,
      status: 0,
    };
  }
}

// Persist a reversal receipt to the same archive as settlement receipts, keyed by
// `lifecycle-<kind>-<handle>` (the handle is the exchange_id or order_id). Keying on
// the kind + handle keeps a cancel with no order uuid filed, and stops a reversal
// receipt from colliding with the order's settlement receipt (`<order_id>.json`). The
// index summary carries the EVENT block (kind, rail, amount, tx hash), not a
// settlement block. Mirrors saveReceipt's write discipline.
function saveLifecycleReceipt(
  terminal: string,
  lookup: LifecycleLookup,
  entry: ReceiptEntry,
  verified: boolean | null,
): { saved: boolean; path?: string; note?: string } {
  const dir = receiptsDir();
  let claims: Record<string, unknown> = {};
  try {
    claims = b64urlToJson((entry.jws ?? "").split(".")[1] ?? "");
  } catch {
    // Undecodable payload is still saved verbatim; the index carries nulls.
  }
  const event = (claims.event ?? {}) as Record<string, unknown>;
  const handle = lookup.exchangeId ?? lookup.orderId ?? "unknown";
  const key = `lifecycle-${lookup.kind}-${handle}`;
  const savedAt = new Date().toISOString();
  const record = {
    key,
    kind: lookup.kind,
    order_id: lookup.orderId ?? null,
    exchange_id: lookup.exchangeId ?? null,
    terminal,
    jws: entry.jws,
    kid: entry.kid,
    provider_jwks: entry.provider_jwks,
    verified,
    claims,
    saved_at: savedAt,
  };
  try {
    Deno.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = `${dir}/${key}.json`;
    Deno.writeTextFileSync(file, JSON.stringify(record, null, 2), { mode: 0o600 });
    const idx = {
      key,
      kind: lookup.kind,
      order_id: lookup.orderId ?? null,
      exchange_id: lookup.exchangeId ?? null,
      terminal,
      rail: event.rail ?? null,
      amount_minor: event.amount_minor ?? null,
      currency: event.currency ?? null,
      tx_hash: event.tx_hash ?? null,
      occurred_at: event.occurred_at ?? null,
      verified,
      file: `${key}.json`,
      saved_at: savedAt,
    };
    Deno.writeTextFileSync(`${dir}/index.jsonl`, JSON.stringify(idx) + "\n", {
      append: true,
      mode: 0o600,
    });
    return { saved: true, path: file };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    note(`lifecycle receipt not saved to ${dir}: ${msg} (grant --allow-write to the receipts dir)`);
    return { saved: false, note: msg };
  }
}

// Fetch + verify + save a reversal receipt, returning the shape the reversal commands
// fold into their result under `receipt`. Best-effort by construction: the reversal
// already happened on-chain, so a receipt problem must never read as a failed
// reversal. Returns { available:false, note } when the event has not anchored yet.
async function fetchVerifySaveLifecycle(
  base: string,
  lookup: LifecycleLookup,
  kya: string,
): Promise<Record<string, unknown>> {
  const { entry, note: rnote } = await fetchLifecycleReceipt(base, lookup, kya);
  if (entry === null) {
    return { available: false, note: rnote };
  }
  const v = await verifyReceipt(entry, base, FACET_LIFECYCLE_TYP);
  const saved = saveLifecycleReceipt(base, lookup, entry, v.verified === true);
  return {
    format: entry.format ?? FACET_LIFECYCLE_TYP,
    jws: entry.jws,
    kid: entry.kid,
    provider_jwks: entry.provider_jwks,
    ...v,
    saved: saved.saved,
    ...(saved.path !== undefined ? { saved_path: saved.path } : {}),
  };
}

// ---- receipts: list the saved receipt archive -----------------------------
// lifecycle-receipt: fetch + verify + archive a signed REVERSAL receipt on demand
// (the cancel / withdraw / dispute / refund analogue of `receipt`). Looked up by the
// caller-held handle: --exchange-id for cancel / withdraw / dispute, --order-id for a
// refund, plus --kind. The Terminal owner-scopes this to a 404 with NO wallet-auth
// fallback, so it resolves only for the identity that performed the reversal. The
// reversal commands already archive it inline; use this to re-fetch it, or to fetch
// one performed earlier in the same wallet-bound identity.
async function cmdLifecycleReceipt(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const kind = requireFlag(flags, "kind");
  if (!["cancel", "refund", "withdraw", "dispute"].includes(kind)) {
    die(`--kind must be one of cancel, refund, withdraw, dispute (got "${kind}")`);
  }
  const orderId = typeof flags["order-id"] === "string" ? flags["order-id"] : undefined;
  const exchangeId = typeof flags["exchange-id"] === "string" ? flags["exchange-id"] : undefined;
  if (orderId === undefined && exchangeId === undefined) {
    die("provide --exchange-id (cancel / withdraw / dispute) or --order-id (refund)");
  }
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const kya = await walletBoundKya(wallet);
  const lookup: LifecycleLookup = {
    kind: kind as LifecycleLookup["kind"],
    ...(orderId !== undefined ? { orderId } : {}),
    ...(exchangeId !== undefined ? { exchangeId } : {}),
  };
  note(`POST ${base}/v1/get_lifecycle_receipt for ${kind} ${exchangeId ?? orderId}`);
  const receipt = await fetchVerifySaveLifecycle(base, lookup, kya);
  emit({
    ok: receipt.available !== false,
    kind,
    ...(orderId !== undefined ? { order_id: orderId } : {}),
    ...(exchangeId !== undefined ? { exchange_id: exchangeId } : {}),
    receipt,
  });
}

async function cmdReceipts(_flags: Record<string, string | boolean>): Promise<never> {
  const dir = receiptsDir();
  let raw = "";
  try {
    raw = await Deno.readTextFile(`${dir}/index.jsonl`);
  } catch {
    emit({ ok: true, receipts_dir: dir, count: 0, receipts: [], note: "no receipts saved yet" });
  }
  const receipts = dedupReceiptIndex(raw);
  emit({ ok: true, receipts_dir: dir, count: receipts.length, receipts });
}

// ---- receipt subcommand: fetch + verify a settled order's proof ------------
async function cmdReceipt(flags: Record<string, string | boolean>): Promise<never> {
  const base = terminalBase(requireFlag(flags, "terminal"));
  const orderId = requireFlag(flags, "order-id");
  const wallet = resolveWallet(typeof flags.wallet === "string" ? flags.wallet : undefined);
  const kya = await walletBoundKya(wallet);
  note(`POST ${base}/v1/get_receipt for order ${orderId}`);
  let { entry, note: rnote, status } = await fetchReceipt(base, orderId, kya);
  // The receipt is scoped to the ephemeral agent identity that made the purchase.
  // When that KYA has expired the aid cannot be reproduced and the Terminal answers
  // 403. Re-authorize by proving control of the order's DURABLE payer wallet: sign
  // the challenge locally (the key never leaves this process) and re-POST. The
  // fresh KYA above still clears the edge; the wallet signature is the real
  // authorization.
  if (entry === null && status === 403) {
    note(
      `aid-scoped fetch refused (403, expired purchase KYA); re-authorizing with a wallet signature`,
    );
    const walletAuth = await walletReceiptAuth(wallet.key, orderId);
    ({ entry, note: rnote, status } = await fetchReceipt(base, orderId, kya, walletAuth));
  }
  if (entry === null) {
    emit({ ok: true, order_id: orderId, available: false, receipt: null, note: rnote });
  }
  if (flags["no-verify"] === true) {
    const saved = saveReceipt(base, orderId, entry, null);
    emit({
      ok: true,
      order_id: orderId,
      available: true,
      jws: entry.jws,
      kid: entry.kid,
      provider_jwks: entry.provider_jwks,
      verified: null,
      saved: saved.saved,
      ...(saved.path !== undefined ? { saved_path: saved.path } : {}),
      note: "verification skipped (--no-verify)",
    });
  }
  const v = await verifyReceipt(entry, base);
  const saved = saveReceipt(base, orderId, entry, v.verified === true);
  emit({
    ok: true,
    order_id: orderId,
    available: true,
    jws: entry.jws,
    kid: entry.kid,
    provider_jwks: entry.provider_jwks,
    ...v,
    saved: saved.saved,
    ...(saved.path !== undefined ? { saved_path: saved.path } : {}),
  });
}

// ---- dispatch --------------------------------------------------------------
// Guarded so this module can be imported by an offline unit test (of the
// exported validators) without running the CLI. When run directly as the
// program, import.meta.main is true and the dispatch executes as before.
if (import.meta.main) {
  const { cmd, sub, positional, flags } = parseArgs(Deno.args);
  // Defense in depth. Every command path already funnels its own failures
  // through die()/emit(), which call Deno.exit and return `never`, so a normal
  // refusal never reaches this catch. It exists only for a genuinely unexpected
  // throw (an unforeseen runtime error before a die() could fire), normalizing
  // it to the same one-JSON-object stdout contract instead of a raw stack trace.
  try {
    switch (cmd) {
      case "wallet":
        await cmdWalletNew(sub, flags);
        break;
      case "wallets":
        await cmdWallets(flags);
        break;
      case "fund":
        await cmdFund(flags);
        break;
      case "discover":
        await cmdDiscover(flags);
        break;
      case "directory":
        await cmdDirectory(flags);
        break;
      case "search":
        await cmdSearch(flags);
        break;
      case "product":
        await cmdProduct(flags);
        break;
      case "provision":
        await cmdProvision(flags);
        break;
      case "buy":
        await cmdBuy(flags);
        break;
      case "email-pref":
        // positional[2] is the address argument for `email-pref set <address>`.
        cmdEmailPref(sub, positional[2], flags);
        break;
      case "redeem":
        await cmdRedeem(flags);
        break;
      case "cancel":
        await cmdCancel(flags);
        break;
      case "withdraw":
        await cmdWithdraw(flags);
        break;
      case "dispute":
        await cmdDispute(flags);
        break;
      case "refund":
        await cmdRefund(flags);
        break;
      case "resolve":
        await cmdResolve(flags);
        break;
      case "reorder":
        await cmdReorder(flags);
        break;
      case "revise":
        await cmdRevise(flags);
        break;
      case "receipt":
        await cmdReceipt(flags);
        break;
      case "receipts":
        await cmdReceipts(flags);
        break;
      case "lifecycle-receipt":
        await cmdLifecycleReceipt(flags);
        break;
      default:
        die(
          `unknown subcommand "${cmd}". Use: wallet new | wallets | fund | discover | directory | ` +
            `search | product | provision | buy | email-pref | redeem | cancel | withdraw | dispute | ` +
            `refund | resolve | reorder | revise | receipt | receipts | lifecycle-receipt.`,
        );
    }
  } catch (e) {
    die(`unexpected error: ${e instanceof Error ? e.message : String(e)}`);
  }
}
