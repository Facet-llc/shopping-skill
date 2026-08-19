// Offline unit tests for the wallet-mint onboarding module (P1-3). These cover
// the pieces that can be exercised with NO real OS keychain and NO real funds:
// the never-leak invariant (no key or mnemonic in the stdout result), the
// encrypted-keystore round-trip, the keystore path being off Google Drive (under
// ~/.facet), address-from-mnemonic derivation, label validation, and the pure
// fund threshold. The keychain tier and the network balance are deliberately NOT
// touched here (a test must never write a real key to the real keychain, and must
// not hit the network for a balance).
//
// Run:
//   deno test --allow-env --allow-read --allow-write --allow-run --allow-net \
//     scripts/wallet.test.ts
//
// Importing wallet.ts pulls in facet-checkout.ts, whose CLI dispatch is guarded
// by import.meta.main (false here), so importing runs no command.

import { assert, assertEquals, assertStringIncludes, assertThrows } from "jsr:@std/assert@^1";
import { privateKeyToAccount } from "npm:viem@2.50.4/accounts";
import { mnemonicToAccount } from "npm:viem@2.50.4/accounts";
import {
  addressFromPrivateKey,
  buildWalletNewResult,
  decryptKeystore,
  encryptKeystore,
  fundedEnough,
  isValidLabel,
  type Keystore,
  keystorePathFor,
  mintWallet,
  readKeystore,
  readWalletIndex,
  safeLabel,
  walletsIndexPath,
  writeKeystore,
} from "./wallet.ts";

// Run a synchronous body with HOME pointed at a fresh temp dir, always restoring
// HOME and removing the temp dir. Keeps every file-touching test OFF the real
// ~/.facet and off Google Drive.
function withTempHome<T>(fn: (home: string) => T): T {
  const prev = Deno.env.get("HOME");
  const home = Deno.makeTempDirSync();
  Deno.env.set("HOME", home);
  try {
    return fn(home);
  } finally {
    if (prev !== undefined) Deno.env.set("HOME", prev);
    else Deno.env.delete("HOME");
    try {
      Deno.removeSync(home, { recursive: true });
    } catch {
      // best effort
    }
  }
}

// ---- derivation ------------------------------------------------------------
Deno.test("mintWallet: derived address matches the mnemonic and the private key", () => {
  const w = mintWallet();
  // A fresh 12-word BIP-39 phrase and a canonical 0x + 64 hex key.
  assertEquals(w.mnemonic.trim().split(/\s+/).length, 12);
  assert(/^0x[0-9a-fA-F]{64}$/.test(w.privateKey), "private key must be 0x + 64 hex");
  assert(/^0x[0-9a-fA-F]{40}$/.test(w.address), "address must be 0x + 40 hex");
  // The address must agree three ways: from the struct, from the key, and from
  // the mnemonic. This is the "derived address matches the mnemonic" check.
  assertEquals(addressFromPrivateKey(w.privateKey), w.address);
  assertEquals(privateKeyToAccount(w.privateKey as `0x${string}`).address, w.address);
  assertEquals(mnemonicToAccount(w.mnemonic).address, w.address);
});

Deno.test("mintWallet: two mints are distinct", () => {
  const a = mintWallet();
  const b = mintWallet();
  assert(a.mnemonic !== b.mnemonic, "each mint must produce a fresh mnemonic");
  assert(a.privateKey !== b.privateKey, "each mint must produce a fresh key");
  assert(a.address !== b.address, "each mint must produce a fresh address");
});

// ---- keystore crypto -------------------------------------------------------
Deno.test("keystore round-trips: encrypt then decrypt returns the same key", () => {
  const w = mintWallet();
  const ks = encryptKeystore(w.privateKey, "correct horse battery staple", {
    label: "t",
    address: w.address,
  });
  assertEquals(ks.crypto.cipher, "aes-256-gcm");
  assertEquals(ks.crypto.kdf, "pbkdf2");
  assertEquals(ks.crypto.kdfparams.iterations, 600_000);
  const back = decryptKeystore(ks, "correct horse battery staple");
  assertEquals(back, w.privateKey);
  assertEquals(addressFromPrivateKey(back), w.address);
});

Deno.test("keystore: the ciphertext is not the plaintext key", () => {
  const w = mintWallet();
  const ks = encryptKeystore(w.privateKey, "pw-pw-pw-pw", { label: "t", address: w.address });
  const blob = JSON.stringify(ks);
  // The encrypted keystore must never carry the key (or its no-0x form) in clear.
  assert(!blob.includes(w.privateKey), "ciphertext blob must not contain the key");
  assert(!blob.includes(w.privateKey.slice(2)), "ciphertext blob must not contain the raw key");
});

Deno.test("keystore: a wrong passphrase fails (GCM auth tag), never returns a key", () => {
  const w = mintWallet();
  const ks = encryptKeystore(w.privateKey, "the-right-one", { label: "t", address: w.address });
  assertThrows(() => decryptKeystore(ks, "the-wrong-one"));
});

Deno.test("keystore: a tampered ciphertext fails to decrypt", () => {
  const w = mintWallet();
  const ks = encryptKeystore(w.privateKey, "pw12345678", { label: "t", address: w.address });
  // Flip the ciphertext; the GCM tag check must reject it.
  const tampered: Keystore = {
    ...ks,
    crypto: { ...ks.crypto, ciphertext: btoa("tampered-ciphertext-bytes-here!!") },
  };
  assertThrows(() => decryptKeystore(tampered, "pw12345678"));
});

// ---- keystore path + file IO ----------------------------------------------
Deno.test("keystore path is under ~/.facet (off Google Drive)", () => {
  withTempHome((home) => {
    const p = keystorePathFor("default");
    assertEquals(p, `${home}/.facet/keys/default.json`);
    assertStringIncludes(p, "/.facet/");
    // The index lives under ~/.facet too.
    assertEquals(walletsIndexPath(), `${home}/.facet/wallets.json`);
  });
});

Deno.test("writeKeystore + readKeystore round-trip under a temp HOME", () => {
  withTempHome(() => {
    const w = mintWallet();
    const ks = encryptKeystore(w.privateKey, "pw-abc-123", { label: "biz", address: w.address });
    const path = writeKeystore("biz", ks);
    assertStringIncludes(path, "/.facet/keys/biz.json");
    const loaded = readKeystore("biz");
    assert(loaded !== undefined, "keystore should read back");
    assertEquals(decryptKeystore(loaded!, "pw-abc-123"), w.privateKey);
  });
});

Deno.test("keystore filename cannot escape the keys dir (label is sanitized)", () => {
  withTempHome((home) => {
    // A hostile label with separators must stay inside ~/.facet/keys. The
    // traversal-critical property is that no path SEPARATOR survives (dots are
    // harmless in a filename); isValidLabel additionally rejects such a label at
    // input, so safeLabel here is the defense-in-depth backstop.
    const keysPrefix = `${home}/.facet/keys/`;
    const p = keystorePathFor("../../etc/evil");
    assertStringIncludes(p, keysPrefix);
    const basename = p.slice(keysPrefix.length);
    assert(!basename.includes("/"), "sanitized basename must contain no separator");
    assertEquals(safeLabel("../../etc/evil").includes("/"), false);
    assert(!isValidLabel("../../etc/evil"), "such a label is rejected at input too");
  });
});

// ---- the never-leak invariant ----------------------------------------------
Deno.test("CRITICAL: buildWalletNewResult carries NO private key and NO mnemonic", () => {
  const w = mintWallet();
  const keystore = buildWalletNewResult({
    label: "default",
    address: w.address,
    storage: "keystore",
    keystorePath: "/tmp/x/.facet/keys/default.json",
  });
  const keychain = buildWalletNewResult({
    label: "default",
    address: w.address,
    storage: "keychain",
  });
  for (const result of [keystore, keychain]) {
    const s = JSON.stringify(result);
    // The stdout object must never carry the key, the raw key, or the mnemonic.
    assert(!s.includes(w.privateKey), "result must not contain the private key");
    assert(!s.includes(w.privateKey.slice(2)), "result must not contain the raw private key");
    assert(!s.includes(w.mnemonic), "result must not contain the mnemonic");
    // No consecutive run of mnemonic words may appear. A single BIP-39 word can be
    // an ordinary English word that legitimately occurs in a hint string (e.g.
    // "check" in the fund hint), so a per-word check false-positives at random; a
    // 2-word ordered run in a 12-word phrase is the real partial-leak signal.
    const mnemonicWords = w.mnemonic.split(" ");
    for (let i = 0; i + 1 < mnemonicWords.length; i++) {
      const run = `${mnemonicWords[i]} ${mnemonicWords[i + 1]}`;
      assert(!s.includes(run), `result must not leak mnemonic run "${run}"`);
    }
    // It MUST carry the public facts.
    assertStringIncludes(s, w.address);
    assertEquals((result as { ok: boolean }).ok, true);
    assertEquals((result as { label: string }).label, "default");
  }
});

// ---- label validation ------------------------------------------------------
Deno.test("isValidLabel accepts safe labels and rejects unsafe ones", () => {
  for (const ok of ["default", "biz", "wallet-1", "a_b.c", "A1"]) {
    assert(isValidLabel(ok), `"${ok}" should be valid`);
  }
  for (const bad of ["", "  ", "../evil", "a/b", "a b", ".hidden", "x".repeat(65), "a$b", "a\\b"]) {
    assert(!isValidLabel(bad), `"${bad}" should be rejected`);
  }
});

Deno.test("safeLabel strips path separators and unsafe characters", () => {
  assertEquals(safeLabel("default"), "default");
  assert(!safeLabel("../../etc/passwd").includes("/"), "no separators survive");
  assert(!safeLabel("a b/c").includes(" "), "no spaces survive");
});

// ---- discovery index -------------------------------------------------------
Deno.test("readWalletIndex is empty when no index exists", () => {
  withTempHome(() => {
    assertEquals(readWalletIndex(), []);
  });
});

// ---- fund threshold (pure, no network) -------------------------------------
Deno.test("fundedEnough: any positive balance funds when no minimum is set", () => {
  assertEquals(fundedEnough(0n, 0n), false);
  assertEquals(fundedEnough(1n, 0n), true);
  assertEquals(fundedEnough(5_000_000n, 0n), true);
});

Deno.test("fundedEnough: a minimum requires the balance to reach it", () => {
  assertEquals(fundedEnough(4_999_999n, 5_000_000n), false);
  assertEquals(fundedEnough(5_000_000n, 5_000_000n), true);
  assertEquals(fundedEnough(6_000_000n, 5_000_000n), true);
  assertEquals(fundedEnough(0n, 5_000_000n), false);
});
