import { assert, assertEquals, assertStringIncludes, assertThrows } from "jsr:@std/assert@^1";
import { fillReceiptTemplate, merchantNameFromHost, pubkeyXForKid } from "./render-receipt.ts";

// A compact JWS built from a real header + payload so fillReceiptTemplate can
// decode and render it. The signature segment is a placeholder (fillReceiptTemplate
// never verifies; that is the page's job).
function b64url(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function makeJws(claims: Record<string, unknown>): string {
  return `${b64url({ alg: "EdDSA", typ: "facet-receipt+jws", kid: "k1" })}.${b64url(claims)}.sig`;
}
const CLAIMS = {
  iss: "https://pecanandpetal.facet.llc",
  sub: "ucp-origin:https://facet.llc",
  iat: 1787194091,
  jti: "050d253c-c92e-47bc-baa5-069b22b0c294",
  settlement: {
    rail: "coin/boson-escrow",
    amount_minor: 2524,
    currency: "USD",
    settled_at: "2026-08-19T16:04:20+00:00",
    livemode: true,
    settlement_id: "20",
  },
  split: { goods_minor: 1500, tax_minor: 124, shipping_minor: 900, duty_minor: 0, discount_minor: 0 },
  chain: { this_hash: "50496f69thishash", prev_hash: "a9832f76prevhash" },
};

// A template stub carrying every token fillReceiptTemplate requires.
const TEMPLATE = [
  "<span class=cur>%%AMOUNT_CUR%%</span>%%AMOUNT%%",
  "<div class=chips>%%CHIPS%%</div>",
  "<div class=items>%%ITEMS%%</div>",
  "<dl class=breakdown>%%BREAKDOWN%%</dl>",
  "%%PROVENANCE%%",
  "<dl class=settle>%%SETTLEMENT_KV%%</dl>",
  "<dl class=signedby>%%SIGNEDBY_KV%%</dl>",
  "%%SERVER_TRAIL%%",
  "%%LEDGER%%",
  '<a id=orderBtn%%ORDER_HIDDEN%% href="%%ORDER_HREF%%">order</a>',
  '<a href="%%JWKS_HREF%%">keys</a>',
  "<span>%%RECEIPT_SHORT%%</span> at <span>%%MERCHANT_HOST%%</span>",
  "<script>const JWS = %%JWS%%; const PUBKEY_X = %%PUBKEY_X%%;</script>",
].join("\n");

Deno.test("fillReceiptTemplate renders money, breakdown, items, and settlement server-side", () => {
  const html = fillReceiptTemplate(TEMPLATE, {
    jws: makeJws(CLAIMS),
    pubkeyX: "PUBKEYX",
    merchant: { name: "Pecan & Petal", host: "pecanandpetal.facet.llc" },
    orderUrl: "https://pecanandpetal.facet.llc/orders/050d253c-c92e-47bc-baa5-069b22b0c294",
    items: [{ name: "Birthday Flower Arrangement", sku: "HCF-BDAY", qty: 1, amount_minor: 1500 }],
  });
  assert(!html.includes("%%"), "every token must be consumed");
  assertStringIncludes(html, "<span class=cur>USD</span>25.24");
  assertStringIncludes(html, "<dt>Goods</dt><dd>$15.00</dd>");
  assertStringIncludes(html, "Birthday Flower Arrangement");
  assertStringIncludes(html, "HCF-BDAY &#183; Qty 1");
  assertStringIncludes(html, "Boson escrow");
  assertStringIncludes(html, "Live &#183; Base mainnet");
  assertStringIncludes(html, "Boson exchange 20");
  assertStringIncludes(html, "050d253c"); // receipt short id in the footer
  assertStringIncludes(html, "50496f69thishash"); // ledger rendered
});

Deno.test("fillReceiptTemplate renders a fallback when there are no items", () => {
  const html = fillReceiptTemplate(TEMPLATE, { jws: makeJws(CLAIMS), pubkeyX: "k", merchant: { name: "m", host: "h" } });
  assertStringIncludes(html, "Line items are not available");
  assertStringIncludes(html, "<dt>Shipping</dt><dd>$9.00</dd>"); // breakdown still renders
});

Deno.test("fillReceiptTemplate injects the JWS and pubkey script-safely", () => {
  const html = fillReceiptTemplate(TEMPLATE, {
    jws: makeJws(CLAIMS),
    pubkeyX: "PUBKEYX",
    merchant: { name: "m", host: "h" },
  });
  assertStringIncludes(html, "const PUBKEY_X = \"PUBKEYX\";");
  assertStringIncludes(html, "const JWS = \"");
  // A null pubkey renders as the literal null (offline-verdict fallback in-page).
  const noKey = fillReceiptTemplate(TEMPLATE, { jws: makeJws(CLAIMS), pubkeyX: null, merchant: { name: "m", host: "h" } });
  assertStringIncludes(noKey, "const PUBKEY_X = null;");
});

Deno.test("fillReceiptTemplate renders the provenance section only when present", () => {
  const withProv = fillReceiptTemplate(TEMPLATE, {
    jws: makeJws(CLAIMS),
    pubkeyX: "k",
    merchant: { name: "m", host: "h" },
    provenance: {
      identity: { aid: "facet:agent:xyz", issuer: "https://issuer.facet.llc", expires: 1787196807 },
      payment: {
        rail: "boson",
        token_authorization: { from: "0xbuyeraaaaaaaaaaaaaaaaaaaaaaaaaaa1", to: "0xescrowbbbbbbbbbbbbbbbbbbbbbbbbb2", value: "2524000", nonce: "0xnoncecccc" },
        buyer_signature: { v: 28, r: "0xrrrrrrrrrrrrrrrrrrrr", s: "0xssssssssssssssssssss" },
        seller_signature: "0xsellerdddddddddddddddd",
        escrow: "0xescrowbbbbbbbbbbbbbbbbbbbbbbbbb2",
      },
    },
  });
  assertStringIncludes(withProv, "Buyer identity");
  assertStringIncludes(withProv, "facet:agent:xyz");
  assertStringIncludes(withProv, "Payment authorization");
  assertStringIncludes(withProv, "2.524 USDC");
  assertStringIncludes(withProv, "Seller sig");

  const noProv = fillReceiptTemplate(TEMPLATE, { jws: makeJws(CLAIMS), pubkeyX: "k", merchant: { name: "m", host: "h" } });
  assert(!noProv.includes("Buyer identity"), "no provenance section without provenance");
});

Deno.test("fillReceiptTemplate renders the server authorization trail when present", () => {
  const html = fillReceiptTemplate(TEMPLATE, {
    jws: makeJws(CLAIMS),
    pubkeyX: "k",
    merchant: { name: "m", host: "h" },
    serverTrail: {
      signatures: [
        { party: "facet", this_hash: "aa", signing_key_id: "k1" },
        { party: "merchant", attestation: "fulfilled" },
      ],
      authorizations: [
        {
          leg: "complete",
          kind: "kya_buyer",
          verification: "verified",
          subject_ref: "facet:agent:x",
          artifact_sha256: "ab12cd34ef56ab12cd34ef56ab12cd34",
        },
        {
          leg: "create",
          kind: "ucp_platform_rfc9421",
          verification: "verified",
          profile_origin: "https://facet.llc",
          artifact: "sig1=:abc:",
        },
        { leg: "complete", kind: "x402_buyer_erc3009", verification: "verified", artifact: "0xerc3009authorizationlong" },
        { leg: "complete", kind: "boson_seller_offer", verification: "attested", subject_ref: "0xseller" },
      ],
    },
  });
  assertStringIncludes(html, "Authorization trail");
  assertStringIncludes(html, "Buyer KYA (complete)");
  assertStringIncludes(html, "sha256 ab12cd34ef"); // the KYA is shown by hash, never cleartext
  assertStringIncludes(html, "Platform signature (create)");
  assertStringIncludes(html, "facet.llc"); // the platform signature by its authenticated origin
  assertStringIncludes(html, "Payment authorization (complete)");
  assertStringIncludes(html, "Seller offer (complete)");
  assertStringIncludes(html, "attested");
  assertStringIncludes(html, "1 Facet Ed25519 response signature");
  assertStringIncludes(html, "1 counterparty attestation");

  // Absent trail: no section.
  const none = fillReceiptTemplate(TEMPLATE, { jws: makeJws(CLAIMS), pubkeyX: "k", merchant: { name: "m", host: "h" } });
  assert(!none.includes("Authorization trail"), "no trail section without serverTrail");
});

Deno.test("fillReceiptTemplate hides the order button when there is no order url", () => {
  const html = fillReceiptTemplate(TEMPLATE, { jws: makeJws(CLAIMS), pubkeyX: "k", merchant: { name: "m", host: "h" }, orderUrl: "" });
  assertStringIncludes(html, "<a id=orderBtn hidden");
});

Deno.test("fillReceiptTemplate throws when the template is missing a token", () => {
  assertThrows(
    () => fillReceiptTemplate("<div>no tokens here</div>", { jws: makeJws(CLAIMS), pubkeyX: null, merchant: { name: "m", host: "h" } }),
    Error,
    "token",
  );
});

// ---- pubkeyXForKid ------------------------------------------------------------

Deno.test("pubkeyXForKid returns the x for an exact kid match", () => {
  const jwks = { keys: [{ kty: "OKP", crv: "Ed25519", kid: "k1", x: "X1" }, { kty: "OKP", crv: "Ed25519", kid: "k2", x: "X2" }] };
  assertEquals(pubkeyXForKid(jwks, "k2"), "X2");
});

Deno.test("pubkeyXForKid falls back to the sole Ed25519 key when the kid does not match", () => {
  assertEquals(pubkeyXForKid({ keys: [{ kty: "OKP", crv: "Ed25519", kid: "other", x: "ONLY" }] }, "nope"), "ONLY");
});

Deno.test("pubkeyXForKid returns null with no Ed25519 key, or ambiguous among many, or bad input", () => {
  assertEquals(pubkeyXForKid({ keys: [{ kty: "RSA", kid: "k", n: "..." }] }, "k"), null);
  const two = { keys: [{ kty: "OKP", crv: "Ed25519", kid: "a", x: "A" }, { kty: "OKP", crv: "Ed25519", kid: "b", x: "B" }] };
  assertEquals(pubkeyXForKid(two, "z"), null);
  assertEquals(pubkeyXForKid({}, "k"), null);
  assertEquals(pubkeyXForKid(null, "k"), null);
});

Deno.test("merchantNameFromHost title-cases the leading label", () => {
  assertEquals(merchantNameFromHost("pecanandpetal.facet.llc"), "Pecanandpetal");
  assertEquals(merchantNameFromHost(""), "");
});
