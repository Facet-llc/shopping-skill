// Offline unit test for the shopping skill's buyer-side offer validator.
// Exercises assertOfferMatches with no secrets, no wallet, and no network:
// the honest offer must pass, and every price / token / chain tampering must
// be refused. Run:
//   deno test --allow-env --allow-read --allow-net scripts/facet-checkout.test.ts
//
// The import pulls in facet-checkout.ts, whose CLI dispatch is guarded by
// import.meta.main (false here), so importing it runs no command.

import { assert, assertEquals, assertThrows } from "jsr:@std/assert@^1";
import { CompactSign, exportJWK, generateKeyPair } from "npm:jose@5.9.6";
import { privateKeyToAccount } from "npm:viem@2.50.4/accounts";
import {
  getAddress,
  hashTypedData,
  recoverMessageAddress,
  recoverTypedDataAddress,
} from "npm:viem@2.50.4";
import {
  assertDisplayScalarsSane,
  assertMppTerms,
  assertOfferMatches,
  buildProvenance,
  decodeBosonCommit,
  kyaIdentity,
  mppRefusedForEscrow,
  assertX402Terms,
  b64urlToJson,
  buildRefundBody,
  refundAuthMessage,
  buildReorderPlan,
  buildResolveBody,
  buildRevisePlan,
  buildWithdrawTypedData,
  chooseRail,
  type CurrentProduct,
  dedupReceiptIndex,
  errorReason,
  forcedRailIdFor,
  isFirstPartyTarget,
  receiptsDir,
  type ReorderLineItem,
  resolveReorderCandidates,
  verifyReceipt,
} from "./facet-checkout.ts";
import {
  attachShippingEmail,
  getShippingEmailPref,
  isPlausibleEmail,
  readOrderPrefs,
  resolveShippingEmail,
  setShippingEmailPref,
  type ShippingEmailPref,
} from "./order-prefs.ts";

// Canonical Base USDC (checksummed). The validator lowercases both sides, so a
// case difference between the offer and the expectation must NOT matter.
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

// The Base mainnet Boson escrow Diamond, the ERC-3009 recipient the buyer signs
// over. ESCROW is the lowercased form the resolver produces for the expectation;
// ESCROW_OFFER is the checksummed form an honest offer carries. The validator
// must match them case-insensitively.
const ESCROW = "0x59a4c19b55193d5a2ead0065c54af4d516e18cb5";
const ESCROW_OFFER = "0x59A4C19b55193D5a2EAD0065c54af4d516E18Cb5";

// The terms the skill displayed, capped, and will confirm: 5 USDC, 25 USDC cap,
// paying into the Base mainnet Boson escrow Diamond.
function baseExpect() {
  return { priceAtomic: 5_000_000, capAtomic: 25_000_000, usdc: USDC, chainId: 8453, escrow: ESCROW };
}

Deno.test("honest offer passes: amount matches price, USDC on Base, escrow Diamond", () => {
  // Offer carries the checksummed escrow; the expectation holds the lowercased
  // form. Passing proves both the amount/asset/network binding and the
  // case-insensitive escrow-recipient match.
  const offer = { amount: "5000000", asset: USDC, network: "eip155:8453", escrowAddress: ESCROW_OFFER };
  assertOfferMatches(offer, baseExpect());
});

Deno.test("honest offer passes with lowercased asset (case-insensitive match)", () => {
  const offer = {
    amount: "5000000",
    asset: USDC.toLowerCase(),
    network: "eip155:8453",
    escrowAddress: ESCROW_OFFER,
  };
  assertOfferMatches(offer, baseExpect());
});

Deno.test("CRITICAL: inflated offer amount is refused (display price != signed amount)", () => {
  // Terminal shows a 5 USDC price but embeds a 10 USDC amount in the signed offer.
  const offer = { amount: "10000000", asset: USDC, network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "does not match");
});

Deno.test("offer amount over the cap is refused", () => {
  // priceAtomic and amount agree, but both exceed the 25 USDC ceiling.
  const offer = { amount: "30000000", asset: USDC, network: "eip155:8453" };
  const expect = { priceAtomic: 30_000_000, capAtomic: 25_000_000, usdc: USDC, chainId: 8453, escrow: ESCROW };
  assertThrows(() => assertOfferMatches(offer, expect), Error, "exceeds");
});

Deno.test("swapped token (not USDC) is refused", () => {
  const offer = { amount: "5000000", asset: "0x0000000000000000000000000000000000000001", network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not the expected USDC token");
});

Deno.test("wrong chain (eip155:1) is refused", () => {
  const offer = { amount: "5000000", asset: USDC, network: "eip155:1" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "eip155:8453");
});

Deno.test("non-numeric offer amount is refused", () => {
  const offer = { amount: "not-a-number", asset: USDC, network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not a positive number");
});

Deno.test("missing offer amount is refused", () => {
  const offer = { asset: USDC, network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not a positive number");
});

Deno.test("zero offer amount is refused", () => {
  const offer = { amount: "0", asset: USDC, network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not a positive number");
});

Deno.test("scientific-notation amount is refused (Number() reads 5e6, chain would not)", () => {
  // "5e6" parses to 5000000 under Number(), which would have passed a naive
  // numeric check against a 5 USDC price, yet it is not the canonical atomic
  // string the SDK signs. The ^\d+$ guard refuses it before any divergence.
  const offer = { amount: "5e6", asset: USDC, network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not a positive number");
});

Deno.test("hex amount is refused (Number() reads 5000000, not a decimal atomic)", () => {
  const offer = { amount: "0x4c4b40", asset: USDC, network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not a positive number");
});

Deno.test("missing offer network is refused", () => {
  const offer = { amount: "5000000", asset: USDC };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "is not eip155:8453");
});

Deno.test("CRITICAL: attacker escrowAddress is refused (recipient substitution)", () => {
  // Price, token, and chain all look right, but the recipient the buyer would
  // sign the ERC-3009 authorization over is the attacker's address, not the
  // Boson escrow Diamond. This is the fund-theft vector the escrow pin closes.
  const offer = {
    amount: "5000000",
    asset: USDC,
    network: "eip155:8453",
    escrowAddress: "0x000000000000000000000000000000000000dEaD",
  };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not the expected Boson escrow Diamond");
});

Deno.test("missing escrowAddress is refused", () => {
  // An offer with no recipient at all must not settle: the SDK would sign over
  // an empty/undefined recipient. Refuse rather than guess.
  const offer = { amount: "5000000", asset: USDC, network: "eip155:8453" };
  assertThrows(() => assertOfferMatches(offer, baseExpect()), Error, "not the expected Boson escrow Diamond");
});

Deno.test("fails closed when no expected escrow is configured for the chain", () => {
  // Unknown chain with no FACET_BOSON_ESCROW override leaves the resolver with
  // an empty expected escrow. The validator must refuse with a clear message,
  // never compare against "" and silently accept or emit an opaque error.
  const offer = { amount: "5000000", asset: USDC, network: "eip155:8453", escrowAddress: ESCROW_OFFER };
  const expect = { priceAtomic: 5_000_000, capAtomic: 25_000_000, usdc: USDC, chainId: 8453, escrow: "" };
  assertThrows(() => assertOfferMatches(offer, expect), Error, "no expected Boson escrow Diamond is configured");
});

// ---- assertX402Terms: the x402-direct guardrail choke point ----------------
// The x402 sibling of assertOfferMatches, run before the buyer signs an ERC-3009
// TransferWithAuthorization straight to a merchant pay_to. Unlike the Boson escrow
// Diamond, the x402 pay_to is per-merchant and server-advertised, so the guard
// validates its FORM: a hostile Terminal redirecting within the cap is bounded by
// the cap and surfaced in the DRY summary, not pinned to a known value here.
const X402_PAYTO = "0x1111111111111111111111111111111111111111";
function x402Adv() {
  return { payTo: X402_PAYTO, amountAtomic: "5000000", domainName: "USD Coin", asset: USDC, chainId: 8453 };
}
function x402Expect() {
  return { chainId: 8453, domainName: "USD Coin", usdc: USDC, capAtomic: 25_000_000, capUsdc: 25 };
}

Deno.test("x402 honest terms pass and return the atomic price", () => {
  assertEquals(assertX402Terms(x402Adv(), x402Expect()), 5_000_000);
});

Deno.test("x402 terms pass with a lowercased asset (case-insensitive match)", () => {
  assertEquals(assertX402Terms({ ...x402Adv(), asset: USDC.toLowerCase() }, x402Expect()), 5_000_000);
});

Deno.test("x402 malformed pay_to is refused (no valid recipient)", () => {
  assertThrows(() => assertX402Terms({ ...x402Adv(), payTo: "" }, x402Expect()), Error, "no valid pay_to");
  assertThrows(() => assertX402Terms({ ...x402Adv(), payTo: "0x123" }, x402Expect()), Error, "no valid pay_to");
});

Deno.test("x402 wrong chain is refused", () => {
  assertThrows(() => assertX402Terms({ ...x402Adv(), chainId: 1 }, x402Expect()), Error, "expected");
});

Deno.test("x402 wrong EIP-712 domain is refused (testnet domain on mainnet)", () => {
  assertThrows(() => assertX402Terms({ ...x402Adv(), domainName: "USDC" }, x402Expect()), Error, "domain");
});

Deno.test("x402 swapped asset (not USDC) is refused", () => {
  const adv = { ...x402Adv(), asset: "0x0000000000000000000000000000000000000001" };
  assertThrows(() => assertX402Terms(adv, x402Expect()), Error, "not the expected USDC token");
});

Deno.test("CRITICAL: x402 amount over the cap is refused", () => {
  assertThrows(() => assertX402Terms({ ...x402Adv(), amountAtomic: "30000000" }, x402Expect()), Error, "exceeds");
});

Deno.test("x402 non-canonical amount is refused (scientific, hex, fractional, whitespace, sign, zero)", () => {
  // Each parses to a plausible number under Number() but is not the canonical
  // atomic string the ERC-3009 signature binds under BigInt(); the ^\d+$ guard
  // refuses them before any divergence. "0" is caught as non-positive.
  for (const bad of ["5e6", "0x4c4b40", "5.5", " 5000000 ", "+5000000", "0"]) {
    assertThrows(
      () => assertX402Terms({ ...x402Adv(), amountAtomic: bad }, x402Expect()),
      Error,
      "not a positive number",
    );
  }
});

Deno.test("x402 empty amount is refused", () => {
  assertThrows(() => assertX402Terms({ ...x402Adv(), amountAtomic: "" }, x402Expect()), Error, "not a positive number");
});

// ---- assertMppTerms: the MPP (mpp.dev) charge guardrail choke point ----------
// The MPP sibling of assertX402Terms, run on the terms the Terminal put in the 402
// challenge BEFORE mppx builds the evm/charge credential and the wallet signs it.
// MPP is the x402 settlement leg in mpp.dev's envelope: no escrow, the recipient is
// the merchant's own server-derived payout, so the guard validates chain, currency
// and the amount cap, and (on settle) binds the recipient to --confirm-pay-to.
const MPP_RECIPIENT = "0x2222222222222222222222222222222222222222";
function mppChal() {
  return { recipient: MPP_RECIPIENT, amountAtomic: "5000000", currency: USDC, chainId: 8453 };
}
function mppExpect() {
  return { chainId: 8453, usdc: USDC, capAtomic: 25_000_000, capUsdc: 25 };
}

Deno.test("MPP honest terms pass and return the atomic price", () => {
  assertEquals(assertMppTerms(mppChal(), mppExpect()), 5_000_000);
});

Deno.test("MPP terms pass with a lowercased currency (case-insensitive match)", () => {
  assertEquals(assertMppTerms({ ...mppChal(), currency: USDC.toLowerCase() }, mppExpect()), 5_000_000);
});

Deno.test("MPP malformed recipient is refused (no valid recipient)", () => {
  assertThrows(() => assertMppTerms({ ...mppChal(), recipient: "" }, mppExpect()), Error, "no valid recipient");
  assertThrows(() => assertMppTerms({ ...mppChal(), recipient: "0x123" }, mppExpect()), Error, "no valid recipient");
});

Deno.test("MPP wrong chain is refused", () => {
  assertThrows(() => assertMppTerms({ ...mppChal(), chainId: 84532 }, mppExpect()), Error, "expected 8453");
});

Deno.test("MPP swapped currency (not USDC) is refused", () => {
  const chal = { ...mppChal(), currency: "0x0000000000000000000000000000000000000001" };
  assertThrows(() => assertMppTerms(chal, mppExpect()), Error, "not the expected USDC token");
});

Deno.test("CRITICAL: MPP amount over the cap is refused", () => {
  assertThrows(() => assertMppTerms({ ...mppChal(), amountAtomic: "30000000" }, mppExpect()), Error, "exceeds");
});

Deno.test("MPP non-canonical amount is refused (scientific, hex, fractional, whitespace, sign, zero)", () => {
  for (const bad of ["5e6", "0x4c4b40", "5.5", " 5000000 ", "+5000000", "0"]) {
    assertThrows(
      () => assertMppTerms({ ...mppChal(), amountAtomic: bad }, mppExpect()),
      Error,
      "not a positive integer",
    );
  }
});

Deno.test("MPP empty amount is refused", () => {
  assertThrows(() => assertMppTerms({ ...mppChal(), amountAtomic: "" }, mppExpect()), Error, "not a positive integer");
});

Deno.test("CRITICAL: MPP recipient mismatch against --confirm-pay-to is refused (swap-at-settle)", () => {
  // On settle the caller pins the recipient it saw at DRY. A Terminal that returned
  // an honest recipient at DRY and a different one at settle is caught here.
  const expectWithConfirm = { ...mppExpect(), confirmPayTo: "0x3333333333333333333333333333333333333333" };
  assertThrows(() => assertMppTerms(mppChal(), expectWithConfirm), Error, "does not match the confirmed");
});

Deno.test("MPP recipient matches --confirm-pay-to (case-insensitive) passes", () => {
  // The confirmed recipient is the challenge recipient in a different case; the
  // guard lowercases both, so it must pass and return the price.
  const expectWithConfirm = { ...mppExpect(), confirmPayTo: MPP_RECIPIENT.toUpperCase().replace("0X", "0x") };
  assertEquals(assertMppTerms(mppChal(), expectWithConfirm), 5_000_000);
});

// ---- mppRefusedForEscrow: no bypassing escrow ------------------------------
// MPP settles x402-direct (no escrow). If the reservation's merchant advertises the
// Boson escrow handler, an MPP charge must be refused so it cannot stand in for an
// escrow checkout. The signal is the merchant's advertised payment_handlers.
const BOSON_HANDLER = "llc.facet.boson_escrow";
const X402_HANDLER = "llc.facet.x402";

Deno.test("CRITICAL: MPP is refused when the merchant advertises Boson escrow", () => {
  // A Boson-default store (e.g. Pecan & Petal) advertises the escrow handler; MPP
  // would bypass it, so the guard refuses.
  assertEquals(mppRefusedForEscrow({ [BOSON_HANDLER]: [{}], [X402_HANDLER]: [{}] }), true);
  assertEquals(mppRefusedForEscrow({ [BOSON_HANDLER]: [{}] }), true);
});

Deno.test("MPP is allowed on an x402-only merchant (no escrow to bypass)", () => {
  assertEquals(mppRefusedForEscrow({ [X402_HANDLER]: [{}] }), false);
});

Deno.test("mppRefusedForEscrow treats no handlers as x402-only (allow)", () => {
  // An empty or absent handler map means no Boson escrow is advertised, so there is
  // no escrow to bypass. The live guard still fails closed on a session it cannot
  // READ (HTTP != 200); this predicate only classifies a session it DID read.
  assertEquals(mppRefusedForEscrow({}), false);
  assertEquals(mppRefusedForEscrow(undefined), false);
});

// ---- kyaIdentity + buildProvenance: the client-side provenance record ---------
// A synthetic KYA (a JWT: header.payload.signature) whose payload carries the
// identity claims. Only the payload segment is read; the signature is ignored.
function fakeKya(claims: Record<string, unknown>): string {
  const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64url('{"alg":"ES256"}')}.${b64url(JSON.stringify(claims))}.sig`;
}

Deno.test("kyaIdentity decodes aid/issuer/expiry from a KYA and never returns the token", () => {
  const kya = fakeKya({ aid: "agent:abc", iss: "https://issuer.facet.llc", exp: 9999999999, sub: "x" });
  assertEquals(kyaIdentity(kya), {
    aid: "agent:abc",
    issuer: "https://issuer.facet.llc",
    expires: 9999999999,
  });
});

Deno.test("kyaIdentity returns null for a non-JWT, empty, or undefined token", () => {
  assertEquals(kyaIdentity("not-a-jwt"), null);
  assertEquals(kyaIdentity(""), null);
  assertEquals(kyaIdentity(undefined), null);
});

Deno.test("kyaIdentity tolerates missing claims (nulls, not a throw)", () => {
  assertEquals(kyaIdentity(fakeKya({ foo: "bar" })), { aid: null, issuer: null, expires: null });
});

Deno.test("buildProvenance assembles identity, payment, settlement, and a verified response", () => {
  const kya = fakeKya({ aid: "agent:xyz", iss: "https://issuer.facet.llc", exp: 123 });
  const prov = buildProvenance({
    rail: "boson",
    kya,
    payment: { commit_authorization: "0xdeadbeef", escrow: ESCROW },
    checkoutId: "chk_1",
    orderId: "ord_1",
    settlementId: "set_1",
    receipt: { jws: "a.b.c", kid: "key1", provider_jwks: "https://m.facet.llc/.well-known/jwks.json", verified: true },
  }) as Record<string, Record<string, unknown>>;
  assertEquals(prov.identity, { aid: "agent:xyz", issuer: "https://issuer.facet.llc", expires: 123 });
  assertEquals(prov.payment.rail, "boson");
  assertEquals(prov.payment.commit_authorization, "0xdeadbeef");
  assertEquals(prov.settlement, { checkout_id: "chk_1", order_id: "ord_1", settlement_id: "set_1" });
  assertEquals(prov.response.signed_receipt, true);
  assertEquals(prov.response.verified, true);
  assertEquals(prov.response.kid, "key1");
  assert(typeof prov.note === "string" && (prov.note as unknown as string).includes("RFC 9421"));
});

Deno.test("buildProvenance verified is tri-state: null when the receipt was not verified inline", () => {
  // x402 path: the receipt entry is present (signed) but not verified inline, so
  // verified is null, not false, and the buyer can still verify it with `receipt`.
  const unverified = buildProvenance({
    rail: "x402",
    payment: { signature: "0xsig" },
    receipt: { jws: "a.b.c", kid: "k" },
  }) as Record<string, Record<string, unknown>>;
  assertEquals(unverified.response.signed_receipt, true);
  assertEquals(unverified.response.verified, null);

  // No receipt at all (e.g. MPP, or a deferred rail): signed_receipt false, verified null.
  const none = buildProvenance({ rail: "mpp", payment: {}, receipt: null }) as Record<
    string,
    Record<string, unknown>
  >;
  assertEquals(none.response.signed_receipt, false);
  assertEquals(none.response.verified, null);
  assertEquals(none.identity, null);
});

Deno.test("decodeBosonCommit extracts the buyer ERC-3009 auth and the seller signature", () => {
  const commit = btoa(JSON.stringify({
    x402Version: 2,
    scheme: "escrow",
    network: "eip155:84532",
    payload: {
      action: "boson-createOfferAndCommit",
      offerRef: { sellerSig: "0xseller123" },
      tokenAuth: {
        kind: "erc3009",
        data: { from: "0xbuyer", to: "0xescrow", value: "12250000", nonce: "0xnonce", v: 27, r: "0xr", s: "0xs" },
      },
    },
  }));
  assertEquals(decodeBosonCommit(commit), {
    token_authorization: { from: "0xbuyer", to: "0xescrow", value: "12250000", nonce: "0xnonce" },
    buyer_signature: { v: 27, r: "0xr", s: "0xs" },
    seller_signature: "0xseller123",
  });
});

Deno.test("decodeBosonCommit returns null on an undecodable blob", () => {
  assertEquals(decodeBosonCommit("not base64 json !!!"), null);
});

// ---- forcedRailIdFor: FACET_RAIL -> explicit rail_id -----------------------
Deno.test("forcedRailIdFor: x402 forces the direct coin rail on the active network", () => {
  assertEquals(forcedRailIdFor("x402", "base"), "coin/usdc-base");
  assertEquals(forcedRailIdFor("X402", "base"), "coin/usdc-base");
});

Deno.test("forcedRailIdFor: boson forces escrow", () => {
  assertEquals(forcedRailIdFor("boson", "base"), "coin/boson-escrow");
  assertEquals(forcedRailIdFor("BOSON", "base"), "coin/boson-escrow");
});

Deno.test("forcedRailIdFor: auto and unknown defer to the site default (undefined)", () => {
  assertEquals(forcedRailIdFor("auto", "base"), undefined);
  assertEquals(forcedRailIdFor("", "base"), undefined);
  assertEquals(forcedRailIdFor("stripe", "base"), undefined);
});

// ---- chooseRail: OMS-default rail precedence. Regression guard for the defect
// that settled a Boson-default WooCommerce store (P&P) x402-direct in auto mode,
// bypassing escrow and buyer protection. ----
const X402_ID = "llc.facet.x402";
const BOSON_ID = "llc.facet.boson_escrow";

Deno.test("CRITICAL: chooseRail auto honors a Boson default_rail even when x402 is also offered", () => {
  // The exact defect: a Woo store advertises BOTH rails with default_rail=boson.
  // auto must settle boson (escrow), never silently downgrade to x402-direct.
  assertEquals(chooseRail("auto", BOSON_ID, true, true), "boson");
});

Deno.test("chooseRail auto honors an x402 default_rail (Shopify-style)", () => {
  assertEquals(chooseRail("auto", X402_ID, true, true), "x402");
});

Deno.test("chooseRail FACET_RAIL forces the rail over the merchant default", () => {
  assertEquals(chooseRail("x402", BOSON_ID, true, true), "x402");
  assertEquals(chooseRail("boson", X402_ID, true, true), "boson");
  assertEquals(chooseRail("X402", BOSON_ID, true, true), "x402"); // case-insensitive
});

Deno.test("chooseRail a forced rail the store does not offer is refused (undefined)", () => {
  assertEquals(chooseRail("x402", BOSON_ID, false, true), undefined);
  assertEquals(chooseRail("boson", X402_ID, true, false), undefined);
});

Deno.test("chooseRail auto with no default_rail prefers escrow (buyer protection)", () => {
  assertEquals(chooseRail("auto", undefined, true, true), "boson");
});

Deno.test("chooseRail auto on a single-rail store settles that rail", () => {
  assertEquals(chooseRail("auto", undefined, true, false), "x402");
  assertEquals(chooseRail("auto", undefined, false, true), "boson");
  assertEquals(chooseRail("auto", BOSON_ID, true, false), "x402"); // default names boson but only x402 offered
});

Deno.test("chooseRail with no rail advertised is undefined", () => {
  assertEquals(chooseRail("auto", undefined, false, false), undefined);
});

// ---- errorReason: the nested-error-parse fix -------------------------------
// The Terminal wraps auth failures as { error: { code, message } }. The reason
// the callers key on ("signature_missing") lives in error.message, and error is
// an OBJECT, so the old String(j.error) yielded "[object Object]" and the
// co-signature detection never fired. These lock the shape handling.

Deno.test("errorReason: nested UNAUTHORIZED reads error.message (the bug-fix case)", () => {
  const body = JSON.stringify({ error: { code: "UNAUTHORIZED", message: "signature_missing", retryable: false } });
  assertEquals(errorReason(body), "signature_missing");
  // The detection the callers run must now fire on this shape.
  assertEquals(/signature/i.test(errorReason(body)), true);
});

Deno.test("errorReason: nested error with only a code falls back to error.code", () => {
  assertEquals(errorReason(JSON.stringify({ error: { code: "FORBIDDEN" } })), "FORBIDDEN");
});

Deno.test("errorReason: flat string error is read directly", () => {
  assertEquals(errorReason(JSON.stringify({ error: "boom" })), "boom");
});

Deno.test("errorReason: flat top-level code is read", () => {
  assertEquals(errorReason(JSON.stringify({ code: "NOT_FOUND" })), "NOT_FOUND");
});

Deno.test("errorReason: non-JSON body yields empty string, never throws", () => {
  assertEquals(errorReason("<html>502 Bad Gateway</html>"), "");
  assertEquals(errorReason(""), "");
});

// ---- isFirstPartyTarget: origination routing gate --------------------------
// With FACET_PLATFORM_ORIGINATION_SUFFIXES unset, the default suffix is
// .facet.llc: Facet-hosted merchant terminals route through the platform
// origination surface, anything else checks out buyer-direct. Match is
// case-folded, and a look-alike host that does not truly end in .facet.llc
// must not be treated as first-party.

Deno.test("isFirstPartyTarget: a Facet merchant subdomain is first-party", () => {
  assertEquals(isFirstPartyTarget("https://store.facet.llc"), true);
  assertEquals(isFirstPartyTarget("https://api.facet.llc"), true);
});

Deno.test("isFirstPartyTarget: match is case-insensitive", () => {
  assertEquals(isFirstPartyTarget("https://Store.Facet.LLC"), true);
});

Deno.test("isFirstPartyTarget: a non-Facet or look-alike host is not first-party", () => {
  assertEquals(isFirstPartyTarget("https://shop.example.com"), false);
  assertEquals(isFirstPartyTarget("https://facet.llc.evil.com"), false);
});

// ---- assertDisplayScalarsSane: the display-scalar DoS fix -------------------
// The skill reads the checkout's sibling display scalars (price_atomic,
// chain_id) before it sees the seller-signed offer. price_atomic feeds
// BigInt(priceAtomic) downstream, and BigInt() throws an uncaught RangeError on
// any non-integer form, which would break the one-JSON-object stdout contract.
// The validator refuses anything that is not a canonical positive-integer
// decimal string, so the throw is a structured refusal, never a stack trace.

Deno.test("display scalars: honest string scalars pass and are returned", () => {
  const got = assertDisplayScalarsSane({ price_atomic: "5000000", chain_id: "8453" });
  assertEquals(got, { priceAtomic: 5_000_000, chainId: 8453 });
});

Deno.test("display scalars: honest numeric scalars pass (String() canonicalizes)", () => {
  // A merchant may serialize these as JSON numbers rather than strings. Both
  // forms are canonical: String(5000000) matches the same integer regex.
  const got = assertDisplayScalarsSane({ price_atomic: 5_000_000, chain_id: 8453 });
  assertEquals(got, { priceAtomic: 5_000_000, chainId: 8453 });
});

Deno.test("display scalars: fractional price is refused before BigInt()", () => {
  // "5.5" is finite under Number() and would clear a naive (0, cap] check, then
  // throw an uncaught RangeError at BigInt(5.5). Refuse it here instead.
  assertThrows(
    () => assertDisplayScalarsSane({ price_atomic: "5.5", chain_id: "8453" }),
    Error,
    "canonical atomic integer",
  );
});

Deno.test("display scalars: scientific-notation price is refused", () => {
  assertThrows(
    () => assertDisplayScalarsSane({ price_atomic: "5e6", chain_id: "8453" }),
    Error,
    "canonical atomic integer",
  );
});

Deno.test("display scalars: hex price is refused", () => {
  assertThrows(
    () => assertDisplayScalarsSane({ price_atomic: "0x4c4b40", chain_id: "8453" }),
    Error,
    "canonical atomic integer",
  );
});

Deno.test("display scalars: missing price is refused", () => {
  assertThrows(
    () => assertDisplayScalarsSane({ chain_id: "8453" }),
    Error,
    "canonical atomic integer",
  );
});

Deno.test("display scalars: zero price is refused as non-positive", () => {
  assertThrows(
    () => assertDisplayScalarsSane({ price_atomic: "0", chain_id: "8453" }),
    Error,
    "positive safe integer",
  );
});

Deno.test("display scalars: oversized price is refused as unsafe integer", () => {
  // All digits, so it clears the regex, but Number() cannot hold it as a safe
  // integer. Refuse rather than silently lose precision.
  assertThrows(
    () => assertDisplayScalarsSane({ price_atomic: "99999999999999999999", chain_id: "8453" }),
    Error,
    "positive safe integer",
  );
});

Deno.test("display scalars: fractional chain_id is refused", () => {
  assertThrows(
    () => assertDisplayScalarsSane({ price_atomic: "5000000", chain_id: "8453.5" }),
    Error,
    "canonical integer",
  );
});

Deno.test("display scalars: missing chain_id is refused", () => {
  assertThrows(
    () => assertDisplayScalarsSane({ price_atomic: "5000000" }),
    Error,
    "canonical integer",
  );
});

// ---- reorder: candidate resolution + the no-auto-buy handoff ----------------
// resolveReorderCandidates joins each past order line item to its CURRENT price
// and availability (from an injected get_product resolver), and buildReorderPlan
// turns the available ones into the buy handoff. Exercised offline with a fake
// resolver: no wallet, no secrets, no network. The three properties under test:
// candidates carry the CURRENT price (not the price paid then), an unavailable
// SKU is skipped rather than fatal, and the purchase is routed to buy's
// confirm-then-settle path, never auto-bought.

// A past order line: one unit bought at 5 USDC, quantity two.
function pastLine(): ReorderLineItem {
  return { product_id: "SKU-1", qty: 2, unit_price: 5 };
}

Deno.test("reorder: a candidate carries the CURRENT price, not the price paid then", async () => {
  // The SKU is still sold, but its price rose from 5 (paid then) to 6.5 (now).
  // The candidate must surface the CURRENT 6.5, flag the change, and keep the
  // original for reference. This proves reorder re-prices against get_product
  // rather than replaying the historical unit_price.
  const getCurrent = (_id: string): Promise<CurrentProduct> =>
    Promise.resolve({ found: true, price: 6.5, currency: "USD", in_stock: true });
  const [c] = await resolveReorderCandidates([pastLine()], getCurrent);
  assertEquals(c.available, true);
  assertEquals(c.current_price, 6.5);
  assertEquals(c.original_unit_price, 5);
  assertEquals(c.price_changed, true);
  assertEquals(c.qty, 2);
});

Deno.test("reorder: an unavailable SKU is skipped, not fatal; the rest still resolve", async () => {
  // Two past items: one SKU is gone (get_product would 404, modeled as
  // found:false), the other is still sold. The gone SKU must resolve to an
  // unavailable candidate with a reason and must NOT throw, so one dead SKU can
  // never fail the whole reorder. The live SKU resolves normally.
  const lines: ReorderLineItem[] = [
    { product_id: "GONE", qty: 1, unit_price: 3 },
    { product_id: "SKU-2", qty: 4, unit_price: 4 },
  ];
  const getCurrent = (id: string): Promise<CurrentProduct> =>
    id === "GONE"
      ? Promise.resolve({ found: false })
      : Promise.resolve({ found: true, price: 4, currency: "USD", in_stock: true });
  const candidates = await resolveReorderCandidates(lines, getCurrent);
  const gone = candidates.find((c) => c.product_id === "GONE");
  const live = candidates.find((c) => c.product_id === "SKU-2");
  assertEquals(gone?.available, false);
  assertEquals(gone?.reason, "not_found");
  assertEquals(live?.available, true);
  // The plan carries only the available SKU; the gone one is dropped, never bought.
  assertEquals(buildReorderPlan(candidates).items, [{ id: "SKU-2", qty: 4 }]);
});

Deno.test("reorder: an out-of-stock SKU is unavailable and skipped", async () => {
  // The SKU still exists (found:true) but has no inventory (in_stock:false). It
  // must be surfaced as unavailable with the out_of_stock reason and excluded
  // from the buy plan, not errored.
  const getCurrent = (_id: string): Promise<CurrentProduct> =>
    Promise.resolve({ found: true, price: 9, currency: "USD", in_stock: false });
  const [c] = await resolveReorderCandidates([pastLine()], getCurrent);
  assertEquals(c.available, false);
  assertEquals(c.reason, "out_of_stock");
  assertEquals(buildReorderPlan([c]).items, []);
});

Deno.test("reorder: a get_product lookup that throws does not fail the whole reorder", async () => {
  // A transient error on one SKU (the resolver throws) is caught and treated as
  // "cannot confirm availability": that SKU is skipped, the others still resolve.
  const lines: ReorderLineItem[] = [
    { product_id: "BOOM", qty: 1, unit_price: 2 },
    { product_id: "SKU-3", qty: 1, unit_price: 7 },
  ];
  const getCurrent = (id: string): Promise<CurrentProduct> => {
    if (id === "BOOM") throw new Error("network blip");
    return Promise.resolve({ found: true, price: 7, currency: "USD", in_stock: true });
  };
  const candidates = await resolveReorderCandidates(lines, getCurrent);
  assertEquals(candidates.find((c) => c.product_id === "BOOM")?.available, false);
  assertEquals(candidates.find((c) => c.product_id === "SKU-3")?.available, true);
  assertEquals(buildReorderPlan(candidates).items, [{ id: "SKU-3", qty: 1 }]);
});

Deno.test("reorder: the plan routes through confirm-then-settle, never auto-buys", async () => {
  // The whole no-auto-buy invariant, made explicit. buildReorderPlan settles
  // nothing and requires the DRY-then-confirm step: the available items are
  // handed to the existing buy flow, which quotes DRY, waits for an explicit
  // confirmation, and only then settles. Reorder itself moves no money.
  const lines: ReorderLineItem[] = [
    { product_id: "SKU-A", qty: 1, unit_price: 5 },
    { product_id: "SKU-GONE", qty: 1, unit_price: 5 },
  ];
  const getCurrent = (id: string): Promise<CurrentProduct> =>
    id === "SKU-GONE"
      ? Promise.resolve({ found: false })
      : Promise.resolve({ found: true, price: 5, currency: "USD", in_stock: true });
  const plan = buildReorderPlan(await resolveReorderCandidates(lines, getCurrent));
  // Only the available SKU is in the cart; nothing settles here.
  assertEquals(plan.items, [{ id: "SKU-A", qty: 1 }]);
  assertEquals(plan.settles, false);
  assertEquals(plan.requires_dry_then_confirm, true);
});

// ---- refund + resolve body builders (partial refunds, the resolveDispute split) ----
// Offline: the pure body assembly for a refund request and a resolve submission. No
// wallet, secret, or network.

Deno.test("buildRefundBody: a null selection is a whole-order request (no line items)", () => {
  const body = buildRefundBody("ord-1", "changed my mind", null);
  assertEquals(body, { order_id: "ord-1", reason: "changed my mind" });
  // The refund_line_items key is ABSENT (not an empty array), which is what tells the
  // server to reverse the whole order rather than a zero-line partial.
  assert(!("refund_line_items" in body), "a whole-order refund must omit refund_line_items");
});

Deno.test("buildRefundBody: a selection maps cart {id, qty} to the server {product_id, qty}", () => {
  const body = buildRefundBody("ord-1", "arrived wilted", [
    { id: "HCF-BDAY", qty: 1 },
    { id: "HCF-CARD", qty: 2 },
  ]);
  assertEquals(body, {
    order_id: "ord-1",
    reason: "arrived wilted",
    refund_line_items: [
      { product_id: "HCF-BDAY", qty: 1 },
      { product_id: "HCF-CARD", qty: 2 },
    ],
  });
});

Deno.test("buildResolveBody: carries only the signed payload, never the split", () => {
  const body = buildResolveBody("42", "0xBUYERsignedResolve");
  // The buyer percent and seller sig are NOT in the body: the Terminal re-derives them
  // from the stored offer, so the buyer cannot smuggle a different split through here.
  assertEquals(body, {
    exchange_id: "42",
    action: "resolve",
    signed_payload: "0xBUYERsignedResolve",
  });
  assert(!("buyer_percent_bps" in body), "the split bps must not travel in the resolve body");
  assert(!("seller_sig" in body), "the seller sig must not travel in the resolve body");
});

// ---- refund buyer_auth attestation (autonomous dual-key refund request) ----
// Offline: the challenge wire format must match the Terminal byte-for-byte, and a
// genuine wallet signature over it must recover to that wallet (so the Terminal
// accepts it). No network, no secrets beyond a fixed test key.

Deno.test("refundAuthMessage: matches the exact Terminal refund-request challenge", () => {
  assertEquals(
    refundAuthMessage("ord-1", "0xAbC0000000000000000000000000000000000001", 1_750_000_000, "n1"),
    "Facet refund request\norder: ord-1\nwallet: 0xAbC0000000000000000000000000000000000001\n" +
      "issued_at: 1750000000\nnonce: n1",
  );
});

Deno.test("refundAuthMessage: a wallet's EIP-191 signature over it recovers to that wallet", async () => {
  const account = privateKeyToAccount(`0x${"a7".repeat(32)}` as `0x${string}`);
  const message = refundAuthMessage("ord-9", account.address, 1_750_000_000, "nonce-9");
  const signature = await account.signMessage({ message });
  // The Terminal recovers the signer from this exact message; it must be the wallet,
  // so the autonomous refund proof verifies against the KYA's payer_wallet.
  const recovered = await recoverMessageAddress({ message, signature });
  assertEquals(getAddress(recovered), account.address);
});

// ---- throwaway shipping-email preference (ask once, store, reuse) ----------
// Offline: the preference store round-trips, `buy`'s order_attributes.contact_email
// attach honors the stored choice, a malformed address is rejected, and a second
// buy re-reads the same stored address with no re-ask. No wallet, secret, or
// network: the store takes an explicit temp file and attachShippingEmail is the
// exact pure call `buy` makes to shape the UCP complete body.

Deno.test("order-prefs: opt-in round-trips (store an address, read it back)", () => {
  const dir = Deno.makeTempDirSync({ prefix: "facet-order-prefs-test-" });
  const file = `${dir}/order-prefs.json`;
  try {
    // Never asked yet: no file, so the preference reads back as null ("unset").
    assertEquals(getShippingEmailPref(file), null);
    setShippingEmailPref({ optedIn: true, address: "throwaway@relay.example" }, file);
    assertEquals(getShippingEmailPref(file), { optedIn: true, address: "throwaway@relay.example" });
    // The on-disk shape is exactly { shippingEmail: { optedIn, address } }.
    assertEquals(readOrderPrefs(file), {
      shippingEmail: { optedIn: true, address: "throwaway@relay.example" },
    });
  } finally {
    Deno.removeSync(dir, { recursive: true });
  }
});

Deno.test("order-prefs: opt-out round-trips (--none stores optedIn=false so we never ask again)", () => {
  const dir = Deno.makeTempDirSync({ prefix: "facet-order-prefs-test-" });
  const file = `${dir}/order-prefs.json`;
  try {
    setShippingEmailPref({ optedIn: false, address: null }, file);
    const pref = getShippingEmailPref(file);
    // Not null: the buyer WAS asked and declined. optedIn=false stops the re-ask.
    assertEquals(pref, { optedIn: false, address: null });
    assertEquals(pref === null, false);
  } finally {
    Deno.removeSync(dir, { recursive: true });
  }
});

Deno.test("order-prefs: an absent file is 'unset' (never asked)", () => {
  const dir = Deno.makeTempDirSync({ prefix: "facet-order-prefs-test-" });
  const file = `${dir}/does-not-exist.json`;
  try {
    assertEquals(getShippingEmailPref(file), null);
    assertEquals(readOrderPrefs(file), {});
  } finally {
    Deno.removeSync(dir, { recursive: true });
  }
});

Deno.test("buy: a stored opted-in address puts order_attributes.contact_email on the complete body", () => {
  // attachShippingEmail is the exact call buy makes to shape the complete body's
  // order_attributes. An opted-in stored preference attaches the address under
  // the pinned field name `contact_email` and signals opted_in.
  const oa: Record<string, string> = { gift_message: "Happy birthday" };
  const signal = attachShippingEmail(oa, null, { optedIn: true, address: "buyer@relay.example" });
  assertEquals(oa.contact_email, "buyer@relay.example");
  assertEquals(signal, "opted_in");
});

Deno.test("buy: opted-out or unset puts NO email on the complete body", () => {
  // Opted out: nothing attached, signal opted_out (do not ask again).
  const optedOut: Record<string, string> = {};
  assertEquals(attachShippingEmail(optedOut, null, { optedIn: false, address: null }), "opted_out");
  assertEquals(optedOut.contact_email, undefined);
  // Never asked: nothing attached, signal unset (agent should ask before settling).
  const unset: Record<string, string> = {};
  assertEquals(attachShippingEmail(unset, null, null), "unset");
  assertEquals(unset.contact_email, undefined);
});

Deno.test("buy: --shipping-email overrides one purchase without changing the stored default", () => {
  // A one-shot override attaches its address and signals "override"; because it
  // never calls setShippingEmailPref, the stored default is untouched.
  const oa: Record<string, string> = {};
  const stored: ShippingEmailPref = { optedIn: false, address: null };
  const signal = attachShippingEmail(oa, "oneshot@relay.example", stored);
  assertEquals(oa.contact_email, "oneshot@relay.example");
  assertEquals(signal, "override");
  // The override path did not mutate the stored preference object.
  assertEquals(stored, { optedIn: false, address: null });
});

Deno.test("resolve: opted-in with a junk stored address falls back to 'unset' so the agent re-asks", () => {
  // Defensive: a corrupted stored address must not attach; treat it as unset.
  assertEquals(resolveShippingEmail(null, { optedIn: true, address: "notanemail" }), {
    email: null,
    signal: "unset",
  });
});

Deno.test("email-pref set: a malformed email is rejected, a plausible one is accepted", () => {
  // isPlausibleEmail is the gate cmdEmailPref and buy's --shipping-email use to
  // reject junk before it is stored or attached.
  for (const bad of ["notanemail", "a@b", "a b@c.com", "@no-local.com", "no-domain@", "a@b..c", ""]) {
    assertEquals(isPlausibleEmail(bad), false);
  }
  assertEquals(isPlausibleEmail("   "), false); // whitespace-only trims to empty
  for (const good of ["throwaway@relay.example", "a.b+tag@sub.domain.co", "x@y.io"]) {
    assertEquals(isPlausibleEmail(good), true);
  }
});

Deno.test("reuse: a second buy with no flag re-reads the SAME stored address (no re-ask)", () => {
  const dir = Deno.makeTempDirSync({ prefix: "facet-order-prefs-test-" });
  const file = `${dir}/order-prefs.json`;
  try {
    // The buyer opted in once.
    setShippingEmailPref({ optedIn: true, address: "reuse@relay.example" }, file);
    // First buy: reads the stored preference and attaches it.
    const firstOA: Record<string, string> = {};
    const firstSignal = attachShippingEmail(firstOA, null, getShippingEmailPref(file));
    // A later buy, no --shipping-email flag: re-reads the SAME stored preference.
    const secondOA: Record<string, string> = {};
    const secondSignal = attachShippingEmail(secondOA, null, getShippingEmailPref(file));
    assertEquals(firstOA.contact_email, "reuse@relay.example");
    assertEquals(secondOA.contact_email, "reuse@relay.example");
    assertEquals(firstSignal, "opted_in");
    assertEquals(secondSignal, "opted_in");
    // The store was never rewritten between reads: still the one stored address.
    assertEquals(getShippingEmailPref(file), { optedIn: true, address: "reuse@relay.example" });
  } finally {
    Deno.removeSync(dir, { recursive: true });
  }
});

// ---- withdraw: the Boson MetaTxFund EIP-712 recipe -------------------------
// These pin the exact structured data the buyer signs for a gasless withdrawFunds,
// replicated from @bosonprotocol/core-sdk@1.48.0 (meta-tx/handler.js
// signMetaTxWithdrawFunds + utils/signature.js prepareDataSignatureParameters). No
// secret and no network: a throwaway key signs a fixed message and must recover to
// its own address, and the domain/types/message must match the source byte for byte.

// A deterministic throwaway key (test-only; not a real wallet, holds nothing).
const WD_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const DIAMOND_8453 = "0x59A4C19b55193D5a2EAD0065c54af4d516E18Cb5"; // Base mainnet Boson Diamond
const USDC_8453 = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

Deno.test("withdraw EIP-712: domain binds the chain via salt, NOT a chainId field", () => {
  const td = buildWithdrawTypedData({
    diamond: DIAMOND_8453,
    chainId: 8453,
    from: "0x0000000000000000000000000000000000000001",
    entityId: 17n,
    token: USDC_8453,
    amount: 1_000_000n,
    nonce: 42n,
  });
  // Boson's domain: name/version/verifyingContract/salt, and salt is the chainId
  // left-padded to bytes32 (8453 = 0x2105). There must be NO chainId field, or the
  // EIP712Domain viem derives would differ from Boson's and the digest would not match.
  assertEquals(td.domain.name, "Boson Protocol");
  assertEquals(td.domain.version, "V2");
  assertEquals(td.domain.verifyingContract, DIAMOND_8453);
  assertEquals(
    td.domain.salt,
    "0x0000000000000000000000000000000000000000000000000000000000002105",
  );
  assertEquals("chainId" in td.domain, false);
});

Deno.test("withdraw EIP-712: primaryType MetaTxFund wraps MetaTxFundDetails, message pins the Diamond + function", () => {
  const td = buildWithdrawTypedData({
    diamond: DIAMOND_8453,
    chainId: 8453,
    from: "0x00000000000000000000000000000000000000aB",
    entityId: 17n,
    token: USDC_8453,
    amount: 2_500_000n,
    nonce: 99n,
  });
  assertEquals(td.primaryType, "MetaTxFund");
  assertEquals(td.types.MetaTxFund, [
    { name: "nonce", type: "uint256" },
    { name: "from", type: "address" },
    { name: "contractAddress", type: "address" },
    { name: "functionName", type: "string" },
    { name: "fundDetails", type: "MetaTxFundDetails" },
  ]);
  assertEquals(td.types.MetaTxFundDetails, [
    { name: "entityId", type: "uint256" },
    { name: "tokenList", type: "address[]" },
    { name: "tokenAmounts", type: "uint256[]" },
  ]);
  // The message carries decimal-string uints (as the SDK does), pins contractAddress
  // to the Diamond, and names the exact Boson function; the relayer re-encodes the
  // SAME (entity, token, amount) calldata, so a mismatch cannot land.
  assertEquals(td.message.nonce, "99");
  assertEquals(td.message.contractAddress, DIAMOND_8453);
  assertEquals(td.message.functionName, "withdrawFunds(uint256,address[],uint256[])");
  assertEquals(td.message.fundDetails, {
    entityId: "17",
    tokenList: [USDC_8453],
    tokenAmounts: ["2500000"],
  });
});

Deno.test("withdraw EIP-712: a signature over the typed data recovers the signer (self-consistent)", async () => {
  const account = privateKeyToAccount(WD_KEY);
  const td = buildWithdrawTypedData({
    diamond: DIAMOND_8453,
    chainId: 8453,
    from: account.address,
    entityId: 17n,
    token: USDC_8453,
    amount: 1_000_000n,
    nonce: 123n,
  });
  const sig = await account.signTypedData(td as Parameters<typeof account.signTypedData>[0]);
  // 65-byte ECDSA signature (r||s||v), the exact bytes the Terminal relays as
  // executeMetaTransaction's _signature.
  assert(/^0x[0-9a-fA-F]{130}$/.test(sig), "expected a 65-byte hex signature");
  const recovered = await recoverTypedDataAddress(
    { ...td, signature: sig } as unknown as Parameters<typeof recoverTypedDataAddress>[0],
  );
  assertEquals(recovered.toLowerCase(), account.address.toLowerCase());
});

Deno.test("withdraw EIP-712: the digest changes when any signed field changes (nonce, amount, entity)", () => {
  const base = {
    diamond: DIAMOND_8453,
    chainId: 8453,
    from: "0x0000000000000000000000000000000000000001",
    entityId: 17n,
    token: USDC_8453,
    amount: 1_000_000n,
    nonce: 42n,
  };
  const h = (o: typeof base) =>
    hashTypedData(buildWithdrawTypedData(o) as Parameters<typeof hashTypedData>[0]);
  const baseHash = h(base);
  // Each mutated field must move the digest, proving it is genuinely bound.
  assert(h({ ...base, nonce: 43n }) !== baseHash, "nonce is not bound");
  assert(h({ ...base, amount: 1_000_001n }) !== baseHash, "amount is not bound");
  assert(h({ ...base, entityId: 18n }) !== baseHash, "entityId is not bound");
  assert(h({ ...base, chainId: 84532 }) !== baseHash, "chain (salt) is not bound");
});

// ---------------------------------------------------------------------------
// Receipt verification: the portable, self-verifying settlement proof.
//
// These sign a fixture receipt with a locally-generated Ed25519 key, publish the
// matching public key as the issuer JWKS via a stubbed fetch, and prove
// verifyReceipt accepts an honest receipt and refuses every tampering: a forged
// issuer, an alg-confusion header, a swapped typ, and a mutated payload. No real
// network, no wallet, no secrets: exactly the offline check a third party runs.
// ---------------------------------------------------------------------------

const RECEIPT_ORIGIN = "https://pecanandpetal.facet.llc";
const RECEIPT_KID = "test-ed25519-1";

const b64url = (o: unknown) =>
  btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function receiptPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: RECEIPT_ORIGIN,
    sub: "aid:facet:agent:test",
    iat: 1_760_000_000,
    jti: "11111111-1111-1111-1111-111111111111",
    settlement: {
      rail: "llc.facet.boson_escrow",
      amount_minor: 5_000_000,
      currency: "USDC",
      settled_at: "2026-08-14T00:00:00.000000+00:00",
      livemode: true,
    },
    chain: { this_hash: "a".repeat(64), prev_hash: null },
    attestations: [],
    ...over,
  };
}

// Mint a compact JWS receipt + the JWKS that verifies it, with a real Ed25519 key.
async function mintFixture(
  opts: { payload?: Record<string, unknown>; typ?: string } = {},
): Promise<{ jws: string; jwks: { keys: unknown[] } }> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = await exportJWK(publicKey);
  const jws = await new CompactSign(
    new TextEncoder().encode(JSON.stringify(opts.payload ?? receiptPayload())),
  )
    .setProtectedHeader({ alg: "EdDSA", typ: opts.typ ?? "facet-receipt+jws", kid: RECEIPT_KID })
    .sign(privateKey);
  return { jws, jwks: { keys: [{ ...jwk, kid: RECEIPT_KID, alg: "EdDSA", use: "sig" }] } };
}

// Run `body` with globalThis.fetch stubbed to serve `jwks` for the JWKS path.
async function withJwks(jwks: { keys: unknown[] }, body: () => Promise<void>): Promise<void> {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.endsWith("/.well-known/jwks.json")) {
      return Promise.resolve(
        new Response(JSON.stringify(jwks), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    }
    return Promise.resolve(new Response("not found", { status: 404 }));
  }) as typeof fetch;
  try {
    await body();
  } finally {
    globalThis.fetch = original;
  }
}

Deno.test("receipt verifies: honest JWS against the issuer JWKS, offline", async () => {
  const { jws, jwks } = await mintFixture();
  await withJwks(jwks, async () => {
    const r = await verifyReceipt({ jws }, RECEIPT_ORIGIN);
    assertEquals(r.verified, true);
    const claims = r.claims as Record<string, unknown>;
    assertEquals(claims.iss, RECEIPT_ORIGIN);
    assertEquals((claims.settlement as Record<string, unknown>).amount_minor, 5_000_000);
  });
});

Deno.test("CRITICAL: a forged issuer is refused before any key fetch", async () => {
  // The receipt claims a different iss than the host the buyer transacted with.
  // This must fail on the iss pin WITHOUT fetching, so a hostile issuer cannot
  // point verification at a JWKS it controls.
  const { jws } = await mintFixture({ payload: receiptPayload({ iss: "https://evil.example" }) });
  let fetched = false;
  const original = globalThis.fetch;
  globalThis.fetch = (() => {
    fetched = true;
    return Promise.resolve(new Response("{}", { status: 200 }));
  }) as typeof fetch;
  try {
    const r = await verifyReceipt({ jws }, RECEIPT_ORIGIN);
    assertEquals(r.verified, false);
    assertEquals(r.reason, "issuer_mismatch");
    assert(!fetched, "must not fetch a JWKS for a receipt whose iss is not the trusted origin");
  } finally {
    globalThis.fetch = original;
  }
});

Deno.test("CRITICAL: a tampered payload fails the signature", async () => {
  const { jws, jwks } = await mintFixture();
  // Swap the payload segment for one claiming 500 USDC, keeping the original
  // signature. The signature no longer covers the bytes, so it must be refused.
  const parts = jws.split(".");
  const forged = `${parts[0]}.${
    b64url(
      receiptPayload({
        settlement: {
          rail: "llc.facet.boson_escrow",
          amount_minor: 500_000_000,
          currency: "USDC",
          settled_at: "2026-08-14T00:00:00.000000+00:00",
          livemode: true,
        },
      }),
    )
  }.${parts[2]}`;
  await withJwks(jwks, async () => {
    const r = await verifyReceipt({ jws: forged }, RECEIPT_ORIGIN);
    assertEquals(r.verified, false);
    assertEquals(r.reason, "bad_signature");
  });
});

Deno.test("an alg-confusion header (not EdDSA) is refused before verification", async () => {
  const jws = `${b64url({ alg: "HS256", typ: "facet-receipt+jws", kid: RECEIPT_KID })}.${
    b64url(receiptPayload())
  }.AAAA`;
  const r = await verifyReceipt({ jws }, RECEIPT_ORIGIN);
  assertEquals(r.verified, false);
  assertEquals(r.reason, "alg_mismatch");
});

Deno.test("a non-receipt typ is refused", async () => {
  const { jws } = await mintFixture({ typ: "JWT" });
  const r = await verifyReceipt({ jws }, RECEIPT_ORIGIN);
  assertEquals(r.verified, false);
  assertEquals(r.reason, "typ_mismatch");
});

Deno.test("a malformed JWS is refused", async () => {
  const r = await verifyReceipt({ jws: "not-a-jws" }, RECEIPT_ORIGIN);
  assertEquals(r.verified, false);
  assertEquals(r.reason, "malformed");
});

Deno.test("b64urlToJson round-trips an object, tolerating missing padding", () => {
  assertEquals(b64urlToJson(b64url({ a: 1, b: "two" })), { a: 1, b: "two" });
});

// ---------------------------------------------------------------------------
// The receipt archive: pure bits (the FACET_RECEIPTS_DIR contract + the index
// dedup). The save/list I/O is exercised live end-to-end; these pin the logic
// offline, with no disk and no --allow-write.
// ---------------------------------------------------------------------------

Deno.test("receiptsDir: FACET_RECEIPTS_DIR overrides and trailing slashes are trimmed", () => {
  const prev = Deno.env.get("FACET_RECEIPTS_DIR");
  try {
    Deno.env.set("FACET_RECEIPTS_DIR", "/tmp/my-receipts///");
    assertEquals(receiptsDir(), "/tmp/my-receipts");
    Deno.env.set("FACET_RECEIPTS_DIR", "   ");
    // A blank override falls back to the HOME default.
    assert(receiptsDir().endsWith("/.facet/receipts"));
  } finally {
    if (prev === undefined) Deno.env.delete("FACET_RECEIPTS_DIR");
    else Deno.env.set("FACET_RECEIPTS_DIR", prev);
  }
});

Deno.test("receiptsDir: defaults to ~/.facet/receipts under HOME", () => {
  const prev = Deno.env.get("FACET_RECEIPTS_DIR");
  Deno.env.delete("FACET_RECEIPTS_DIR");
  try {
    assertEquals(receiptsDir(), `${Deno.env.get("HOME") ?? "."}/.facet/receipts`);
  } finally {
    if (prev !== undefined) Deno.env.set("FACET_RECEIPTS_DIR", prev);
  }
});

Deno.test("dedupReceiptIndex: latest save per order wins, newest first, corrupt lines skipped", () => {
  const raw = [
    JSON.stringify({ order_id: "A", saved_at: "2026-08-14T00:00:00Z", verified: true }),
    "not json",
    JSON.stringify({ order_id: "B", saved_at: "2026-08-15T00:00:00Z", verified: false }),
    // A re-fetch of A appends a newer line; it must replace the older one.
    JSON.stringify({ order_id: "A", saved_at: "2026-08-16T00:00:00Z", verified: false }),
    "",
    JSON.stringify({ missing_order_id: true }),
  ].join("\n");
  const out = dedupReceiptIndex(raw);
  assertEquals(out.length, 2);
  // Newest saved_at first: A's re-fetch (08-16), then B (08-15).
  assertEquals(out[0]!.order_id, "A");
  assertEquals(out[0]!.saved_at, "2026-08-16T00:00:00Z");
  assertEquals(out[0]!.verified, false);
  assertEquals(out[1]!.order_id, "B");
});

Deno.test("dedupReceiptIndex: empty body yields no receipts", () => {
  assertEquals(dedupReceiptIndex(""), []);
  assertEquals(dedupReceiptIndex("\n\n  \n"), []);
});

Deno.test("buildRevisePlan: two-step cancel-and-rebuy, moves no money, embeds the kept cart", () => {
  const plan = buildRevisePlan(
    "https://pecanandpetal.facet.llc",
    "18",
    [{ id: "HCF-BDAY", qty: 1 }],
    "default",
  );
  assertEquals(plan.mode, "REVISE_PLAN");
  assertEquals(plan.settled, false);
  assertEquals(plan.auto_executed, false);
  assertEquals(plan.exchange_id, "18");
  assertEquals(plan.kept_items, [{ id: "HCF-BDAY", qty: 1 }]);
  assertEquals(plan.steps.length, 2);
  // Step 1 cancels the WHOLE order and cashes out (the refund path) on the given exchange.
  assertEquals(plan.steps[0]!.action, "cancel");
  assert(plan.steps[0]!.command.includes("--exchange-id 18"), "cancel targets the exchange");
  assert(
    plan.steps[0]!.command.includes("--withdraw"),
    "cancel cashes the refund back to the wallet",
  );
  assert(plan.steps[0]!.command.includes("--wallet default"), "wallet label threads through");
  // Step 2 re-buys ONLY the kept items, carrying the cart JSON.
  assertEquals(plan.steps[1]!.action, "buy");
  assert(
    plan.steps[1]!.command.includes('[{"id":"HCF-BDAY","qty":1}]'),
    "rebuy carries the kept cart",
  );
});

Deno.test("buildRevisePlan: omits the wallet flag when no label is given", () => {
  const plan = buildRevisePlan("https://x.facet.llc", "7", [{ id: "A", qty: 2 }]);
  assert(!plan.steps[0]!.command.includes("--wallet"), "no wallet flag without a label");
  assert(plan.steps[1]!.command.includes('[{"id":"A","qty":2}]'), "rebuy carries the cart");
});
