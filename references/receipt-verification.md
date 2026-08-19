# The settlement receipt: verifying the proof

Every settled purchase on a Facet Terminal leaves a signed receipt on the Facet
ledger. This document explains what that receipt is, what it attests, and exactly
how to verify it, both with the skill (`verifyReceipt`) and independently with any
JOSE library. It is written to be reproducible by a third party who never touched
this skill.

## Why the receipt exists

Facet already signs every response and hash-chains every settlement internally. But
an internal signature is only useful to Facet: to trust a Facet-signed header a
third party would have to ask Facet. The receipt turns that internal chain into an
artifact that circulates. It is a compact Ed25519 JWS (RFC 7515) that verifies
against the issuing Terminal's published JWKS with a stock JOSE library and no call
back to Facet. A receipt you have to phone the issuer to check is a service; one
that verifies on its own is evidence.

## Getting a receipt

The receipt is pull-model, and it is anchored server-side before the checkout
COMPLETE response returns (the ledger append is awaited during response signing),
so a fetch right after a settled buy is race-free.

- `buy --settle` returns it inline under `receipt` (fetched and verified for you).
- `receipt --terminal <url> --order-id <id>` re-fetches and verifies it for any past
  order.

Both call `POST /v1/get_receipt {order_id}` on the buyer's KYA. The Terminal returns
`{ receipt: { format, jws, kid, provider_jwks } }`, where `jws` is the compact JWS.
A deferred-settlement escrow rail may not anchor until a later leg; until then
`get_receipt` answers `404` and the skill reports `available: false` rather than an
error, because a payment that already happened must never read like it failed.

## Re-fetching after the buyer identity expires

A receipt is authorized to the agent identity (`aid`) that made the purchase. The
skill mints a fresh, throwaway `aid` per checkout and caches only the short-lived
KYA, so once that KYA expires the `aid` cannot be reproduced and `get_receipt`
answers `403`. Two things make the receipt durable anyway:

1. `buy --settle` fetches the receipt inline while the KYA is still alive, so the
   buyer holds the self-contained JWS from the moment of purchase. Once held, it
   verifies forever with no further call.
2. To retrieve a past order later, the caller proves control of the order's
   **payer wallet** instead of the expired `aid`. `receipt --order-id <id>` signs a
   canonical challenge with the wallet and re-POSTs `get_receipt` with a
   `wallet_auth` block:

   ```json
   {
     "order_id": "<uuid>",
     "wallet_auth": {
       "wallet": "0x<payer>",
       "issued_at": 1760000000,
       "nonce": "<uuid>",
       "signature": "0x<EIP-191 over the challenge>"
     }
   }
   ```

   The signed message is
   `Facet receipt refetch\norder: <order_id>\nwallet: <wallet>\nissued_at: <issued_at>\nnonce: <nonce>`.
   The Terminal recovers the signer, requires it to equal the order's stored payer
   wallet, enforces a short freshness window, and consumes the nonce single-use, so
   a captured signature cannot be reused for another order or replayed. The wallet
   key never leaves the buyer's process; only the signature crosses the wire. The
   caller still presents any fresh KYA to clear the edge, but the wallet signature
   is the authorization.

## The wire format

The receipt is a standard three-segment compact JWS:
`base64url(header) + "." + base64url(payload) + "." + base64url(signature)`.

Header:

```json
{ "alg": "EdDSA", "typ": "facet-receipt+jws", "kid": "<signing key id>" }
```

Payload (the signed claims):

```json
{
  "iss": "https://<merchant-terminal-host>",
  "sub": "<agent aid that made the purchase>",
  "iat": 1760000000,
  "jti": "<order id, one receipt per order>",
  "settlement": {
    "rail": "llc.facet.boson_escrow",
    "amount_minor": 5000000,
    "currency": "USDC",
    "settled_at": "2026-08-14T00:00:00.000000+00:00",
    "livemode": true
  },
  "chain": { "this_hash": "<hex>", "prev_hash": "<hex or null>" },
  "attestations": [
    { "party": "merchant", "says": "<attestation>", "signed_at": "<iso>" }
  ],
  "split": {
    "goods_minor": 4200000, "tax_minor": 500000,
    "shipping_minor": 300000, "duty_minor": 0, "discount_minor": 0
  }
}
```

Notes on the claims:

- `chain` links the order into Facet's tamper-evident, hash-chained ledger. Each
  money-moving dispatch on an order appends one facet-signed entry; the receipt
  anchors to the newest, so it is a snapshot, not a final word.
- `attestations` are counterparty signatures. The array is empty right after a fresh
  buy and that is NOT a negative signal; merchant and agent countersignatures accrue
  as they are added. Re-fetch with `receipt` to pick them up.
- `split` is present only when Facet actually recorded a reconciling split. Absent
  means unknown, never zero: a receipt claiming `tax_minor: 0` for an order whose tax
  was never recorded would be a signed falsehood, which is worse than a signed gap.

## How to verify (the five checks)

The trust anchor is the host you transacted with, never the receipt itself.

1. Split the JWS into three segments; base64url-decode the header and payload to JSON.
2. Confirm the header `typ` is exactly `facet-receipt+jws` and `alg` is `EdDSA`. The
   signature check below is hard-wired to Ed25519, so refusing any other `alg` keeps
   the header honest and forecloses an alg-confusion consumer that keyed off it.
3. Confirm the signed `iss` equals the exact Terminal origin you bought from. This is
   the pin: a receipt must not be able to nominate a different issuer. The entry's
   `provider_jwks` field sits OUTSIDE the signature and is deliberately ignored.
4. Fetch `<iss>/.well-known/jwks.json` and select the key whose `kid` matches the
   header `kid` (an Ed25519 OKP key).
5. Verify the Ed25519 signature over `base64url(header) + "." + base64url(payload)`.

If all five pass, the receipt is authentic and unaltered, and the claims are exactly
what the merchant Terminal signed.

## Verifying independently (any JOSE library)

The skill's `verifyReceipt` is the reference, but nothing about the receipt is
Facet-specific. A third party reproduces it with stock JOSE. Deno or Node example:

```ts
import { compactVerify, createLocalJWKSet } from "jose";

// `jws` is receipt.jws; `origin` is the Terminal host you transacted with.
const [h, p] = jws.split(".");
const header = JSON.parse(atob(h.replace(/-/g, "+").replace(/_/g, "/")));
const claims = JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));

if (header.typ !== "facet-receipt+jws" || header.alg !== "EdDSA") throw new Error("bad header");
if (claims.iss.replace(/\/+$/, "") !== origin.replace(/\/+$/, "")) throw new Error("issuer mismatch");

const jwks = await (await fetch(`${origin}/.well-known/jwks.json`)).json();
const { payload } = await compactVerify(jws, createLocalJWKSet(jwks));
console.log("verified:", JSON.parse(new TextDecoder().decode(payload)));
```

The same holds in Python (`PyJWT` / `python-jose`), Go (`go-jose`), or the JVM
(`nimbus-jose-jwt`): fetch the JWKS, select by `kid`, verify EdDSA. There is no Facet
call in the loop beyond fetching public keys.

## Threat model, and what each check stops

- Issuer substitution: a receipt that claims a different `iss` fails check 3 before any
  key is fetched, so a hostile issuer cannot point verification at a key set it
  controls. `verifyReceipt` proves this by asserting no JWKS is fetched for a
  mismatched issuer.
- Algorithm confusion: a header advertising `none` or an HMAC alg fails check 2; the
  signature is only ever Ed25519-verified.
- Tampering: any change to the header or payload bytes invalidates the Ed25519
  signature at check 5.
- Self-nominated keys: the entry's `provider_jwks` hint is never used; the key source
  is the origin you already trust.

## Pointers

- Skill verifier: `verifyReceipt` and `fetchReceipt` in `scripts/facet-checkout.ts`.
- Offline conformance tests: the receipt cases in `scripts/facet-checkout.test.ts`
  (honest verify, forged issuer, tampered payload, alg confusion, wrong typ,
  malformed), run with no wallet, no secrets, and no real network.
- Terminal route: `POST /v1/get_receipt {order_id}`, KYA-authenticated, scoped to the
  calling agent and the host-resolved merchant site.
