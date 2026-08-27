# Troubleshooting

The errors this skill can return, what each means, and how to resolve it. Every
`facet_*` tool returns one JSON object; the fields below appear there.

## Contents

- Setup and identity
- Discovery
- Guardrail refusals (the protection working)
- Settlement
- Rails and co-signature

## Setup and identity

**`deno: command not found`.** The helper runtime is missing. Install Deno from
https://deno.com so the MCP server can spawn its helper, then reload the server.

**`no KYA available` / `no trusted KYA for [label] and no <ENV> set to mint one`.**
No usable identity token and no wallet key to mint one. Set `FACET_WALLET_KEY` (or
the wallet's key env) so a wallet-bound KYA can be self-issued, or export a trusted,
wallet-bound `FACET_KYA`. The browse legs self-heal by minting when a key is
available.

**`enrollment failed` / `KYA mint failed`.** The self-serve issuer path did not
complete. Check network reachability to the issuer, confirm the wallet key is valid,
and retry. Repeated failures can be issuer rate-limiting; wait and retry.

**A stale `FACET_KYA` is being ignored.** Expected. A token that is expired, from an
untrusted issuer, or bound to a different wallet is skipped and a fresh wallet-bound
one is minted. Set `FACET_KYA` only to pin a specific trusted identity for the same
address behind the wallet key.

## Discovery

**`facet_discover` returns `facet_enabled: false` or `agents.txt 404`.** The site is
not Facet-enabled. Shop it normally in the browser; do not call the Terminal.

**`the Facet directory is identity-gated; set a valid FACET_KYA first` (HTTP 401,
402, or 403).** The directory needs a trusted, wallet-bound KYA. Ensure the wallet
key is set so one can be minted, then retry. This is not a store rejection.

**`directory needs at least one filter`.** Pass at least one of `query`,
`near` (a `lat,lng`), `capabilities`, `taxonomy`, `min_reputation`, or
`claimed_only` to `facet_directory`.

## Guardrail refusals (the protection working)

These refusals mean the client caught something wrong with the merchant's terms and
declined to sign or settle. Do not try to bypass them.

**`refusing a non-HTTPS Terminal URL`.** Identity and checkout must ride TLS. A
Terminal advertised over plain HTTP is refused. Use the `https://` Terminal.

**`GUARDRAIL: offer amount ... does not match the advertised and confirmed price`.**
The seller-signed offer embedded a different amount than the displayed price. This
is the show-one-price, sign-another attack; the client refused it. Do not settle.

**`GUARDRAIL: offer escrowAddress ... is not the expected Boson escrow Diamond`.**
The recipient the signature would authorize is not the known escrow. This is the
fund-redirection attack; the client refused it.

**`offer asset ... is not the expected USDC token` / `offer network ... is not
eip155:<chain>`.** Token or chain swap; refused.

**`GUARDRAIL: price ... outside (0, cap] cap`.** The price exceeds the per-checkout
cap. Raise `max_usdc` on `facet_buy` only if the cart genuinely needs it and the
user has confirmed. The cap cannot exceed the absolute ceiling.

**`merchant price_atomic ... is not a canonical atomic integer`.** The merchant
returned a malformed price (fractional, hex, scientific, or oversized). Refused
before it could break the client.

**`insufficient funds`.** The wallet balance is below the checkout total. Fund the
wallet address shown, in USDC on the expected network, then re-run.

## Settlement

**`settle refused: --confirm must equal the freshly-advertised price`.** The price
changed between the dry quote and the settle attempt, or the `confirm` value did not
match. Re-run the dry `facet_buy` (no `settle`), show the user the new total, and
settle with the exact `confirm` value it prints.

**`settled: "unconfirmed"` with a "DO NOT retry" warning.** The settle POST was
accepted (HTTP 2xx) but its response body did not parse, so money may already have
moved. Do not retry `facet_buy` with `settle: true`. Verify the order and on-chain
state first, then act on what you find.

## Rails and co-signature

**`no supported payment rail on this checkout`.** The CREATE advertised neither the
x402-direct (`llc.facet.x402`) nor the Boson escrow (`llc.facet.boson_escrow`) handler
this client settles. Ask the merchant to enable one of the two supported rails. This
client is dual-rail: it settles x402-direct (the buyer's ERC-3009 straight to the
merchant `pay_to`, no escrow) and Boson escrow, following whichever handler the CREATE
advertises, or whichever `FACET_RAIL` forces.

**`this store requires a platform co-signature` / `platform_cosignature_required`.**
On CHECKOUT (`facet_buy` with `settle: true`), the store will not settle a buyer-only
checkout. For a first-party (`.facet.llc`) merchant this is handled by routing
through platform origination; for a non-first-party store, a buyer-only client cannot
supply the co-signature, and the client reports this rather than routing around it.
On a REFUND request this no longer applies: the client authorizes the request with a
single-use, order-bound wallet attestation it signs locally, so `facet_refund` opens
the ticket on a dual-auth store with no platform in the loop (see the `facet_refund`
entry in SKILL.md). If you still see this error on a refund, that store's Terminal has
not enabled the autonomous buyer path, and the refund needs the merchant or platform
to act.

**`no supported payment rail on this checkout`.** The checkout advertised no rail
this client can settle. The `advertised_rails` field lists what the merchant
offered.
