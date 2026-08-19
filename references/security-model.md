# Security model

The threat model for the buyer-side shopping client, and every guardrail mapped
to the attack it defends. This is a reference document; the enforced policy and
the disclosure process are in [`../SECURITY.md`](../SECURITY.md).

## Contents

- Trust boundaries
- The non-custodial invariant
- Threat model: a hostile or compromised Terminal
- Guardrail catalog (attack, defense, code)
- Residual risk that is bounded, not eliminated
- Dual authorization and co-signature
- Identity: self-issued, wallet-bound KYA
- Supply chain
- Operational defaults

## Trust boundaries

Four parties, with very different trust:

- **The user's wallet and key.** The root of trust. The key stays on the user's
  machine and signs locally.
- **The assistant.** A semi-trusted orchestrator. It never sees the key; it drives
  the scripts and relays results to the user. It cannot move funds beyond what the
  user confirms and the guardrails permit.
- **The Terminal and the merchant.** Untrusted peers on the network. Every field
  they return is treated as potentially hostile and is validated before it can
  influence a signature or a settlement.
- **The chain.** The source of truth for balances and settlement. USDC balance and
  the escrow recipient are on-chain facts, not merchant claims.

The design assumption that drives every guardrail below: **the Terminal is
untrusted.** It may be a genuine merchant, a compromised one, or an attacker
standing up a lookalike. The client must never let a Terminal turn a display value
into a signature over different terms.

## The non-custodial invariant

- The wallet key is read from the environment, used to sign locally, and never
  transmitted, logged, or persisted. Only signatures leave the process.
- Funds settle on-chain from the user's wallet into the merchant's escrow. No
  Facet server is a custodian.
- No issuer service key exists in this repository. The KYA is minted through the
  public self-serve enroll path, authenticated by the user's own wallet proof.

## Threat model: a hostile or compromised Terminal

The primary adversary is the party on the other end of the checkout. Its goals,
in rough order of severity:

1. Get the user to sign a payment to the attacker's address (fund theft).
2. Get the user to sign for more than they agreed (overcharge).
3. Get the user to sign in the wrong token or on the wrong chain (value swap).
4. Cause a double settlement (double spend).
5. Break the client so a naive retry re-sends an authorization.
6. Downgrade the transport to intercept identity or payment.

Each maps to a guardrail below.

## Guardrail catalog

Each guardrail is enforced in `scripts/facet-checkout.ts` unless noted. The
offer-object checks live in `assertOfferMatches`, which runs before any signature
is produced.

### 1. Show one price, sign a larger amount

The ERC-3009 authorization binds the seller-signed offer object's own `amount`,
not the checkout's sibling display scalar. A hostile Terminal could show a small
`price_atomic` while embedding a larger `amount` in the object the SDK signs.

**Defense.** `assertOfferMatches` requires the offer `amount` to be a canonical
decimal-integer string (`^\d+$`) and to equal the price the user was shown and
confirmed. Scientific notation, hex, fractional, signed, or whitespace-padded
values are all refused, because those parse under `Number()` yet would settle a
different amount on-chain.

### 2. Substitute the recipient (fund theft)

The ERC-3009 signature authorizes a transfer to a recipient. If the Terminal
swaps the escrow address for the attacker's, the amount, token, and chain can all
still look correct while the money goes to the attacker.

**Defense.** The offer `escrowAddress` is pinned to the known Boson escrow Diamond
for the expected chain (a fixed, network-scoped address, not a per-merchant
value). A mismatch, or a missing recipient, is refused. This is the fund-theft
choke point.

### 3. Swap the token

**Defense.** The offer `asset` is pinned to the expected USDC token address
(compared case-insensitively). Any other token is refused.

### 4. Swap the chain

**Defense.** The offer `network` is pinned to `eip155:<expected chain>`. The
sibling display `chain_id` and `network` scalars are also checked against the
expected chain and network before anything is signed.

### 5. Downgrade the transport

Identity and payment must not travel over a channel an attacker can read or
rewrite.

**Defense.** `terminalBase` refuses any Terminal URL that does not resolve to
`https://` (scheme detected case-insensitively so a padded or mixed-case value
cannot slip through). Identity and checkout ride TLS or they do not run.

### 6. Coax a higher spend

**Defense.** A per-checkout cap defaults conservatively and is bounded by an
absolute ceiling that runtime configuration can only tighten, never raise. A
garbage cap value falls back to the pinned default rather than becoming `NaN`
(which would compare false against every limit) or disabling the ceiling. As
defense in depth, the escrow client is also given a `maxAmount` backstop on the
exact field it signs.

### 7. Price drift between quote and settle

**Defense.** Settlement is a separate, explicit step. The `--confirm` value must
equal the freshly advertised price, and that price is bound to the seller-signed
offer `amount` proven equal earlier in the same process. If the price changed
after the dry quote, settlement is refused and the user re-quotes.

### 8. Double settlement after an ambiguous response

If the settle POST returns a 2xx but an unparseable body, money may already have
moved. A generic parse-and-die would read like "nothing happened" and invite a
retry.

**Defense.** That case has its own handler that reports an explicit unconfirmed
terminal state, tells the caller not to retry, and points to on-chain
verification. It is deliberately not the shared die-on-bad-JSON path.

### 9. Stale, untrusted, or forged identity

**Defense.** A KYA is used only when it is unexpired, from a trusted issuer, and
bound to the paying wallet. A token that fails any of these is skipped, and a
fresh wallet-bound one is self-issued. A stale or untrusted `FACET_KYA` never
blocks or misdirects a checkout. See `kyaUsable` in `scripts/kya-provision.ts`.

### 10. Display-scalar denial of service

The client reads `price_atomic` before it sees the signed offer, and feeds it to
`BigInt()`. A fractional or oversized value would throw an uncaught `RangeError`
and break the one-JSON-object output contract.

**Defense.** `assertDisplayScalarsSane` refuses any non-canonical or unsafe
integer form first, turning a would-be crash into a structured refusal.

### 11. Lookalike first-party host

Origination routing treats `.facet.llc` merchants as first-party. A host like
`facet.llc.evil.com` must not qualify.

**Defense.** `isFirstPartyTarget` matches on a true dotted-suffix boundary, not a
substring, and is case-folded. The offline tests assert the lookalike is rejected.

### 12. Hostile or malformed responses

Any peer can return non-JSON (an HTML 502 page), the literal `null`, or a scalar.

**Defense.** Every external response is parsed through `parseJsonObjOrDie`, which
funnels all of those into a clean structured error rather than a stack trace that
would break the output contract.

## Residual risk that is bounded, not eliminated

The escrow-recipient pin binds where the money goes (the shared Boson escrow
Diamond), how much, in which token, on which chain. It does not bind which seller
account inside that shared Diamond the commit routes to: Boson identifies the
seller by an opaque offer blob the SDK forwards verbatim, and the sibling
`seller_id` scalar is display-only. A `seller_id` equality check would therefore
be theater, since a hostile Terminal controls both the blob and the scalar.

The residual is bounded and surfaced instead of hidden:

- **Bounded.** Funds settle into Boson escrow, never to a seller externally-owned
  account. A wrong or non-performing seller is recoverable through the Boson
  cancel, dispute, and refund path, all under the per-checkout USDC cap.
- **Surfaced.** The dry-run summary prints `seller_id`, the escrow address, and the
  asset, so a human sees the routing before confirming.

Stating this residual plainly is deliberate. A model that claims to bind something
it cannot is worse than one that bounds the gap and shows it.

## Dual authorization and co-signature

Some production stores require a co-signature from the shopping platform in
addition to the buyer's identity and payment. A buyer-only client cannot produce
that co-signature.

For a first-party (`.facet.llc`) merchant, the client routes the checkout through
the Facet platform origination surface, which adds the RFC 9421 co-signature and
forwards the buyer KYA verbatim. The buyer still signs its own payment client-side,
so no key or custody reaches the server. For a non-first-party store that requires
a co-signature the buyer cannot supply, the client prices the cart and then reports
plainly that the store will not settle a buyer-only checkout. It does not retry or
route around the rejection.

On the refund REQUEST route, a dual-auth store instead accepts an autonomous buyer
proof, so a buyer-only client can open a refund ticket with no platform in the loop.
The client signs a wallet attestation locally: an EIP-191 message binding the order
id and the paying wallet, with a fresh timestamp and a single-use nonce. Only the
signature leaves the process. The Terminal recovers the signer, requires it to equal
the `payer_wallet` on the buyer's wallet-bound KYA, enforces a short freshness window,
and consumes the nonce so the same attestation cannot be replayed. The attestation
opens the ticket only: it authorizes no amount and moves no funds, and the merchant
still approves before any send-back or split. A store without the autonomous path
enabled rejects the request, and the client reports that rather than routing around
it. This is the refund analogue of the buyer-signed `cancel` and `dispute` meta-txs,
a second independent factor the buyer proves itself, which keeps the money path
dual-auth without a platform co-signature.

## Identity: self-issued, wallet-bound KYA

`kya-provision.ts` mints a wallet-bound KYA with no service key:

1. Generate a fresh P-256 identity key locally and derive its `aid`.
2. Enroll it at the issuer with a proof-of-possession JWS.
3. Authenticate the mint with a self-issued `private_key_jwt` client assertion.
4. Prove control of the paying wallet with an EIP-191 signature over a
   single-use challenge.
5. Receive a KYA bound to that wallet, cached to a mode-600 file, never printed.

The issuer's signing key stays on the server. This client only ever reaches the
public, rate-limited self-serve path, so it can reach nothing an attacker could
not already reach.

## Supply chain

Runtime dependencies are minimal and pinned to exact versions, with the full
graph integrity-locked in `deno.lock`:

- `viem` for wallet signing.
- `@bosonprotocol/x402-client` for the ERC-3009 commit authorization.
- `jose` for the identity JWS and client assertion.

Deno's default-deny permission model applies: the scripts run with only the
`--allow-env`, `--allow-read`, `--allow-net`, and (for the KYA cache) a narrowly
scoped `--allow-write="$HOME/.cache"`. The storefront reader needs only
`--allow-net` and touches no secrets.

## Operational defaults

- Dry-run first: the default `buy` moves nothing.
- One confirmation per settlement: a yes for one purchase is not a yes for the next.
- HTTPS only for identity and checkout.
- A conservative per-checkout cap under an absolute ceiling.
- The key never appears on a command line; the scripts read it from the
  environment only.
