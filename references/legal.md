# Legal, terms, and acceptable use

This document states the terms under which this reference client is provided, the
responsibilities it assumes and does not assume, and how it treats identity and
data. It is not legal advice.

## Provided as a reference implementation, as is

This skill is open-source software licensed under Apache-2.0 (see
[`LICENSE`](LICENSE)). It is provided "as is", without warranty of any kind,
express or implied, including merchantability, fitness for a particular purpose,
and non-infringement. It moves real funds on public blockchains; you run it at
your own risk.

## Non-custodial: you hold your funds and your keys

The client never takes custody of your funds or your keys. Your wallet key is read
from your environment, signs locally inside the process, and never leaves it; only
signatures are transmitted. Funds settle on-chain directly from your wallet into the
merchant's escrow or payout address. No Facet server, and no other party in this
skill, is a custodian at any point. The full statement and the guardrails that
enforce it are in [`SECURITY.md`](SECURITY.md) and
[`references/security-model.md`](references/security-model.md).

## Your responsibility

You are the principal. Each settlement is an explicit, per-purchase authorization
you give. You are responsible for:

- Securing your wallet key and recovery phrase. Losing them loses the funds, and no
  one can recover them for you.
- The purchases you authorize, and paying for them.
- Complying with the laws of your jurisdiction, the merchant's terms of sale, and
  any export, sanctions, tax, or licensing rules that apply to what you buy.

The built-in guardrails (chain and recipient pinning, the per-checkout spend cap,
the prohibited-goods policy) reduce risk. They do not move any of these
responsibilities off you.

## Acceptable use

Use this client only for lawful purchases you are authorized to make. Do not use it
to buy anything prohibited by law in your jurisdiction or by the merchant, and do
not use it to evade sanctions, launder funds, or circumvent a merchant's controls.
The agent-behavior policy in [`references/safety.md`](references/safety.md),
including the prohibited-goods list, applies to every purchase.

## Not professional advice

Nothing produced by this skill is legal, financial, tax, investment, or other
professional advice. Stablecoin payments and on-chain settlement carry risks,
including irreversibility and network fees; assess them yourself or with a qualified
advisor.

## Identity: the credential, precisely

The identity the client presents to a merchant is a wallet-bound Facet KYA: an ES256
(P-256) JSON Web Token, sent as `Authorization: Bearer <KYA>` and, on a money-moving
checkout, also carried inside the signed payment instrument. It is self-issued from
the Facet issuer (`https://issuer.facet.llc` by default, override with
`FACET_ISSUER_URL`) by enrolling a fresh identity key and proving control of the
paying wallet with a single-use, domain-separated signature. No issuer service key
exists in this repository; the token is short-lived and re-minted as needed. A KYA
from an issuer you have not trusted is ignored rather than used.

## Data handling and network egress

The client sends no analytics or telemetry and does not phone home. Exactly which
hosts it contacts, what it stores locally, and what never leaves your machine are
itemized in [`SECURITY.md`](SECURITY.md) under "Network egress and data handling".

## Third-party rails and services

Checkout and settlement ride open, public rails and independent services: the
merchant's Facet Terminal, x402 over HTTP-402 with USDC on Base, Boson escrow, the
UCP checkout, and RFC 9421 request signing. The merchant, the payment networks, the
blockchain, and any escrow contract are independent parties governed by their own
terms. This client is a reference integration over those rails, not a party to your
transaction and not a required intermediary.

## Trademarks

"Facet" is a trademark of Facet, LLC. Other product and company names are the
property of their respective owners; their mention here is nominative and does not
imply endorsement.
