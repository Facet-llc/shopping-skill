# Security policy

This skill signs a payment authorization with the user's wallet key and settles
real USDC on-chain. Treat it with the care that implies, and read this before you
run it.

## The non-custodial invariant

Everything in this skill holds to one rule: **Facet never holds the user's funds
or the user's key.**

- The wallet private key is read from an environment variable, used to sign
  locally inside the Deno process, and is never transmitted, logged, or written
  to disk. Only the resulting signature leaves the process.
- Funds move on-chain directly from the user's wallet into the merchant's escrow.
  No Facet server, and no other third party, is a custodian at any step.
- The identity token is a wallet-bound Facet KYA the user self-issues by proving
  control of the wallet. No issuer service key exists in this repository.

If any change to this code would break that invariant, the change is wrong, not
the invariant.

## Network egress and data handling

The client is transparent about what it contacts and what it stores. It makes
network calls only to:

- **The merchant Terminal you point it at** (the `--terminal` host): discovery,
  quoting, checkout, and settlement.
- **The Facet issuer** (`issuer.facet.llc`, override with `FACET_ISSUER_URL`): to
  self-issue a wallet-bound KYA. No issuer service key is used; the request carries
  the user's own client assertion and a wallet-signed challenge.
- **The Base network RPC**: to read the wallet's USDC balance and to settle on-chain.
- **The merchant storefront**: to read `/.well-known/agents.txt` and, in the
  fallback reader, the public catalog.

It sends no analytics, no telemetry, and no usage beacons; there is no phone-home.
It transmits no private key or recovery phrase (only signatures leave the process),
and no personal data beyond the shipping details the user supplies for the order in
hand. Local state stays on the user's machine: a cached KYA (mode 600, under
`~/.cache/facet`), the optional encrypted wallet keystore (`~/.facet/keys`), the
shipping-email preference, and archived signed receipts (`~/.facet/receipts`).

## Supported versions

The latest release on the default branch is supported. This skill tracks live
protocol surfaces (the Facet Terminal, the issuer, on-chain contracts); older
checkouts may reference endpoints or contract addresses that have moved.

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue, pull
request, or discussion for a suspected vulnerability.

1. Preferred: use GitHub's private vulnerability reporting on this repository
   (the "Report a vulnerability" button under the Security tab).
2. Alternative: email the Facet security contact at `security@facet.llc`.

Please include: the affected file and version, a description of the issue, a
proof-of-concept or reproduction if you have one, and the impact you believe it
has. You will get an acknowledgement, and we will keep you updated as the issue
is triaged and fixed. Please give a reasonable window to remediate before any
public disclosure.

## Scope

In scope for this repository:

- The buyer-side scripts under `scripts/` (the checkout helper, the KYA minter,
  the storefront reader).
- The buyer-side validators and guardrails (offer binding, recipient pin, caps,
  the settle gate).

Out of scope here (report to Facet through the same contact, but these are
server-side and live in other systems):

- The Facet Terminal, the UCP checkout endpoints, and the origination surface.
- The KYA issuer service and its signing keys.
- The edge WAF and the directory.

## What defends the money path

The buyer-side guardrails, and the exact attack each one closes, are documented
in full in [`references/security-model.md`](references/security-model.md). In
short:

- The seller-signed offer is re-validated before any signature: amount, token,
  chain, and escrow recipient are each pinned to what the user was shown and
  confirmed. A hostile Terminal cannot show one price and get the user to sign
  another, or redirect the recipient.
- Identity and checkout ride HTTPS only; a non-HTTPS Terminal URL is refused.
- Settlement is a separate, explicit step. The default `buy` run is a dry quote
  that moves nothing; settling requires a confirm value that equals the freshly
  advertised price, which is bound to the seller-signed amount.
- A per-checkout USDC cap has an absolute ceiling that runtime configuration can
  only tighten, never raise.
- The wallet key stays local; only signatures are sent.

## Operational guidance

- Keep the wallet key in an environment variable or a sourced env file, never on
  a command line and never in a committed file. The `.gitignore` blocks common
  secret patterns as defense in depth.
- Fund the shopping wallet with only what a session needs. The cap bounds a single
  checkout; the wallet balance bounds the blast radius across a session.
- Review the dry-run summary (item, price, escrow recipient, token) before you
  confirm a settlement. One confirmation authorizes one purchase.
