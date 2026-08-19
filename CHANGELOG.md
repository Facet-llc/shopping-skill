# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-18

### Added

- x402-direct buyer settlement, alongside Boson escrow: the client is now dual-rail.
  `buy` follows whichever handler the checkout CREATE advertises: a Boson commit for an
  escrow offer, or, for an x402-direct offer, the buyer's ERC-3009
  TransferWithAuthorization signed locally and settled straight to the merchant's
  `pay_to` (no escrow, no buyer protection). Facet custodies neither funds nor keys on
  either rail. Before signing, a new pure `assertX402Terms` guardrail refuses a bad
  recipient, a wrong chain or EIP-712 domain, a swapped asset, or a non-canonical or
  over-cap amount, mirroring the Boson `assertOfferMatches` choke point, so a hostile
  Terminal cannot redirect or inflate the transfer the buyer signs. The buyer signs
  against a fully client-pinned EIP-712 domain (name, version, chain, USDC address),
  never the advertised one; and because the per-merchant `pay_to` is the one term with no
  authoritative source to pin against, settle requires a matching `--confirm-pay-to` so
  the recipient the user approved at the DRY step is the recipient bound. `FACET_RAIL=x402`
  or `FACET_RAIL=boson` forces a rail; the default `auto` follows the merchant's OMS-keyed
  site default (Shopify x402-direct, WooCommerce Boson escrow). This lets the client
  check out at a Shopify-backed store, which the Boson-only client could not.

- Enterprise-readiness documentation: `references/legal.md` (terms, acceptable use,
  the precise identity credential, non-custodial and not-advice disclaimers), a
  "Network egress and data handling" section in `SECURITY.md` (the exact hosts the
  client contacts, no analytics or telemetry, keys never transmitted), a walletless
  quick-start path in the README, and a corrected repository layout that lists the
  wallet-mint, MCP, safety, and receipt-verification surfaces.

- Guidance for rendering a detailed, shareable receipt view. The receipt (and its
  archived `<order_id>.json`) already carries the full verifiable proof; `SKILL.md`
  now directs the assistant to render it as a checkable view on request, laying out
  the order and money, the signing terminal and the on-chain settlement reference
  (the tx hash / Boson exchange), the tamper-evident chain link, the attestations, and
  the offline JWKS verification verdict, so a buyer can SEE and share the proof instead
  of reading raw JSON. A reversal's `facet-lifecycle+jws` receipt renders the same way.

- `revise` planner for changing a multi-item order before it ships. A Boson escrow
  cannot be partially refunded while committed, so removing one line and keeping the
  rest is a cancel-and-rebuy: `revise --exchange-id <id> --keep '[{"id","qty"}]'`
  returns the two ordered steps (cancel the whole order for a full refund cashed back
  to the wallet, then re-buy only the kept items) and moves NO money on its own, like
  `reorder`. Each leg leaves a signed receipt (the cancel a `facet-lifecycle+jws`, the
  rebuy a settlement receipt), so the whole revision is auditable. A `facet_revise` MCP
  tool wraps it.

- Signed lifecycle (reversal) receipts. A cancel, withdraw, or dispute now fetches,
  verifies, and archives its own signed receipt (a compact Ed25519 JWS with typ
  `facet-lifecycle+jws`, the reversal analogue of the settlement receipt) on the same
  KYA that performed the reversal, and folds it into the command result under
  `receipt`. A new `lifecycle-receipt --kind <cancel|withdraw|dispute|refund>
  ( --exchange-id | --order-id )` subcommand fetches one on demand, and a
  `facet_lifecycle_receipt` MCP tool wraps it. Reversal receipts are saved to the same
  archive as settlement receipts, keyed `lifecycle-<kind>-<handle>.json`. So a
  cancelled order no longer reads as "settled" with only a tx hash: it carries
  portable, JWKS-verifiable proof of the reversal. Owner-scoped at the Terminal (a
  foreign caller is a 404) with no wallet-auth fallback, so the reliable path is the
  inline archive at reversal time.

- Buyer-authorized refund requests on dual-auth stores. `refund` now signs a wallet
  attestation (`buyer_auth`): an EIP-191 message binding the order and the paying wallet,
  single-use and fresh, signed locally so only the signature leaves the process. It lets
  a buyer-only client open a refund ticket on a store that gates the request behind a
  platform co-signature (the autonomous dual-key path), the refund-request analogue of
  the buyer-signed meta-tx on `cancel` / `dispute`. The ticket opens only; no funds move
  until the merchant approves. A single-factor store ignores the attestation.

- Full MCP surface parity with the CLI: `facet_fund` (show a wallet's address and USDC
  balance, or poll until funded with `await_funding`) and `facet_email_pref` (record or
  read the throwaway shipping-email choice with `action` `show` / `set`) join the tool
  table, so every buyer subcommand is now driveable over MCP. The `facet_refund` tool
  description and the `SKILL.md`, `references/troubleshooting.md`, and
  `references/security-model.md` docs now describe the autonomous `buyer_auth` refund
  path, so an agent reading the skill knows a buyer-only refund on a dual-auth store no
  longer needs a platform co-signature. Offline argv tests cover both new tools.

- Partial refunds and buyer-driven split resolution. `refund` now takes a required
  `--reason` (the merchant reviews it) and an optional `--items` selection (a JSON array
  of `{ id, qty }`) that requests a PARTIAL refund of just those lines, with shipping
  retained; omitting `--items` requests the whole order. A new `resolve` subcommand
  completes a Boson partial-refund split after the merchant approves: it signs the buyer
  half of the mutual `resolveDispute` locally and gaslessly and submits it to the dispute
  route, and the Terminal validates the split against the merchant's stored offer so the
  buyer can never alter the percentage or forge the seller half. `resolve --refund-id <id>`
  auto-reads the approved offer from the buyer's own refund ticket (`get_refund`), or the
  offer can be passed explicitly with `--exchange-id --buyer-percent-bps --seller-sig`. The
  MCP surface gains `facet_resolve` and extends `facet_refund` with `reason` + `items`.
  Pure `buildRefundBody` and `buildResolveBody` are exported and unit-tested offline.

- Settlement receipt fetch, verify, and archive: `buy --settle` now fetches the Facet
  ledger's signed receipt for the settled order (`POST /v1/get_receipt`), verifies it
  offline against the merchant Terminal's published JWKS, and archives it, returning it
  under `receipt`. A new `receipt --order-id <id>` subcommand re-fetches and verifies any
  past order's receipt (re-authorizing with the paying wallet, via a locally signed
  challenge, when the original short-lived buyer identity has expired), and a new
  `receipts` subcommand lists the local archive. The receipt is a compact Ed25519 JWS
  (RFC 7515) that verifies against the Terminal's JWKS with a stock JOSE library and no
  call back to Facet: `verifyReceipt` pins the JWKS to the host transacted with, requires
  the signed `iss` to match, ignores the receipt's own `provider_jwks` hint, and refuses a
  wrong `typ`, a non-EdDSA `alg`, a forged issuer, or a tampered payload. Every fetched
  receipt is saved to a durable folder (default `~/.facet/receipts`, override
  `FACET_RECEIPTS_DIR`): one `<order_id>.json` per order plus an `index.jsonl`; saving is
  best-effort and needs `--allow-write` to that folder, so the standard Deno invocation now
  grants `$HOME/.facet` alongside `$HOME/.cache`. Exposed over MCP as `facet_get_receipt`
  and `facet_receipts`. Offline tests cover the honest verify path, each tampering vector,
  the `FACET_RECEIPTS_DIR` contract, and the index dedup. See
  `references/receipt-verification.md`.

- Throwaway shipping-email preference (ask once, store, reuse): the agent asks the
  buyer ONCE, on the first purchase, whether they want shipping-confirmation emails,
  then reuses that choice on every order after without asking again. A new `email-pref`
  subcommand on `scripts/facet-checkout.ts` records it (`email-pref set <address>` to opt
  in, `email-pref set --none` to decline, `email-pref show` to print it), stored as plain,
  non-secret JSON at `~/.cache/facet/order-prefs.json` (never the `~/.facet` keystore).
  When the buyer opted in, `buy` puts the stored throwaway address on
  `order_attributes.contact_email` of the UCP checkout automatically; `--shipping-email <addr>`
  overrides for a single purchase without changing the stored default. Every `buy` result
  carries `shipping_email_pref` (`unset`, `opted_in`, `opted_out`, or `override`) so the
  agent knows when to ask. The email is buyer-provided; a Facet-generated relay alias is a
  follow-up, and the Terminal-side plumbing that threads `order_attributes.contact_email` to the
  merchant order is a separate change. Offline tests cover the preference round-trip, the
  opted-in, opted-out, and unset attach behavior, malformed-email rejection, and reuse on a
  second buy.

- Agent-behavior safety layer: `references/safety.md`, the behavioral contract the
  SKILL.md "Safety rules" summarize, covering external content treated as data,
  prohibited goods, purchase intent and authority, identity and privacy, advice
  limits, and refusals. SKILL.md now points to it.

- Reorder ("buy that again"): a `reorder` subcommand on `scripts/facet-checkout.ts`
  (`reorder --terminal <url> [--order-id <id>] [--limit <n>] [--wallet <label>]`) and a
  matching `facet_reorder` MCP tool. It reads the buyer's own order history
  (owner-scoped to their identity at the Terminal), re-prices each past item against the
  store's CURRENT catalog via `get_product`, and returns the reorder candidates plus a
  buy plan. Pure orchestration of calls that already exist: it settles nothing and buys
  nothing on its own, adds no new money path, and hands the available items to the same
  `buy` flow (DRY quote, explicit confirmation, then `--settle`) as any other checkout.
  A SKU that is gone or out of stock is marked unavailable and skipped, never fatal to
  the reorder. Without `--order-id` it reorders the most recent order; with it, that
  order. Offline tests cover current-price surfacing, the skipped-unavailable path, and
  the no-auto-buy handoff.
- MCP server (`scripts/mcp-server.ts`, stdio transport) that exposes the buyer
  workflow as MCP tools so an autonomous agent can drive Facet shopping over MCP:
  `facet_wallet_list`, `facet_wallet_new`, `facet_provision`, `facet_discover`,
  `facet_directory`, `facet_search`, `facet_product`, `facet_buy`,
  `facet_browse_storefront`, and the lifecycle tools `facet_redeem`,
  `facet_cancel`, `facet_dispute`, `facet_refund`. It is a thin wrapper: each tool
  spawns the matching `facet-checkout.ts` or `browse-storefront.ts` subcommand and
  relays the one JSON object it prints, reimplementing no checkout, wallet, or KYA
  logic. Each child runs with `stderr: "null"`, so the one-time recovery phrase
  `wallet new` writes to stderr is discarded and never enters a tool result; a tool
  result carries an address or a status, never a secret. Run it with `deno task mcp`.
  Implemented with no new dependency (a minimal stdio JSON-RPC server: initialize,
  tools/list, tools/call).
- Gift message and delivery date on agent checkout: `buy` now accepts
  `--gift-message`, `--delivery-date` (ISO YYYY-MM-DD), and `--occasion`, carried in
  the UCP checkout complete as `order_attributes`. On a WooCommerce store the message
  becomes the order note and the date becomes the requested delivery date.
  Display-only, never priced, and a malformed value never blocks settlement.
  (Requires the matching Terminal change that threads `order_attributes` through the
  UCP complete.)
- Post-purchase lifecycle subcommands: `redeem` (confirm receipt, release escrow to
  the seller), `cancel` (pre-redeem cancel, escrow back to the buyer), `dispute`
  (raise / retract / escalate), and `refund` (the x402-direct rail). The Boson
  actions are signed locally and gasless with the buyer's own wallet and relayed
  through the Terminal's agent-facing UCP routes; the wallet key never leaves the
  process.

### Changed

- Browse-first flow now mandates the native browser by default: on any shopping
  request the agent opens the store in the real, visible browser it can drive and
  navigates it live for the user to watch (to the category and products), rather than
  handing over a link to click, an open-in-browser card, or a headless read. The
  headless catalog readers are explicitly fallbacks only.

- Corrected the `redeem` guidance. The docs framed redeem as the buyer action required
  for the seller to be paid ("do it when the goods are received"). On an OMS-connected
  store (WooCommerce, Shopify) that is wrong: the merchant marking the order fulfilled or
  shipped fires the buyer's held redeem automatically over a fulfillment webhook
  (deferred-redeem-on-fulfillment), so fulfillment releases the escrow with no buyer
  action. `redeem` is now documented as an optional early-release the buyer can use to
  release sooner, or the release path on a store with no fulfillment webhook.

### Planned

- Dual-rail support for the direct `llc.facet.x402` settlement path, so a store
  that advertises only the x402-direct rail can be checked out without a Boson
  escrow rail.

## [1.0.0] - 2026-08-14

First public release of the buyer-side shopping skill.

### Added

- Non-custodial checkout on the Boson escrow rail: the wallet key signs an ERC-3009
  commit authorization locally and only the signature leaves the process; funds
  settle on-chain into the merchant's escrow.
- Self-serve, wallet-bound Facet KYA minting with no issuer service key
  (`kya-provision.ts`): a fresh identity key, proof-of-possession enroll, a client
  assertion, and an EIP-191 wallet proof.
- Guided shopping flow in `SKILL.md`: browse the real storefront first, discover
  agent-readiness via `agents.txt`, offer agent checkout, choose the wallet,
  self-issue identity, resolve the Terminal from the directory, quote dry, and
  settle after explicit confirmation.
- Discovery via per-host `agents.txt` and the network directory, with a canonical
  manifest re-read that trusts the Terminal's own copy over a storefront copy.
- Buyer-side guardrails: offer amount, token, chain, and escrow-recipient binding;
  HTTPS-only Terminal URLs; a per-checkout USDC cap under an absolute ceiling; a
  price-drift settle gate bound to the seller-signed amount; and an explicit
  unconfirmed-settlement handler that refuses a blind retry.
- Offline unit tests (`facet-checkout.test.ts`) exercising the honest path and every
  tampering vector (inflated amount, swapped token, wrong chain, substituted
  recipient, malformed scalars) with no wallet, no secrets, and no network.
- Last-resort public-catalog reader (`browse-storefront.ts`) for when neither the
  assistant's browser nor the Terminal search is available.
- Reproducible, integrity-locked dependencies via `deno.json` and `deno.lock`.

[1.1.0]: https://github.com/Facet-llc/shopping-skill/compare/v1.0.0...v1.1.0

[1.0.0]: https://github.com/Facet-llc/shopping-skill/releases/tag/v1.0.0
