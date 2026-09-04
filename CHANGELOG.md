# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.1] - 2026-09-03

### Added
- Card payment via Stripe Link at `stripe/charge` merchants, alongside the existing USDC path. The numbered flow now reads the store's payment rails from `facet_discover` (`commerce_rails` plus `mpp_method: stripe/charge`) and presents the USDC-versus-card choice to the user before anything is minted or quoted (steps 3, 4, 7), so an agent walking the flow offers both rather than defaulting to USDC. A new "Paying by card (Stripe Link)" section documents the card path: it composes `@stripe/link-cli` (`link-cli mpp pay` against the merchant's Facet MPP endpoint), the user links a card once (`link-cli onboard`) and approves each spend in their Link app, and the charge settles as a direct, non-custodial charge on the merchant's own connected Stripe account, with no card or Link credential ever passing through the skill. `facet_mpp_charge` gains a TEST `stripe/charge` SPT path (behind `FACET_STRIPE_SANDBOX_SK`) so the card rail is testable with no Link account.
- Voice discipline: the skill works silently through its own plumbing (loading the skill, guard and permission steps, and tool orchestration) and speaks only to shopper-facing substance, the store opening and its catalog, agent-readiness, the held total, and the receipt, instead of narrating a play-by-play of its process.
- Full multi-line cancel receipts: a per-line ("set form") cancel now archives a signed cancel lifecycle receipt for each cancelled line and marks those lines in the local order archive, and the receipt render (`discoverReversals`) treats a line as cancelled from either a signed receipt or its archived status. A full cancel therefore renders every cancelled line and "Net now" reads $0, instead of showing only the one line whose receipt happened to be archived. Pairs with the Terminal change that emits a per-line cancel lifecycle receipt. The in-process writes require the server launched with `--allow-write=$HOME/.cache,$HOME/.facet` (added to the launch snippets and the `mcp` task; the spawned child already had it).

## [1.4.0] - 2026-08-27

### Added
- `facet_render_receipt` now amends the original settlement receipt in place after a reversal: a cancel, withdraw, dispute, or refund adds an Amendments section below the untouched settlement showing the reversed line(s), the amount returned, a running net, and each reversal's own signed `facet-lifecycle+jws` receipt (embedded and verifiable in-browser). It builds this from the order's archived escrow lines plus the archived lifecycle receipts, so it works after settlement with no live call.
- `facet_mpp_charge` now refuses a non-`evm/charge` MPP challenge (for example `stripe/charge`) with a clear, actionable message instead of a misleading USDC-terms mismatch: a Stripe Shared Payment Token is a card credential this wallet-based skill does not mint, so it points you to `facet_buy` on the merchant's own rail. Guarded by the new exported `assertMppMethodEvm`, unit-tested both directions.
- `facet_lifecycle_receipt` and `facet_render_receipt` can now fetch and render a buyer's own refund receipt on a platform-originated order. When a refund is owned by an origin identity rather than the buyer, the skill proves control of the order's payer wallet with an EIP-191 signed challenge (`Facet lifecycle refetch`, bound to the order, wallet, issued-at, and a single-use nonce) to retrieve the signed `facet-lifecycle+jws` refund receipt, then amends the settlement receipt with it. A cancel, withdraw, or dispute stays strictly owner-only. `facet_render_receipt` pulls the merchant-approved refund receipt best-effort and dedupes the Amendment by transaction hash, so re-rendering never double-counts.

### Changed
- `facet_buy` is now a 2-step commit on the Boson escrow rail: a `settle` commits the funds and then ARMS the deferred redeem in the same call, so the merchant is cleared to fulfil and the escrow can pay out on their fulfillment signal. An un-armed deferred commit would sit on-hold and never ship. Arming is best-effort and reports `armed` plus `arm_skipped`; the funds are already committed, so an arm the store will not hold never fails the buy. Dry runs and x402 buys are unchanged. The buyer keeps the escrow's cancel, dispute, and timeout recourse, and the armed set is surfaced in the result and provenance so the release trigger is auditable.
- `facet_redeem_on_fulfillment` is reframed as the manual re-arm: `facet_buy` arms automatically, so this is for re-arming a specific `exchange_id` (for example one reported in `arm_skipped`) or a redeem deliberately held.
- Refund guidance now leads with reading the live on-chain exchange state before claiming a line is refundable, cancellable, or disputable: the agent reads each line's `exchange_state` with `facet_lines` and gates the action on it, rather than reasoning from the rail or memory.
- Post-delivery refund docs now state that a send-back is approved by the merchant in a Coinbase authorization window: on approval the merchant signs a gasless USDC transfer from its own payout wallet (an x402 `pay_to`) or Coinbase Smart Wallet treasury (a completed Boson leg), which Facet relays. Non-custodial on both sides; a buyer's `facet_refund` stays a request the merchant approves out of band.
- The rendered receipt's header logo is the current Facet brandmark, shown theme-aware: the white cube and wordmark on the dark panel, and the ink version on light. The dark-theme receipt panel background is now #202020 to match the brand. Each variant is the brand SVG inlined as a self-contained image, so it renders in the receipt's sandboxed view with no external fetch.
- MPP (mpp.dev) docs now describe both charge methods: `evm/charge` (the on-chain USDC settlement this wallet skill signs, straight to the merchant's payout wallet) and `stripe/charge` (a Stripe Shared Payment Token that settles as a direct, non-custodial charge on the merchant's own connected Stripe account, captured and refundable, validated live on production). The docs previously framed MPP as on-chain x402 only.

### Fixed
- `facet_buy` now arms a PER-LINE Boson cart's deferred redeem correctly. The 2-step commit-and-arm detected a per-line cart (one voucher per line) but armed it on the single-voucher store, where per-line exchanges never appear, so the arm silently no-op'd and the order sat on-hold with no held redeem for the merchant's fulfillment webhook to fire. A per-line cart now arms the whole line set (delivery voucher included) in one deferred call on the per-line route (`redeem_line_items` with `defer:true`), which is site-bound and buyer-direct, the same route and auth the immediate per-line redeem uses; a single-voucher cart still arms on the pooled store. The arm route is chosen from the buy result (`classifyBuyArm`): a per-line cart by its `perline:` settlement id or line `exchange_ids`, a single-voucher Boson buy by its rail and settlement id, with x402 and dry runs left untouched. Requires a Terminal with per-line deferred-redeem storage; where it is absent the arm is reported in `arm_skipped` and never fails the buy.
- A single-line cancel and `facet_lines` now resolve correctly for a settled per-line order, so the agent takes the right cancel route instead of retrying one that fails.

## [1.3.9] - 2026-08-21

### Added

- `facet_redeem_on_fulfillment` MCP tool: arm release-on-fulfillment for a just-committed Boson order by pre-storing a locally-signed deferred boson-redeem, so the merchant's fulfillment webhook releases the escrow. Routes through the Facet platform's originated-redeem relay for a first-party merchant (which supplies the RFC 9421 co-signature the redeem store requires, since the store is bound to the platform origin that committed the exchange) and buyer-direct otherwise. Opt-in and lower buyer protection than confirming receipt yourself with `facet_redeem`. In-process, non-custodial (the wallet key signs locally and never leaves the process).
- `facet_live_stores` MCP tool and a `stores` command: browse the public Facet store directory (merchants with a live Terminal) by query, without having to name a specific host first.
- Per-line Boson escrow: when a checkout advertises per-line fees, the buyer commits one escrow voucher per line (goods, delivery) instead of a single voucher for the whole cart, so an individual line can later be redeemed, cancelled, or disputed on its own.
- Per-line lifecycle on the CLI: `cancel`, `redeem`, and `dispute` accept `--exchange-ids` to act on a selection of a multi-line order's vouchers at once, routed through the per-line routes (the MCP path already did).
- SKILL.md: an ordered walkthrough of the dispute-driven partial refund (refund one delivered line, keep the rest) under "After the purchase", chaining redeem, `facet_dispute`, `facet_refund` (with `items`), the merchant approve, `facet_resolve`, and `facet_withdraw` in the sequence a post-delivery Boson escrow split requires. Calls out the two easy-to-miss preconditions: the dispute path opens only after the exchange is redeemed, and the buyer's refunded share is withdrawn from Boson available-funds to the wallet.

### Changed

- Rail-accurate buyer protection: the post-purchase summary relays `buyer_protection.recourse` per rail instead of promising escrow for every order. A Boson order holds the funds and releases on fulfillment (cancel before it ships, dispute after); an x402-direct order is the merchant's money on settlement, so its recourse is a Terminal refund request against the receipt.
- Documentation leads with the MCP server as the agent-facing surface and demotes the CLI to the implementation the tools spawn.

### Fixed

- Receipt render: line items now show for platform-originated orders, and the shareable receipt page renders gracefully with no JavaScript.
- Receipt render: the compact JWS and JOSE snippet boxes are server-rendered too, so the receipt is complete without any client-side script.

## [1.3.0] - 2026-08-20

### Added

- Version check against the GA release. A new `version` subcommand (and `facet_version`
  MCP tool) reads the newest tag from the public GA repository's GitHub API
  (`Facet-llc/shopping-skill`) and compares it to this build, so a user can confirm they
  are on the latest GA release: it returns `version`, `latest`, `up_to_date`, a human
  `message`, and an `update_url` when a newer release exists. Read-only (no wallet, no
  KYA, no secret), and a GitHub outage reports `up_to_date: null` (unknown) rather than
  failing. `SKILL_VERSION` in `scripts/version.ts` is the single source of truth for the
  build version; an offline test asserts it matches the newest dated CHANGELOG section, so
  a release cannot bump the tag without the version.

## [1.2.0] - 2026-08-20

### Added

- Per-line Boson escrow over MCP. New in-process MCP tools redeem, cancel, and dispute a
  SELECTION of a Boson order's line items in one request, each line carrying its own
  locally-signed payload, plus a `facet_lines` reader that lists an order's per-line
  escrow states. Unlike the other MCP tools, which spawn the CLI to sign in isolation,
  these run in-process and import the audited signing helpers, because a per-line action
  posts one request whose body is a set of signed line payloads the single-exchange CLI
  cannot assemble. The wallet key still signs locally, and neither the key nor any signed
  payload ever appears in a tool result.
- Server-recorded authorization trail in the receipt. `render-receipt` now reads the
  Terminal's owner-scoped `get_signatures` endpoint at render time and shows, inside the
  proof reveal, every credential the Terminal verified across the purchase: the KYA by
  hash, the UCP RFC 9421 platform signature, the ERC-3009 payment authorization, the
  seller offer, and a count of Facet's own Ed25519 response signatures and counterparty
  attestations. Owner-scoped exactly like the receipt, with the same payer-wallet
  fallback (over a distinct signatures challenge) so a platform-originated order the
  buyer paid for still reads its trail. Best effort: the receipt renders without the
  trail when the endpoint is unavailable, and the KYA is never returned in cleartext.
- Official receipt template and renderer. `render-receipt --terminal <url> --order-id <id>`
  (and the `facet_render_receipt` MCP tool) fetch and verify a settled order's receipt,
  embed the merchant's Ed25519 public key, and fill the canonical template at
  `references/receipt-template.html`, writing a self-contained, self-verifying HTML page:
  the verify seal runs a real in-browser Ed25519 check, every field derives from the
  embedded signed JWS, and the identity, payment, and verification provenance chain
  renders when available. The template is a dark, signed-ledger design (with a light
  toggle) that pairs the order's line items with the money breakdown (goods, tax,
  shipping, duty, discount): each item shows its name, SKU, and quantity. Items are read
  from the buyer's `order_history` (each SKU's display name from `get_product`), or
  supplied explicitly with `--items-file <path>` (a JSON array of `{ name, sku, qty,
  amount_minor? }`) for an order the buyer's identity does not own, such as a
  platform-originated order; without either, the receipt renders the money breakdown
  alone. Provenance comes from the archive a `buy --settle` now writes alongside the
  receipt (`saveReceipt` stores it) or an explicit `--provenance-file`; optional
  `--merchant-name` / `--merchant-location` / `--order-url` set the masthead and order
  link. New pure helpers `fillReceiptTemplate`, `pubkeyXForKid`, and
  `merchantNameFromHost` in `scripts/render-receipt.ts`, each with offline tests. This
  replaces the hand-rolled, one-off receipt pages with a single canonical rendering for
  all receipts.
- Client-side provenance on every settled purchase. `buy` (both rails) and `mpp-charge`
  now return a `provenance` block recording the signature chain the client presented and
  received: the buyer KYA's identity claims (aid / issuer / expiry, decoded from the token,
  never the raw bearer); the payment leg (on Boson, the buyer's ERC-3009 token
  authorization plus the seller's offer signature, extracted from the commit rather than
  the raw multi-KB blob; on x402/MPP, the ERC-3009 authorization and signature); the
  settlement chain (checkout, order, settlement id); and the Terminal's Ed25519-signed
  receipt with whether it verified offline against the merchant JWKS. New pure helpers
  `kyaIdentity`, `buildProvenance`, and `decodeBosonCommit`, each with offline tests. The
  block deliberately notes what it cannot include, the platform's `ucp_platform_rfc9421`
  co-signature, which the Terminal records server-side in its own FORCE-RLS-locked
  signatures ledger with no buyer-facing endpoint.
- Machine Payments Protocol (mpp.dev) support: a new `mpp-charge` subcommand (and
  `facet_mpp_charge` MCP tool) that pays a held reservation through mpp.dev's charge
  envelope, for an mpp.dev-native flow. MPP is not a separate rail: it is the same
  on-chain x402 settlement re-dressed in mpp.dev's challenge / credential / receipt
  shape. Reserve first with a DRY `buy` (its `checkout_id` is a valid reservation id),
  then `mpp-charge --reservation-id <id>` probes the charge endpoint for the 402
  challenge (amount, recipient, currency and chain all server-derived, never client-set),
  verifies it against a new pure `assertMppTerms` guardrail (chain, USDC, per-checkout
  cap, and a `--confirm-pay-to` recipient bind), and stops. `--settle` requires an exact
  `--confirm` of the amount AND `--confirm-pay-to` of the recipient (the MPP recipient is
  the merchant's own server-derived payout, not escrow-pinned, so it is confirmed like
  the x402-direct recipient); mppx then builds the evm/charge credential (an ERC-3009
  authorization whose nonce is bound to the challenge), the wallet signs it locally, and
  it is resubmitted. No KYA rides the charge leg (the unguessable reservation id is the
  capability and the credential moves the signer's own funds). `discover` now also
  surfaces a host's `mpp_endpoint` / `mpp_method` / `mpp_auth` when it serves MPP.
  Because MPP settles x402-direct with no escrow, `mpp-charge` never bypasses escrow:
  before charging it reads the reservation's own checkout session and refuses
  (`escrow_available_mpp_refused`, pure `mppRefusedForEscrow`) if the merchant offers
  Boson escrow, sending the caller to `buy`; it fails closed if it cannot confirm the
  merchant is x402-only. MPP has no refund leg of its own (an MPP charge is an
  x402-direct order), so the settle result surfaces `order_id` and a `refund` hint:
  a refund runs through the standard `refund --order-id` request and the merchant's
  x402-direct send-back. Facet custodies neither funds nor keys.

### Changed

- Receipt template surface trimmed to what a person reads at a glance: the amount and
  order breakdown, the live verify stamp, and the tamper-evident ledger. The settlement
  metadata, the signing details, the buyer identity and payment authorization provenance,
  and the compact signed JWS now live inside the collapsible proof reveal, opened on
  demand. Token-only move (the renderer is unchanged); the reveal body is a plain
  container so each tucked section pads itself like the surface sections.
- Refund flow docs corrected: a merchant approve of a still-committed Boson escrow now
  RELEASES the escrow via a seller revoke (the whole escrow returns to the buyer, then
  `withdraw`), with no buyer `resolve` step. `resolve` is only for a disputed post-redeem
  partial (a `resolveDispute` split). The earlier wording implied every Boson refund
  needed a `resolve`.

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
