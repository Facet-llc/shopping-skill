---
name: shopping
description: Shop any Facet-enabled website and buy on the user's behalf using the user's OWN agent identity (a self-issued, wallet-bound Facet KYA) and their OWN self-custodied wallet, non-custodially. Trigger when the user says "go shopping", or asks to shop, browse, or buy from a named store or site, add items to a cart, or check out somewhere that runs a Facet Terminal, or to redeem, cancel, dispute, refund, fetch and verify the signed settlement receipt for a past Facet order, or list saved receipts. Browses the merchant's human-facing site first; only when it discovers the site is agent-ready does it alert the user, offer agent checkout, and ask which of the user's own wallets to pay from. Checkout runs on the signed, agent-native rail (a UCP checkout session, on-chain USDC on Base) that the user confirms before any money moves. Never types a card into a merchant's web form.
---

# Shopping on a Facet-enabled store

This skill lets you shop a website for the user and complete a real purchase, end to end, without any middleman ever holding their money or their keys. The purchase is what makes it a skill; the browsing is just how the user picks.

## How this skill is consumed: the MCP server

This skill ships as an MCP (Model Context Protocol) server over stdio, `scripts/mcp-server.ts`. Facet is built to be walked by agents, not humans, so the agent-facing surface is the set of `facet_*` MCP tools the server advertises (catalogued under "The tools" below). You consume this skill by calling those tools through your MCP client.

You do NOT run `deno run scripts/facet-checkout.ts` yourself. That Deno script is the INTERNAL implementation the MCP server spawns to do the work (see "Driving this skill over MCP" for the wiring); it reads the wallet key inside the child process, and it is not an agent interface. There is no CLI step for you to invoke and no CLI fallback.

If the `facet_*` tools are not available in your client, the MCP server is simply not connected. That is a setup gap, not a reason to shell out: load the server (see "Loading the server" under "Driving this skill over MCP") and call the tools. Never work around a missing server by running the script directly.

## Non-custodial, and the open rail (read first)

This skill signs a payment with the user's wallet key, so the trust model comes first. The key is read from the environment, signs locally inside the Deno helper, and is never transmitted, logged, or written to disk; only the resulting signature leaves the process. Funds settle on-chain straight from the user's wallet into the merchant's escrow or, on the x402-direct rail, straight to the merchant's own payout wallet, so no Facet server ever holds the money or the key. Which rail is the merchant's default is set by the merchant's OMS (Facet's rail-split): Shopify stores default to x402-direct on both testnet and mainnet, and WooCommerce stores default to Boson escrow. The identity is a wallet-bound Facet KYA the user self-issues by proving control of the wallet, with no issuer service key anywhere in this skill.

These scripts are an auditable reference client for an open, published rail (agents.txt, the Facet KYA, the UCP checkout, x402 over HTTP-402, ERC-3009 on USDC, RFC 9421), and a fallback for agents that cannot sign on their own, not a required intermediary. For depth, one level down: [references/architecture.md](references/architecture.md) for the flow and rails, [references/security-model.md](references/security-model.md) for the threat model and every guardrail, and [references/troubleshooting.md](references/troubleshooting.md) for the error taxonomy, and [references/legal.md](references/legal.md) for terms, acceptable use, and data handling.

## The two surfaces (read this first)

"Shopping" hides two different jobs behind one word, and they call for opposite tools.

- Discovery and selection: finding the store, seeing what it sells, picking items. The best front end for this is the client's OWN web browsing on the merchant's real storefront, the same pages a person sees. Do not rebuild the merchant's catalog into a panel; their own site renders it better than anything this skill could assemble, and the catalog is not the moat. Trim your instinct to reconstruct a shopping mall in the chat.
- Checkout and settlement: identifying as the buyer, paying, getting a receipt. This is the whole point of the skill, and it runs on Facet's signed, agent-native rail: a UCP checkout session, a KYA-bearer identity, a non-custodial on-chain settlement, and a signed receipt. It NEVER means typing the user's card into the merchant's human checkout form in a browser tab. That would expose their card, carry no verifiable agent identity, and leave no provenance. The signed rail is strictly higher trust, and it is what "check out through Facet" means.

The mental model is Apple Pay. The merchant's storefront is the web page you browse (keep it, do not rebuild it). The little "agent checkout" badge on the page is the "Buy with Apple Pay" button. How the phone knows that button is real is the Facet directory plus the store's own `agents.txt`. And the Apple Pay rail itself, the part that moves money without ever handing the merchant a card, is the Facet Terminal.

Non-custodial by construction: the user's wallet key signs the payment inside a local helper process and never leaves the machine. Funds move straight from the user's wallet to where the merchant's rail directs: into Boson escrow (the WooCommerce default, held until fulfillment) or straight to the merchant's own payout wallet (the x402-direct default, for example Shopify). Escrow protects only about half the network, not every merchant, so never tell a buyer their money is held in escrow without checking the order's rail. Either way, no Facet server and no third party ever holds the money.

## When to use this

Trigger on natural intent, not just the exact words:
- "go shopping", "shop at acme.com", "buy the birthday bundle from that flower store"
- "add two of those to my cart", "check out", "what does this store sell?"

If the user names a site, start there. If they say "go shopping" with no site, either ask which store or use the directory (below) to find Facet-enabled merchants that fit what they want.

## One-time setup (tell the user once, then proceed)

The user provides two things through their environment. You never type, echo, or pass either value as a tool argument.

1. Deno (the runtime the MCP server and its helper scripts run on). If missing, point them to https://deno.com. Nothing else installs; the server pulls its two dependencies (a wallet signer and the escrow client) on first run.
2. Two environment variables in their shell (a profile export, or a local env file they source):
   - `FACET_KYA` (optional) : a Facet KYA, an ES256 bearer token from an issuer the store trusts, used as the agent identity for directory search and checkout. If it is absent, expired, or from an untrusted issuer, the helper self-serve mints a fresh wallet-bound KYA from the Facet issuer using `FACET_WALLET_KEY` (see "Getting a KYA"). Set it only to pin a specific identity.
   - `FACET_WALLET_KEY` : their wallet private key (`0x` + 64 hex). It signs the payment locally and is never transmitted. Ideally this is the SAME wallet their KYA is bound to (see "Getting a KYA" below). No wallet yet? The user can mint one with `facet_wallet_new` and skip this variable entirely (see "Getting a wallet (for a walletless user)" below); the minted wallet is then used automatically by label.

A walletless user is not a dead end: instead of asking them to produce a key, guide them through "Getting a wallet (for a walletless user)" below (`facet_wallet_new`, then `facet_fund`). For any other missing variable the helper returns a clear error; relay it and ask the user to set it, and never try to work around a guardrail.

More than one wallet (optional): a user who shops from several wallets can register them by setting `FACET_WALLETS` to a JSON array, one entry per wallet, for example:

    [{"label":"personal","key_env":"FACET_WALLET_KEY","kya_env":"FACET_KYA"},
     {"label":"business","key_env":"FACET_BIZ_WALLET_KEY","kya_env":"FACET_BIZ_KYA"}]

Each entry names the env vars that hold that wallet's key and KYA; the values themselves stay in the environment and are never written into the registry. With no `FACET_WALLETS` set, the single default wallet (`FACET_WALLET_KEY` + `FACET_KYA`) is used. You never need a key to list or pick a wallet: the `facet_wallet_list` tool shows each wallet's label, address, and balance so the user can choose.

## The tools

You drive this skill by calling its `facet_*` MCP tools. The server advertises the whole buyer surface via `tools/list`; every tool below is one of them. Tool arguments use snake_case (for example `exchange_id`, `max_usdc`); `items`, `ship`, and `keep` accept either a JSON string or a native array or object. A tool result is one JSON object (an address, a price, a status, a receipt); parse it. `isError` is set when the call failed or the underlying result was `ok: false`. No tool ever returns a wallet key or a KYA.

Your native browser is the DEFAULT and required way to SEE a storefront: on any shopping request, open the store in the real, visible browser you can drive and navigate it live so the user watches (to the category, the products, an item's page). Do not present a link the user must click, an "open in your browser" card, or a headless read as the way the user sees the store, and never lead with the Terminal. Only checkout and settlement run over these tools. See "Browsing the storefront" under the flow.

The product SKU is the join key from selection to checkout: a storefront `sku` is the same string as the Terminal product `id`. You pick by SKU and you buy by SKU.

Wallets and identity:

- `facet_wallet_list` : list the user's configured wallets so they can choose which to shop with. For each it shows the `label`, the derived `address`, the `usdc_balance` on Base, and whether a KYA is present. It reads only the user's own environment (the `FACET_WALLETS` registry, or the single default wallet); it never derives or displays a key, and it has no knowledge of any wallet the user did not configure. Call this FIRST, before searching, then pass the chosen `wallet` (the label) to the other tools. A wallet minted by `facet_wallet_new` appears here too (listed from its public address, with no key load or passphrase prompt).
- `facet_wallet_new` (`label`, `keystore`, `force`) : mint a fresh self-custodied wallet for a walletless user. It generates a recovery phrase, derives the wallet, and stores the private key securely (macOS keychain first, else an AES-256-GCM encrypted keystore under `~/.facet/keys`). The result carries only the public `address`, the `label`, where the key was stored, and a fund hint; the private key and the recovery phrase are NEVER returned. The one-time recovery phrase is written to the child process stderr, which the server discards, so it is intentionally not surfaced through MCP (a tool result is logged by the caller); to capture it a human must mint in a terminal where that stderr is theirs alone. Refuses to overwrite an existing `label` without `force: true`; `keystore: true` forces the encrypted-keystore tier. See "Getting a wallet (for a walletless user)".
- `facet_fund` (`label`, `min_usdc`, `await_funding`) : show a wallet's address and current USDC-on-Base balance so the user can send funds to it. With `await_funding: true` it polls until the balance is positive (or reaches `min_usdc`), then reports funded; omit it for a one-shot balance check. It loads no key and moves no money; it just watches the address. USDC on Base only.
- `facet_provision` (`wallet`) : self-serve mint a wallet-bound KYA for the chosen wallet from the Facet issuer (`issuer.facet.llc`), with NO issuer service key. The wallet signs a challenge locally (never transmitted); the issuer binds the KYA to that wallet. The token is cached and reused by `facet_search` and `facet_buy`, and is never printed or returned. `facet_buy` also mints on demand, so you rarely call this directly. Reach for it when a store rejects the current identity as untrusted, or to establish identity before an identity-gated call.

Discovery:

- `facet_discover` (`site`) : resolve ONE host's `agents.txt` (unauthenticated, no identity needed) to learn whether it runs a Facet Terminal and where. Authoritative for a single host; pass the bare host, for example `shop.example.com`. Returns `terminal`, `kya_issuers`, `commerce_rails`, `capabilities`, and, when the host serves the Machine Payments Protocol (mpp.dev), `mpp_endpoint` / `mpp_method` (`evm/charge`, the on-chain USDC method this skill signs; a host may instead card-settle via `stripe/charge`) / `mpp_auth` (`payment-scheme`). If the site is not Facet-enabled it returns `{ ok: false, facet_enabled: false }`.
- `facet_directory` (`query`, `near`, `radius_km`, `taxonomy`, `capabilities`, `min_reputation`, `claimed_only`, `limit`, `terminal`) : search the Facet directory across the network (identity-gated) for merchants that fit a query, location, capability, or taxonomy, and see which have a live Terminal. Use it to find a store from an intent, and to resolve a canonical Terminal URL by business name. Returns `{ ok, count, with_terminal, total_estimate, next_offset, results }`; each result carries `name`, `address`, `reputation`, `capabilities`, and a `terminal_url` that is non-null exactly when that merchant has a live Terminal.
- `facet_live_stores` (`terminal`) : list the live Facet-enabled stores a buyer can check out at RIGHT NOW, with no wallet and no KYA needed. Returns a count plus each store's name, storefront URL to browse, and Facet Terminal URL. Use it to answer "how many online stores can I buy from" and to hand the user storefront links to browse. This is the ungated public directory; `facet_directory` is the deeper identity-gated search.
- `facet_search` (`terminal`, `query`, `category`, `tags`, `limit`, `cursor`) : read a merchant's own agent-native transaction catalog from its Terminal (identity-gated, given not scraped: lean ids, pricing, stock, no images). Use it to confirm a SKU is purchasable on the rail, or as a selection source when the client cannot browse the storefront. Prefer it over `facet_browse_storefront` when a Terminal URL is known.
- `facet_product` (`terminal`, `id`) : read one product's rail detail from a Terminal by its SKU `id`, including the settlement rail the store advertises for it.

Checkout and payment:

- `facet_buy` (`terminal`, `items`, `ship`, `wallet`, `settle`, `confirm`, `confirm_pay_to`, `max_usdc`, `gift_message`, `delivery_date`, `occasion`) : the UCP checkout, signed and paid from the chosen `wallet`. DRY by default: it creates the checkout session, reads the seller-signed offer, validates it against the buyer guardrails, signs the payment authorization locally, and stops, returning the exact `price_usdc` and a `confirm_atomic` value. Nothing moves. To settle real money, call again with `settle: true` and `confirm` set to the exact atomic price the dry run returned, only after the user has approved that total. On the x402-direct rail the dry run also returns `confirm_pay_to` (the recipient), which must be passed back on settle: that rail settles straight to a per-merchant, server-advertised address that is not escrow-pinned, so the recipient is confirmed like the amount; the Boson escrow rail pins its recipient and needs only `confirm`. On the Boson escrow rail a `settle` is a 2-step buyer action done in this one call: it commits the funds to escrow and then ARMS the deferred redeem, pre-signing the release so the merchant's fulfillment webhook can pay them. An un-armed deferred commit would sit on-hold and never ship, so `facet_buy` arms every committed exchange itself and reports `armed` (plus `arm_skipped` for any the store would not hold, which never fails the buy since the funds are already committed). Arming ties release to the merchant's fulfillment signal rather than to the buyer confirming receipt; the buyer keeps the escrow's cancel, dispute, and timeout recourse. `items` is an array of `{ id, qty }`; `ship` is the shipping address object `{ recipient, line1, locality, region, postal_code, country }`. `gift_message`, `delivery_date` (`YYYY-MM-DD`), and `occasion` are applied to the merchant order at settlement (display-only, never change the price). When the buyer opted into shipping confirmations (see `facet_email_pref`), the stored throwaway email rides `order_attributes.contact_email` automatically. Every result carries `shipping_email_pref` (`unset` | `opted_in` | `opted_out` | `override`) so you know whether to ask. The wallet key never leaves the child process. See "Buying" and "Shipping confirmations".
- `facet_mpp_charge` (`terminal`, `reservation_id`, `wallet`, `settle`, `confirm`, `confirm_pay_to`, `max_usdc`) : pay a held reservation through the Machine Payments Protocol (mpp.dev) charge envelope, for an mpp.dev-native flow. MPP is a challenge / credential / receipt envelope, not a separate pot of money, and it carries two methods: `evm/charge` (an on-chain USDC settlement, the same one `facet_buy` performs, straight to the merchant's payout wallet) and `stripe/charge` (a Stripe Shared Payment Token that settles as a direct, non-custodial charge on the merchant's OWN connected Stripe account, captured and refundable, validated live on production). This wallet-based skill mints ONLY the `evm/charge` credential, so it settles that method; if the DRY probe returns a `stripe/charge` challenge (the merchant is card-settling through Stripe) it refuses with a clear message and points you to `facet_buy`, because a Stripe SPT is a card credential this skill does not mint. Reserve first (call `facet_buy` in DRY mode and use its `checkout_id`) and pass that as `reservation_id`. DRY by default: it probes the charge endpoint, reads the server-derived challenge (amount, recipient, currency, chain), validates it against the buyer guardrails, and stops, returning `confirm_atomic` and `confirm_pay_to`. Nothing moves. To settle real USDC, call again with `settle: true`, `confirm` set to that amount, and `confirm_pay_to` set to that recipient, only after the user approved the total. The credential is signed locally and the wallet key never leaves the child process. MPP settles x402-direct with no escrow, so it REFUSES on any merchant that offers Boson escrow (it reads the reservation's rails first) and points you to `facet_buy` instead: MPP never bypasses escrow. See "Paying through MPP".
- `facet_email_pref` (`action`, `address`, `none`) : record or read the buyer's throwaway shipping-confirmation email, asked once and reused on every later order so the agent never asks twice. `action: "show"` prints the current preference. `action: "set"` with `address` opts in and stores that address; `action: "set"` with `none: true` opts out, so the agent stops asking. When opted in, `facet_buy` attaches the stored address automatically. The address is buyer-provided and non-secret; it is stored as plain JSON under the cache dir, never the keystore. See "Shipping confirmations".

Browsing fallback:

- `facet_browse_storefront` (`site`, `query`, `limit`) : last-resort reader for a merchant's PUBLIC, human-facing storefront, for the rare case where neither the assistant's own browser nor a Terminal `facet_search` is available. Reads the public catalog (WooCommerce Store API, then JSON-LD) and returns a lean product list with SKUs: `{ ok, source, store, count, total, products: [ { sku, name, price, regular, currency, on_sale, in_stock, short, url, img_url, img_full } ] }`. The image fields are remote URLs on the merchant's host, kept for reference only; nothing is fetched, inlined, or rendered. Needs no identity, no wallet, and no secrets.

The escrow lifecycle (after a Boson purchase):

- `facet_redeem` (`terminal`, `exchange_id` or `exchange_ids`, `wallet`) : redeem a settled Boson escrow order, confirming the goods arrived and releasing the escrow to the seller, signed locally and gasless with the buyer's own wallet. `exchange_id` is the `settlement_id` the buy receipt returned. For a committed per-line (multi-item) order, pass `exchange_ids` (a string array, or a comma-separated string) instead to redeem a SELECTION of lines at once: each line is signed locally and posted as one set, and the result summarizes it with a top-level status plus counts and a per-line `lines[]` array. Pass exactly one of `exchange_id` or `exchange_ids`; read the lines first with `facet_lines`.
- `facet_cancel` (`terminal`, `exchange_id` or `exchange_ids`, `wallet`, `withdraw`, `amount`) : cancel a Boson escrow order before redemption; the full escrow returns to the buyer's Boson protocol available-funds, signed locally and gasless. Set `withdraw: true` to also cash the returned escrow out to the buyer's own wallet in the same call (cancel, then a gasless withdraw); `amount` optionally overrides the withdrawn atomic amount (default the full available balance). For a committed per-line order, pass `exchange_ids` to cancel a SELECTION of lines at once (same set semantics and `lines[]` summary as `facet_redeem`); `withdraw` is single-line only, so it cannot be combined with `exchange_ids`. Pass exactly one of `exchange_id` or `exchange_ids`. A single `exchange_id` that belongs to a per-line order is auto-routed to the per-line cancel path, so a one-line cancel works whether the order settled pooled or per-line, with no need to know which it is.
- `facet_withdraw` (`terminal`, `exchange_id`, `wallet`, `amount`, `dry_run`) : cash a Boson escrow's returned available-funds out to the buyer's OWN wallet, gaslessly. After a cancel (or a seller revoke) the escrowed USDC sits in the buyer's Boson protocol available-funds; this signs the buyer's `withdrawFunds` meta-tx locally and a gas-only relayer submits it. `withdrawFunds` is self-binding on-chain, so the funds can only go to the buyer's own wallet. `exchange_id` is the `settlement_id` the buy receipt returned; `amount` optionally overrides the atomic amount (default the full balance); `dry_run: true` gathers, signs, and returns the exact request body WITHOUT posting, for inspection before a real cash-out. Returns status, tx, and amount; never a key.
- `facet_dispute` (`terminal`, `exchange_id` or `exchange_ids`, `action`, `wallet`) : raise, retract, or escalate a dispute on a Boson escrow order, signed locally and gasless. `action` is one of `raise`, `retract`, `escalate` (default `raise`). To complete a partial-refund split, use `facet_resolve` (it carries the seller's counter-signature). For a committed per-line order, pass `exchange_ids` to apply the same action to a SELECTION of lines at once (same set semantics and `lines[]` summary as `facet_redeem`). Pass exactly one of `exchange_id` or `exchange_ids`; read the lines first with `facet_lines`.
- `facet_lines` (`terminal`, `order_id`, `wallet`) : read a committed per-line (multi-item) Boson order's current escrow lines so you can choose which lines to act on. Returns the order's `escrow_lines`: each line's own `line_index`, `exchange_id`, `amount`, `currency`, and `exchange_state` (plus status), owner-scoped to the caller's wallet-bound identity. Reads only; moves no money and returns no key. Use it before `facet_redeem`, `facet_cancel`, or `facet_dispute` with `exchange_ids`. `order_id` is the order id the buy receipt returned. For a SETTLED per-line order the live checkout session is gone, so `facet_lines` falls back to the settle-time archived line map (each line's `exchange_id` + `sku` + `amount`) and marks `source: "archive"`; `order_id` therefore resolves both before and after settlement, so it never dead-ends on a settled order.
- `facet_redeem_on_fulfillment` (`terminal`, `exchange_id`, `wallet`) : arm release-on-fulfillment for a just-committed Boson order: pre-authorize the escrow to release to the merchant automatically when they mark the order fulfilled. Signs a `boson-redeem` voucher locally with the buyer wallet and stores it (deferred) while the exchange is still committed, so the merchant's fulfillment webhook releases it. `facet_buy` ARMS this automatically on every Boson commit (the 2-step commit-and-arm), so you rarely call it directly. Reach for it only to manually re-arm a specific `exchange_id`: a commit whose arm came back in `arm_skipped`, or a redeem you deliberately held. It releases on the merchant's fulfillment signal, not on your confirmation that the goods arrived; to keep that confirm-on-receipt protection instead, use `facet_redeem` after delivery on a store that supports it. Non-custodial: the key signs locally and never leaves the process. For a first-party merchant the store is relayed through the Facet platform (which supplies the required co-signature); a buyer-only client cannot store it directly.

Refunds and returns:

- `facet_refund` (`terminal`, `order_id`, `reason`, `items`, `wallet`) : open a refund ticket for a settled order. REQUEST only: it opens the ticket and moves no money; the merchant reviews the `reason` and approves, and only the approve moves money, in one of three ways by rail and escrow state. An x402 order (and a completed-Boson leg) sends USDC back from the merchant wallet: on approval the merchant authorizes a gasless send-back from its own payout wallet or treasury in a Coinbase authorization window (signed there, relayed by Facet, so Facet never holds the merchant's key either). A still-committed Boson escrow is RELEASED by the approve itself (the Terminal signs the seller revoke, the whole escrow returns to the buyer, then `facet_withdraw` cashes it to the wallet, with no `facet_resolve` step). A disputed Boson order (a post-redeem partial) offers a seller-signed `resolveDispute` split the buyer completes with `facet_resolve`. Pass `items` (an array of `{ id, qty }`) for a PARTIAL refund of just those lines, with shipping retained; omit it to request the whole order. On a store that gates the request behind a platform co-signature, it authorizes itself with a single-use, order-bound wallet attestation signed locally, so a buyer-only agent can open the ticket with no platform in the loop; a single-factor store ignores it. `order_id` is the order id the buy receipt returned.
- `facet_resolve` (`terminal`, `refund_id` or (`exchange_id`, `buyer_percent_bps`, `seller_sig`), `wallet`) : complete a Boson partial-refund split (a mutual `resolveDispute`) after the merchant approves. Signs the buyer half locally and gaslessly and submits it; the Terminal validates the split against the merchant's stored offer before relaying, so the buyer cannot alter the percentage or the seller half. Give `refund_id` to auto-read the approved offer from the buyer's own refund ticket, OR pass the offer explicitly with `exchange_id`, `buyer_percent_bps`, and `seller_sig`. The wallet key never leaves the child process.

Reorder and revise (planners, they move no money):

- `facet_reorder` (`terminal`, `order_id`, `limit`, `wallet`) : buy a past order again. Reads the buyer's own order history (owner-scoped to the caller's identity), then for each past item reads the CURRENT price and availability, and returns the reorder candidates plus a buy plan. Pure orchestration: it settles nothing and buys nothing on its own. A SKU that is gone or out of stock is marked unavailable and skipped, never fatal. The actual purchase runs through `facet_buy` exactly like any other checkout: DRY first, an explicit user confirmation, then settle. With `order_id` it reorders that order; without it, the most recent order. See "Reordering a past order".
- `facet_revise` (`terminal`, `exchange_id`, `keep`, `wallet`) : plan a change to a multi-item order BEFORE it ships. Boson cannot partially refund a committed escrow, so the non-custodial equivalent is cancel-and-rebuy: cancel the whole order (the full escrow refunds, cashed back to the wallet) then re-buy only the kept items. Returns the two-step plan (the exact cancel and buy steps) and moves NO money on its own, like `facet_reorder`. `exchange_id` is the escrow to cancel; `keep` is an array of `{ id, qty }` for the items to keep and re-buy. Run the two steps through `facet_cancel` and `facet_buy`, confirming each. See "Revising an order before fulfillment".

Receipts and proof (read-only):

- `facet_get_receipt` (`terminal`, `order_id`, `no_verify`, `wallet`) : fetch and verify the Facet ledger's signed settlement receipt for a settled order, offline against the merchant Terminal's published JWKS with no call back to Facet. A settled `facet_buy` already returns this inline; use this to re-fetch or independently verify any past order. If the original buyer identity has expired it re-authorizes by signing a challenge with the paying wallet, so the wallet that paid can always retrieve its own receipts. `no_verify: true` returns the raw receipt without the offline signature check. Every fetched receipt is also saved to the local archive. Returns the receipt and its `verified` flag; never a key. See "The receipt".
- `facet_render_receipt` (`terminal`, `order_id`, `wallet`, `merchant_name`, `merchant_location`, `order_url`, `provenance_file`, `out`) : render a settled order's receipt into the OFFICIAL, self-contained, self-verifying HTML page (the one canonical Facet receipt view). Every field is derived in the page from the embedded signed JWS, the merchant's Ed25519 public key is embedded so the verify seal is a real in-browser check, and the identity, payment, and verification provenance chain renders when it is available (from the archive a settled buy wrote, or an explicit `provenance_file`). Writes the HTML and returns its path; nothing on it is secret, so the file is shareable. `merchant_name` is an optional display name; `out` is an optional output path (defaults under the receipts archive). See "Showing a detailed, shareable receipt view".
- `facet_lifecycle_receipt` (`terminal`, `kind`, `exchange_id` or `order_id`, `wallet`) : fetch, verify, and archive the signed REVERSAL receipt for a cancel, withdraw, dispute, or refund (the lifecycle analogue of `facet_get_receipt`), a compact Ed25519 JWS (typ `facet-lifecycle+jws`) verified offline against the merchant Terminal's published JWKS. The reversal tools already archive it inline; use this to re-fetch it, or to fetch one performed earlier in the same wallet-bound identity. `kind` is one of `cancel` / `withdraw` / `dispute` / `refund`; pass `exchange_id` for cancel / withdraw / dispute, or `order_id` for a refund. Owner-scoped at the Terminal (a 404 otherwise, never a leak). Returns the receipt and its `verified` flag; never a key.
- `facet_receipts` : list the local receipt archive: every settlement receipt this environment has fetched, most recent first, each with its order id, rail, amount, and verified flag. Reads only local files under the receipts folder (default the buyer's own home, override with `FACET_RECEIPTS_DIR`); needs no wallet and no network. Use it when the user asks about their past purchases, rather than re-fetching each order. Returns public receipt metadata only; never a key.

Housekeeping:

- `facet_version` : confirm the installed skill against the latest GA release. Reads the newest published tag from the public GA repository's GitHub API (`Facet-llc/shopping-skill`) and compares it to this build, returning `version`, `latest`, `up_to_date`, a human `message`, and an `update_url` when a newer release exists. Read-only (no wallet, no KYA, no secret); a GitHub outage reports `up_to_date: null` (unknown), never an error. Use it when the user asks whether the skill is up to date.

## Driving this skill over MCP (for autonomous agents)

The `facet_*` tools above are served by an MCP (Model Context Protocol) server over stdio, `scripts/mcp-server.ts`. Facet is built to be walked by agents, not humans, so an autonomous agent that speaks MCP can discover, identify, browse, and check out with no human at a keyboard. The server is a thin wrapper: nearly every tool spawns one internal script (`scripts/facet-checkout.ts` or `scripts/browse-storefront.ts`) as a child process and relays the one JSON object it prints, so no checkout, wallet, or KYA logic is reimplemented and the guardrails and the non-custodial invariant are identical across every tool. The one deliberate exception is the per-line Boson escrow tools (`facet_redeem`, `facet_cancel`, and `facet_dispute` over a selection of `exchange_ids`, plus the `facet_lines` reader and `facet_redeem_on_fulfillment`): they run in-process and import the audited signing helpers, so for those tools the server itself reads the wallet key to sign each line locally. That is necessary because a per-line action posts one request whose body is a set of line items, each carrying its own locally signed payload, which the single-exchange child cannot assemble. The key still signs only locally, and no key or raw signed payload ever enters a tool result. The `facet_redeem_on_fulfillment` tool signs a deferred boson-redeem locally and stores it so the merchant's fulfillment webhook can release the escrow, routing through the Facet platform's originated-redeem relay for a first-party merchant (which supplies the RFC 9421 co-signature the store requires, since the store is bound to the platform origin that committed the exchange) and buyer-direct otherwise.

### Loading the server

Point your MCP client at this stdio command:

```bash
deno run --allow-env --allow-read --allow-run --allow-net "$SKILL/scripts/mcp-server.ts"
```

or, from the skill directory, `deno task mcp`. A typical MCP client config entry:

```json
{
  "mcpServers": {
    "facet-shopping": {
      "command": "deno",
      "args": ["run", "--allow-env", "--allow-read", "--allow-run", "--allow-net", "<absolute path>/scripts/mcp-server.ts"]
    }
  }
}
```

The server spawns each internal script with the narrow, per-script grants it needs (network only for the public storefront reader; env, read, a write scoped to `~/.cache` and `~/.facet`, run, and network for the checkout script). The wallet key and KYA are read by the child from the environment, so set `FACET_WALLET_KEY` (or a `FACET_WALLETS` registry) in the environment the MCP client launches the server with. The server process itself never reads the key into a variable.

### The secret invariant on MCP

A tool result is logged and persisted by the calling agent, so it is held to the same bar the secret-egress rule holds stdout to: it carries an address or a status, never a secret. The wallet key and the recovery mnemonic never appear in a tool argument or a tool result. The one place a secret is revealed, the one-time recovery phrase from `facet_wallet_new`, goes to the child process stderr, which the server runs with `stderr: "null"` so it is discarded by the OS and never captured, forwarded, or returned. A human who needs that recovery phrase must mint in a terminal where that stderr is visible only to them.

### Internal implementation: the scripts the tools spawn

This is internal wiring, not an agent interface. Do not invoke these scripts yourself; call the `facet_*` tools above.

- `scripts/facet-checkout.ts` is the identity-and-money implementation each spawn tool runs as a child (the `wallet new`, `wallets`, `fund`, `directory`, `discover`, `stores`, `search`, `product`, `provision`, `buy`, `mpp-charge`, `email-pref`, `redeem`, `cancel`, `withdraw`, `dispute`, `refund`, `resolve`, `reorder`, `revise`, `receipt`, `render-receipt`, `lifecycle-receipt`, `receipts`, `version` subcommands). It reads the wallet key and KYA from the environment (the `FACET_WALLETS` registry, or the default `FACET_WALLET_KEY` plus `FACET_KYA`) and signs locally; the key stays in the child and the server never reads it (except the in-process exception above). Each child prints ONE JSON object to stdout, which the tool relays; progress notes go to stderr, which the server discards. Its write grant (`--allow-write="$HOME/.cache,$HOME/.facet"`) is what lets the minted KYA cache under `~/.cache/facet` (so identity-gated tools reuse it instead of re-minting), lets the encrypted keystore and wallet index live under `~/.facet`, and lets every fetched settlement receipt archive under `~/.facet/receipts`.
- `scripts/kya-provision.ts` is the self-serve identity minter the child uses for `facet_provision` and for `facet_buy` on demand: it enrolls a fresh identity key and mints a wallet-bound KYA from the Facet issuer with NO service key, then caches it for reuse. It never prints the token.
- `scripts/browse-storefront.ts` is the public-catalog reader behind `facet_browse_storefront`: it reads a store's public catalog into a lean list with network access only, no env, no files, and no secrets.

Which tool wraps which internal subcommand:

| MCP tool | internal subcommand |
|---|---|
| `facet_wallet_list` | `wallets` |
| `facet_wallet_new` | `wallet new` |
| `facet_fund` | `fund` |
| `facet_provision` | `provision` |
| `facet_discover` | `discover` |
| `facet_directory` | `directory` |
| `facet_live_stores` | `stores` |
| `facet_search` | `search` |
| `facet_product` | `product` |
| `facet_buy` | `buy` |
| `facet_mpp_charge` | `mpp-charge` |
| `facet_email_pref` | `email-pref` |
| `facet_browse_storefront` | `browse-storefront.ts` |
| `facet_redeem` | `redeem` (or in-process for a per-line set) |
| `facet_cancel` | `cancel` (or in-process for a per-line set) |
| `facet_withdraw` | `withdraw` |
| `facet_dispute` | `dispute` (or in-process for a per-line set) |
| `facet_lines` | in-process (reads the order's escrow lines) |
| `facet_redeem_on_fulfillment` | in-process (deferred redeem store) |
| `facet_refund` | `refund` |
| `facet_resolve` | `resolve` |
| `facet_reorder` | `reorder` |
| `facet_revise` | `revise` |
| `facet_get_receipt` | `receipt` |
| `facet_render_receipt` | `render-receipt` |
| `facet_lifecycle_receipt` | `lifecycle-receipt` |
| `facet_receipts` | `receipts` |
| `facet_version` | `version` |

## The flow

The first job is ordinary web shopping; Facet only enters once you discover the store is agent-ready. Never lead with the Terminal.

1. Open the store in your native browser and navigate it live for the user to see. The moment the user asks to shop, open the merchant's real storefront in your own native browser, the real, visible browser you can drive and that the user can watch, and navigate it in front of them: go to the matching category or use the site's search box (for "birthday flowers", open the birthday collection or search "birthday", do not stop at the home page), scroll the products into view, and open an item's page when they want a closer look. On a request to shop or to see a store's products, this is the default first action, not a fallback. Do NOT hand the user a link to click, do NOT open the page only as an "open in your browser" card, and do NOT lead with a headless fetch or a plain-text description: drive the visible browser yourself so the user watches their own shopping happen. As you go, read the arrangements off the page (name, price, sale price, rating, image) and keep a short running list with prices. You are the cart: hold the user's choices and quantities in your own memory.

The browser is for looking, not buying. Use it to browse and select only. Never add items to the store's cart, never open the store's own checkout, and never touch a pay button (Google Pay, a card field, anything) on the merchant's page. Do not raise wallets or payment yet. When the user is ready to buy, STOP driving the store and switch to the Facet Terminal (steps 4 to 8): checkout is ALWAYS the Facet Terminal's signed rail, never the store's own checkout. This step works on any store, Facet-enabled or not. See "Browsing the storefront" below for the concrete loop.
2. In the same browser pass, spot the agent-checkout badge and read it. Look for the "agent checkout" badge on the page (usually near the human cart or checkout, often labeled for Facet). It is the visual signal that the store may accept agent checkout, the "Buy with Apple Pay" button in the Apple Pay model. Click it to read it: the badge links straight to the store's `agents.txt`, the discovery pointer that says whether the store really runs a Terminal and where. Treat the badge itself as a hint to verify, never as proof (see "The badge is a hint").
3. Discover and alert. Confirm agent-readiness by resolving the store's `agents.txt` (call `facet_discover` with `site`). If it carries a `Terminal`, tell the user plainly: this site is agent-ready and supports agent checkout. If it does not, the store is not Facet-enabled; stay in ordinary browsing and let the user check out however they normally would. Never touch the Terminal for a non-agent store.
4. Offer agent checkout and choose the wallet. Ask the user two things together: do they want to use agent checkout for this purchase, and which of their own wallets to pay from. Call `facet_wallet_list` and show each label, address, and USDC balance so they can choose, then carry the chosen `wallet` (the label) through the rest. This is the handoff and the "pick your card" step, and it happens now, at discovery, not before browsing. If the user declines, stop here; nothing else runs.
5. Self-issue the wallet-bound identity. Mint a wallet-bound KYA for the chosen wallet from an issuer the store trusts (call `facet_provision` with `wallet`), self-serve and with no service key: the wallet signs a challenge locally so the issuer binds the KYA to it. The wallet key never leaves the machine, and the token is never printed (see "Identity and wallet-bound checkout"). You need this before the next step, because the directory and the Terminal are identity-gated.
6. Find the Terminal in the Facet directory. Search the directory for the business name without the `.com` (call `facet_directory` with `query: "<business name>"`, authenticated with the KYA from step 5) and read the matching result's `terminal_url`. This resolves the store's canonical Terminal from Facet's own records, so it stays correct even if the merchant's `agents.txt` is stale. Cross-check it against the `Terminal` value from step 3.
7. Quote and price it (DRY). Call `facet_buy` with `terminal`, `items`, `ship`, and the chosen `wallet`, and omit `settle`. This creates the UCP checkout, reads the merchant's offer, verifies it against the guardrails, signs the payment authorization locally, and stops. It returns the exact `price_usdc` and a `confirm_atomic` value. Nothing has moved. Show the user a thin confirmation (item, price, terms), not a rebuilt storefront (see "The confirmation surface"). If this is a gift, ask the user for a card message and a delivery date first and pass them as `gift_message` and `delivery_date` (`YYYY-MM-DD`), and `occasion` if useful: the signed UCP checkout supports these order attributes and carries them to the merchant order, so the message lands on the order and a future delivery date is requested. They do not change the price. The DRY result also carries `shipping_email_pref`; if it is `unset`, ask the buyer once about shipping confirmations before you settle (see "Shipping confirmations"), record the answer with `facet_email_pref`, then re-run the DRY `facet_buy` so the stored choice is applied.
8. Confirm and settle. Show the real total, the items, and the wallet it pays from, and get an explicit yes for this purchase. Only then call `facet_buy` again with `settle: true` and `confirm` set to `<confirm_atomic>` (the exact value from step 7), same `wallet` (and `confirm_pay_to` from the DRY run on the x402-direct rail). Report the settlement: status, order id, settlement id, and the signed receipt. This confirmation is required every time; never skip, batch, or infer it.

### Browsing the storefront (drive it live, do not just describe it)

Steps 1 and 2 are an active job in your native browser, driven live in front of the user, not a passive one. Open the real, visible browser and navigate it so the user watches their shopping happen. This is what makes it feel real, so do it every time, proactively, before you ever mention Facet:

- Open the merchant's site in your native browser (the visible one the user can watch) and navigate to their intent: use the store's own search box, or the category that matches ("birthday", "roses", "sympathy"), rather than stopping at the home page.
- Read the products off the rendered page: name, price, sale price, rating, availability, and image.
- Show the user visually: a screenshot or a rendered view of the arrangements, plus a concise list (name, price, the sale price when on sale, rating). Let them see the flowers and pick.
- Refine by what they say ("something brighter", "under $30", "add a card"), and offer to open any single item for a closer look.
- Fallbacks, and only when you genuinely cannot drive a browser: the Terminal's own catalog via `facet_search` (after identity is set) or `facet_browse_storefront` for a lean public list. These are backups for a headless environment, never the default, and neither one replaces showing the user.

This whole loop is browsing, not buying. Never proceed into the store's cart or checkout, and never touch a pay button on the merchant's page. The moment the user picks, switch to the Facet Terminal (steps 4 to 8); checkout is always the signed rail, never the store's own checkout.

## Choosing the wallet (at the handoff)

Picking the wallet is the "pick your card" step in the Apple Pay model, and it happens at the handoff: once the store is discovered as agent-ready and the user opts into agent checkout (step 4), not before browsing. The wallet the user chooses sets three things at once: their identity (the wallet-bound KYA), the balance they can spend, and the address the USDC actually moves from. So the skill asks at that moment, then carries that one choice all the way through checkout.

Call `facet_wallet_list` and read it back to the user: label, address, and USDC balance for each. If they configured only one wallet, say which it is and confirm. If they configured several (via `FACET_WALLETS`), list them and let the user pick by label. Pass the chosen `wallet` to `facet_provision`, `facet_search`, `facet_product`, and `facet_buy` so identity and payment both come from the same wallet.

This lists the user's OWN wallets only. It reads their `FACET_WALLETS` registry, or the single default `FACET_WALLET_KEY` plus `FACET_KYA`, and nothing else. It derives each address locally from the user's own key and never prints, echoes, or transmits a key. It cannot see, recommend, or list any wallet the user did not configure in their own environment.

## Does this merchant have a Terminal?

Two mechanisms, one answer.

- Per host, call `facet_discover` with `site` to resolve the store's own `agents.txt`. This is authoritative for a single site: it is the store telling you, on its own domain, that it runs a Terminal and where that Terminal is. Use it whenever the user names a specific store.
- Across the network, `facet_directory` searches the Facet directory for merchants that fit a query, a location, a capability, or a taxonomy, and tells you which of them have a live Terminal (`terminal_url` non-null). Use it to find a store when the user has an intent but not a URL.

### The badge is a hint, not a permission

Some Facet-enabled stores show an "agent checkout" badge on the page, typically near the human cart or checkout button. Teach yourself to spot it: it is the visual signal that the store accepts agent checkout, the same role the "Buy with Apple Pay" button plays. Click it to read it: the badge links to the store's `agents.txt`, so clicking is the quickest way to reach the discovery pointer and confirm the Terminal.

But a badge is a pointer, never an authorization, and a pixel can be spoofed. Treat a badge as "go verify," not as proof. Confirm it by resolving the store's `agents.txt` (or the directory) and by completing the KYA handshake at the Terminal. The handshake is what actually establishes that the store runs a real Terminal and that the user's identity is accepted; the badge just tells you it is worth checking.

## The confirmation surface (thin, not a mall)

Once the user has picked, present a thin confirmation panel, not a rebuilt catalog. The user already saw the merchant's real storefront in the browser; your job here is to confirm exactly what is about to be bought, not to re-render the store.

Keep it to what a confirmation needs:
- the item name (and quantity),
- the price, with the sale price shown when the item is on sale,
- the key terms (what settles, on what rail, to what wallet, plus shipping when it is physical goods),
- the gift message and the delivery date, when the user set them (the signed UCP checkout carries them to the merchant order),
- a plain question: buy this?

A short markdown block is enough. One item, or a few lines for a small cart. Do not build image grids, do not fetch and inline photos, do not assemble a multi-item gallery. If the user wants to see the product again, send them back to the merchant's real page in the browser. The render panel is a confirmation surface, not a shopping mall.

### The conversational cart

There is no clickable cart and no shortlist widget. You are the cart. As the user talks ("the peonies, and two of the sunflower ones"), hold their selection in your own working memory, confirm it back in words, and carry those SKUs into the DRY checkout. The only place the user acts is confirming the real total before settlement.

## Buying

Checkout is the signed, agent-native rail, and only that. It creates a UCP checkout session at the merchant's Terminal, presents the user's KYA as the buyer identity, signs an on-chain payment authorization locally with the user's wallet, and settles non-custodially on the merchant's own rail (into Boson escrow, or straight to the merchant's payout wallet on x402-direct), returning a signed receipt. It is NEVER Claude typing a card number into the merchant's human web checkout. If you ever find yourself about to fill a card field in a browser tab to "complete the purchase," stop: that is not this skill, and it breaks identity, provenance, and the non-custodial invariant all at once.

`items` is a JSON array of `{ "id": "<product_id>", "qty": <n> }`. `ship` is a JSON object: `{ "recipient", "line1", "locality", "region", "postal_code", "country" }`. Both accept a native array or object, or a JSON string.

Optional gift and delivery arguments are applied to the merchant order at settlement: `gift_message: "Happy birthday!"` writes a card message on the order, `delivery_date: "YYYY-MM-DD"` requests a future delivery date, and `occasion: "birthday"` tags the occasion. The Terminal validates and length-caps them and the store maps them through (on a WooCommerce store the card message becomes the order note and the date becomes the requested delivery date). They are display-only, never change the price, and never block settlement: a malformed value is dropped rather than failing the purchase.

### Shipping confirmations (ask once, then reuse)

Shipping-confirmation emails are OFF by default, for privacy: with no email on the order the store never sees the buyer's real address. On the buyer's FIRST purchase you offer them a choice, once, and then you honor that choice on every order after without asking again.

How to tell it is the first time: the DRY `facet_buy` result carries `shipping_email_pref`. When it is `unset`, the buyer has never been asked. Ask them plainly, before you settle: shipping confirmations are off by default; if they want them, give a throwaway email (not their real one) and it will be reused for every future order so the store never sees their real address, or they can decline and keep confirmations off. Record the answer, once:

- They want confirmations: call `facet_email_pref` with `action: "set"` and `address` set to the throwaway address. Stored as opted in.
- They decline: call `facet_email_pref` with `action: "set"` and `none: true`. Stored as opted out, so you never ask again.

After that, reuse is automatic and silent. `facet_email_pref` stores the choice under `~/.cache/facet/order-prefs.json`, and every later `facet_buy` reads it: an opted-in address rides `order_attributes.contact_email` on the checkout automatically (the store un-suppresses the shipping-confirmation email and sends it to the throwaway address), and an opted-out or already-answered buyer is never asked again. `shipping_email_pref` on the buy result reflects the state each time (`opted_in`, `opted_out`, or `override`); you only ever ask on `unset`. To send one order to a different address, update the stored address with `facet_email_pref` before that `facet_buy` (the stored preference is what every `facet_buy` applies).

The email is buyer-provided. It is a preference, not a secret, so it lives as plain JSON in the cache (never the `~/.facet` keystore) and may be passed as a plain `facet_email_pref` argument. A Facet-generated relay alias, so the buyer need not supply their own throwaway address, is a planned follow-up and is not part of this flow yet.

DRY (default, safe): call `facet_buy` with:

```json
{
  "terminal": "<terminal>",
  "wallet": "<label>",
  "items": [{ "id": "SKU-1", "qty": 1 }],
  "ship": { "recipient": "Jane Doe", "line1": "123 Main St", "locality": "Austin", "region": "TX", "postal_code": "78701", "country": "US" }
}
```

Settle (real money, only after the user confirms the DRY total): call `facet_buy` again with the same arguments plus `settle: true` and `confirm` set to the DRY result's `confirm_atomic`:

```json
{
  "terminal": "<terminal>",
  "wallet": "<label>",
  "items": [{ "id": "SKU-1", "qty": 1 }],
  "ship": { "...": "same as above" },
  "settle": true,
  "confirm": "<confirm_atomic-from-the-DRY-result>"
}
```

(`wallet` is the label the user chose in step 1. With a single default wallet it can be omitted, but pass it explicitly once the user has picked so identity and payment stay pinned to that one wallet. On the x402-direct rail also pass `confirm_pay_to`, echoing the recipient the DRY run returned.)

The `confirm` value must equal the price the DRY run just advertised. If the store's price changed in between, the settle refuses. That is intended; re-run DRY, show the new total, and confirm again.

## Paying through MPP (mpp.dev)

Most checkouts should just use `facet_buy`: it creates the UCP checkout AND settles it in one signed flow, and it is what "check out through Facet" means. `facet_mpp_charge` is for the case where the payer is an mpp.dev-native agent, or where you want to settle a reservation through the Machine Payments Protocol's own challenge / credential / receipt envelope. MPP is not a different pot of money: it is a challenge / credential / receipt envelope an agent that already speaks mpp.dev can use to pay a Facet order with no Facet-specific code. It carries two methods. `evm/charge` is the SAME on-chain USDC settlement `facet_buy` performs, expressed in mpp.dev's shape, and is the one THIS wallet-based skill signs (an ERC-3009 authorization straight to the merchant's payout wallet). `stripe/charge` is a Stripe Shared Payment Token that settles as a DIRECT, non-custodial charge on the merchant's OWN connected Stripe account (captured and refundable, with a platform application fee for non-promo merchants; validated live on production): a CARD credential this skill does not mint, so when the charge probe returns a `stripe/charge` challenge the skill refuses with a clear message and you pay through `facet_buy` on the merchant's own rail instead (the Stripe method is for a card agent, not this wallet flow). A host advertises MPP in `agents.txt` (`facet_discover` surfaces `mpp_endpoint` / `mpp_method` / `mpp_auth: payment-scheme`); a host without those lines does not serve MPP, so use `facet_buy`.

One hard rule: **MPP never bypasses escrow.** MPP settles x402-direct (straight to the merchant's payout, no escrow, no buyer protection), so `facet_mpp_charge` reads the reservation's own checkout session first and REFUSES if the merchant offers Boson escrow, pointing you to `facet_buy` (which settles into that escrow). In practice MPP is for x402-native merchants; a Boson-default store like Pecan & Petal is always settled through `facet_buy`. The guard fails closed: if it cannot confirm the merchant is x402-only (for example the reservation was made by a different wallet, so its session is not readable), it refuses rather than risk bypassing escrow.

The flow is two tool calls, and it keeps the same non-custodial invariant and the same DRY-then-confirm discipline as `facet_buy`:

1. Reserve. Call `facet_buy` in DRY mode (omit `settle`) for the cart and shipping address. It creates the UCP checkout, and its result carries `checkout_id`. A UCP checkout session id IS a reservation id, so that value is what MPP charges. (Do not settle the `facet_buy`; you are only using it to hold the priced reservation.)
2. Charge, DRY. Call `facet_mpp_charge` with `terminal` and `reservation_id: <checkout_id>`. It probes the charge endpoint with no credential to draw the 402 challenge, in which the amount, recipient, currency and chain are all server-derived from the reservation and the merchant's own payout row (never anything the client wrote), verifies those terms against the buyer guardrails, and stops. It returns `confirm_atomic` and `confirm_pay_to`. Nothing has moved. Show the user the amount and the recipient.
3. Charge, settle. After the user approves, call `facet_mpp_charge` again with `settle: true`, `confirm: <confirm_atomic>`, and `confirm_pay_to: <confirm_pay_to>`, passing back the exact values the DRY run returned. mppx builds the evm/charge credential (an ERC-3009 authorization whose nonce is bound to this challenge), the wallet signs it locally, and it is resubmitted as `Authorization: Payment`. The result carries the receipt, including the on-chain `reference`.

DRY charge, call `facet_mpp_charge` with:

```json
{ "terminal": "https://<merchant>.facet.llc", "reservation_id": "<checkout_id>", "wallet": "<label>" }
```

Then, after the user confirms the amount AND recipient, settle:

```json
{ "terminal": "https://<merchant>.facet.llc", "reservation_id": "<checkout_id>", "wallet": "<label>", "settle": true, "confirm": "<confirm_atomic>", "confirm_pay_to": "<confirm_pay_to>" }
```

Both `confirm` (the amount) and `confirm_pay_to` (the recipient) must equal what the DRY run just returned, or the settle refuses. The recipient is confirmed as well as the amount because, like the x402-direct rail, the MPP recipient is the merchant's own server-derived payout address and is not escrow-pinned. The escrow guard reads the reservation's session owner-scoped, so it presents the wallet's KYA; the charge credential itself carries no KYA (the reservation id is the capability and the credential moves the signer's own funds, so charging only ever spends the chosen wallet). After settlement, fetch and verify the signed receipt exactly as for any order (see "The receipt").

MPP has no refund or return leg of its own: an MPP charge is an ordinary x402-direct order (its rail is `coin/usdc-base`), so refunds run through the standard path. The settle result carries `order_id`; to refund, call `facet_refund` with `order_id` and `reason` (a REQUEST, no money moves), and the merchant's approve sends the USDC back from its own payout wallet over x402-direct (non-custodial, gasless). There is no escrow and no dispute fallback, which is the same reason the escrow guard above sends any escrow-offering merchant to `facet_buy`: an x402-direct refund depends on the merchant approving it.

## Reordering a past order ("buy that again")

When the user wants to buy a past order again, `facet_reorder` does the legwork: it reads their own order history from the Terminal, then re-prices each item against the store's CURRENT catalog, and hands the result back for a normal, confirmed checkout. It is pure orchestration of calls that already exist (`order_history` then `get_product`), and it adds no new money path: reorder itself settles nothing and buys nothing.

1. Resolve the candidates. Call `facet_reorder` with `terminal` (and optionally `order_id` and `wallet`). Without `order_id` it uses the most recent order; with it, that specific order. For each past line item it reads the CURRENT price and availability, so the user sees today's prices, not what they paid before. A SKU that is gone or out of stock comes back marked unavailable and is skipped, never erroring the whole reorder.

2. Show the user the candidates. Present the available items with their current price (and a note when the price changed since the last order), plus any items that are no longer available. This is a thin confirmation surface, the same as a normal cart, not a rebuilt catalog.

3. Route the purchase through the normal buy flow. Reorder returns the available items as a buy plan; take those SKUs into the ordinary `facet_buy` DRY quote (step 7 of the flow), show the user the real total, get an explicit yes, then settle with `settle: true` and `confirm`. This is the same confirm-then-settle path as any other purchase: one explicit confirmation per settlement, and no auto-buy. Reorder never settles on its own; it only prepares the cart.

Reorder needs the buyer's shipping address at buy time (order history does not carry it), so supply `ship` on the `facet_buy` step as usual. Everything else (the guardrails, the wallet-bound identity, the non-custodial settlement) is identical to a fresh purchase.

## Revising an order before fulfillment ("drop one item, keep the rest")

A buyer sometimes wants to remove one line from a multi-item order that has not shipped yet, and keep the rest. A Boson escrow cannot be partially refunded while it is still committed (the on-chain dispute path that could split it only opens after the order is redeemed), and a cart settles as ONE escrow, not one per line. So "partial cancel before shipping" is not a single move. The non-custodial equivalent is **cancel-and-rebuy**: cancel the whole order for a full refund, then re-buy only the items the buyer is keeping.

`facet_revise` (with `terminal`, `exchange_id`, and `keep`) plans this. Like `facet_reorder`, it is a PLANNER: it returns the two ordered steps and moves no money on its own.

1. **Cancel the whole order.** Step 1 is `facet_cancel` with `exchange_id` and `withdraw: true`: the full escrow returns to the buyer and is cashed back to their wallet in one gasless call, and the signed cancel receipt (a `facet-lifecycle+jws`) is archived. The removed item is now fully refunded along with everything else.
2. **Re-buy the kept items.** Step 2 is an ordinary `facet_buy` with just the `keep` SKUs: run the DRY quote, show the user today's real total, get an explicit yes, then settle. This is a fresh signed purchase and leaves its own settlement receipt. Supply `ship` as usual.

The net effect is the buyer keeps what they wanted, is made whole on the dropped line, and the whole revision is auditable end to end: a signed cancel receipt for the refund and a signed settlement receipt for the new order. Confirm each step with the user before running it; `facet_revise` itself settles nothing.

## After the purchase: redeem, cancel, withdraw, dispute, refund, resolve, receipt

Checkout is not the end. Once a Boson escrow purchase settles, the buyer can act on it, and this skill drives the full escrow lifecycle non-custodially (an x402-direct order has no escrow lifecycle; its recourse is a Terminal `facet_refund` request against the receipt, below). Each Boson action is signed locally and gasless with the buyer's own wallet; the wallet key never leaves the machine, and only the wallet that owns the on-chain voucher can act, so an agent cannot touch an exchange it does not hold the key for. Keep the buy receipt: `exchange_id` is the `settlement_id` it returned, and `order_id` is its order id.

**Read the live exchange state before you claim anything is refundable, cancellable, or disputable.** Never reason from the rail, from memory, or from what an order "should" be: the authoritative fact is each line's on-chain `exchange_state`, and Boson states are monotonic (`Committed`, then `Redeemed`, then `Completed`; or `Canceled` / `Revoked` / `Disputed`). Before proposing ANY redeem, cancel, dispute, or refund flow, call `facet_lines` (`order_id`) and read the target line's `exchange_state`, then gate the action on it:

| `exchange_state` | what the buyer can still do | what REVERTS |
| --- | --- | --- |
| `Committed` | `facet_cancel` returns the full escrow to the buyer, gasless; the dispute-split path needs a redeem first | a dispute on a still-committed line reverts |
| `Redeemed` | the dispute-driven partial split below (`facet_dispute`, then `facet_resolve`, then `facet_withdraw`) | `facet_cancel` and `facet_redeem` revert (already redeemed) |
| `Completed` | the escrow is already released, finalized, and PAID OUT; the only refund left is a merchant-signed send-back opened with `facet_refund` (the merchant approves and sends from their own wallet: the x402 `pay_to`, or a completed-Boson seller treasury). If that line's funds already returned to the buyer, there is nothing to refund, say so plainly | `facet_redeem`, `facet_cancel`, and `facet_dispute` all revert (no committed escrow remains) |
| `Canceled` / `Revoked` | already refunded to the buyer; nothing to do | every escrow action reverts |

If a `facet_refund` reconciles to a DIFFERENT line's existing refund record (for example a cancelled card line), that is a signal the target line is NOT in a refundable state, not a reason to retry with different phrasing: re-read `exchange_state` and tell the user what it actually is. Never claim a line is "still committed" without the `facet_lines` read that proves it, and never propose a redeem-then-dispute flow on a `Completed` line.

**Per-line (multi-item) orders, the deterministic recipe (do this, don't experiment).** A multi-item cart settles as one escrow PER line, so its `settlement_id` is `perline:<n>` and the buy receipt carries an `escrow_lines` array (each line's own `exchange_id` + `sku` + `amount`). That array IS the authoritative line map. To act on the lines: read them with `facet_lines` (`order_id`) or straight from the buy receipt's `escrow_lines` (identical, and `facet_lines` falls back to that archive once the order settles, so it never 404s on a settled `order_id`). To cancel/redeem/dispute ONE line, pass its single `exchange_id` (it auto-routes to the per-line path); for SEVERAL at once, pass `exchange_ids`. Do not first try a pooled single-voucher action and treat its refusal as a dead end, and do not conclude `facet_lines` is broken because a `settlement_id` looks unusual: `perline:<n>` is the normal shape of a per-line order.

- **redeem** (`facet_redeem` with `exchange_id`): the buyer confirming receipt to release the escrow toward the seller, signed locally and gasless. On an order-management-connected store (WooCommerce, Shopify) the buyer usually does NOT need to do this for the seller to be paid: when the merchant marks the order fulfilled or shipped, a fulfillment webhook tells the Terminal to fire the buyer's held redeem automatically (deferred-redeem-on-fulfillment). That held redeem is the one `facet_buy` armed at checkout: it arms every Boson commit, and the webhook has nothing to fire unless a redeem was armed, so on these stores the buyer's release is already set up by the buy itself. Reach for `facet_redeem` to release early ("I already have it, release now"), or on a store with no fulfillment webhook where the buyer's redeem is what moves the escrow. It is the buyer saying "I got what I paid for."
- **cancel** (`facet_cancel` with `exchange_id`, optional `withdraw: true`): before redemption, cancel the order and the full escrow returns to the buyer. The refund lands in the buyer's Boson protocol available-funds first; moving it to the wallet is a separate withdraw. Set `withdraw: true` to do both in one call: the gasless cancel returns the escrow, then the gasless withdraw cashes it out to the buyer's own wallet.
- **withdraw** (`facet_withdraw` with `exchange_id`, optional `amount`, `dry_run: true`): cash a Boson escrow's returned available-funds out to the buyer's own wallet, gaslessly. Signs the buyer's `withdrawFunds` meta-tx locally and a gas-only relayer submits it; `withdrawFunds` is self-binding on-chain, so the funds can only reach the buyer's own wallet. Use it after a plain `facet_cancel`, or standalone whenever available-funds are sitting in the buyer's Boson entity. `dry_run: true` returns the signed request body without posting.
- **dispute** (`facet_dispute` with `exchange_id`, optional `action: raise|retract|escalate`): if something is wrong, raise a dispute into adjudication, then retract or escalate as it proceeds. To settle a disputed order as a partial refund, use `facet_resolve` below.
- **refund** (`facet_refund` with `order_id`, `reason`, optional `items`): open a refund ticket for a settled order. REQUEST only: it opens the ticket and moves no money. The merchant reviews the `reason` and approves, and only the approve moves money, in one of three ways by rail and escrow state. An x402 order (and a completed-Boson leg) sends USDC back from the merchant wallet: on approval the merchant authorizes a gasless send-back from its own payout wallet or treasury in a Coinbase authorization window (signed there, relayed by Facet, so Facet never holds the merchant's key either). A still-committed Boson escrow (the common case, a whole-order refund before redemption) is RELEASED by the approve itself: the Terminal signs the seller revoke, the whole escrow returns to the buyer's Boson available-funds, and `facet_withdraw` cashes it to the wallet, with no `facet_resolve` step. A disputed Boson order (a post-redeem partial) offers a seller-signed `resolveDispute` split the buyer completes with `facet_resolve`. Pass `items` (a JSON array of `{ id, qty }`) for a PARTIAL refund of just those lines, with shipping retained; omit it to request the whole order. Post-delivery returns run here: on an x402 order the send-back settles straight to the buyer once approved.
- **resolve** (`facet_resolve` with `refund_id`, or the explicit `exchange_id` + `buyer_percent_bps` + `seller_sig`): complete a Boson partial-refund split after the merchant approves. When a disputed Boson order is refunded partially, the merchant offers a seller-signed split; this signs the buyer half of the mutual `resolveDispute` locally and gaslessly and submits it. The Terminal validates the split against the merchant's stored offer before relaying, so the buyer can never change the percentage or forge the seller half. Give `refund_id` to auto-read the approved offer from the buyer's own refund ticket, or pass the offer explicitly.
- **receipt** (`facet_get_receipt` with `order_id`): fetch and verify the signed settlement receipt for a settled order, and archive it. Read-only proof, not a fund-moving action; see "The receipt" below.
- **lifecycle-receipt** (`facet_lifecycle_receipt` with `kind` and `exchange_id` or `order_id`): fetch, verify, and archive the signed REVERSAL receipt (typ `facet-lifecycle+jws`) for one of those actions. Read-only; the reversal already happened. `facet_cancel`, `facet_withdraw`, and `facet_dispute` archive their receipt inline, so a reversal leaves the same portable, JWKS-verifiable proof a purchase does; use this to re-fetch one.

Each returns the Terminal's result. These move real funds, so treat them like settlement: confirm the action and the order with the user before running it. The exceptions are `facet_get_receipt` and `facet_lifecycle_receipt`, which only read and verify proof and move nothing. A reversal (cancel / withdraw / dispute) now also carries its own signed lifecycle receipt in its result under `receipt` and in the archive, so a cancelled order no longer reads as "settled" with only a tx hash: it has portable, verifiable proof of the reversal.

### The dispute-driven partial refund (refund one delivered line, keep the rest)

"Revising an order before fulfillment" above is the PRE-fulfillment move: cancel the whole escrow and re-buy the kept items. Once an order has redeemed or fulfilled, that door is closed, but a Boson escrow can still be split down one or more lines through the on-chain dispute path. That makes a post-delivery partial refund (one wilted-flowers line comes back, the rest of the order stays settled) an ordered dispute-then-resolve flow, not a single call. Every step is signed locally and gasless with the buyer's own wallet. Two things about the ORDER are easy to get wrong, so hold them: raising the dispute is a precondition (an escrow that is still committed cannot be disputed, so the split path only opens after redeem), and the buyer's refunded share lands in Boson available-funds, so a withdraw is what finally moves it to the wallet.

Precondition, confirm it before step 1: this flow needs the line currently `Committed` or `Redeemed`. Read the live `exchange_state` with `facet_lines` (the state table under "After the purchase" above), do not assume it. A `Completed` line is PAST this door: its escrow is already released and paid out, so `facet_redeem` and `facet_dispute` both revert, and the only refund left is the merchant-signed send-back opened with `facet_refund`. If the line's funds already returned to the buyer, there is nothing to refund at all.

1. **Release the escrow first.** `facet_redeem` with `exchange_id`, or simply let deferred-redeem fire when the merchant marks the order fulfilled (see redeem above). The dispute path only opens on a redeemed exchange; a still-committed escrow reverts on dispute.
2. **Raise the dispute.** `facet_dispute` with `exchange_id` and `action: raise`. This moves the exchange into the disputed state the split needs.
3. **Request the partial.** `facet_refund` with `order_id`, a plain-language `reason`, and `items` (the `{ id, qty }` lines to refund). This opens the ticket and moves no money; shipping is retained on the kept lines.
4. **Merchant approves (out of band).** The merchant reviews the reason and approves, which records a seller-signed `resolveDispute` split (the buyer's percentage of the escrow, derived by the Terminal from the order's own itemized breakdown) against the ticket. Nothing settles yet, and the buyer runs no command in this step.
5. **Co-sign the split.** `facet_resolve` with `refund_id` (it auto-reads the approved offer from the buyer's own ticket, so no percentage or signature is passed by hand). This signs the buyer half of the mutual `resolveDispute` and submits it; the Terminal validates the split against the merchant's stored offer before relaying, so the buyer can never alter the percentage or the seller half. On success the escrow splits on-chain: the refunded share to the buyer's Boson available-funds, the remainder to the seller.
6. **Cash out the refund.** `facet_withdraw` with `exchange_id` moves the buyer's refunded share from Boson available-funds to their own wallet, gaslessly and self-binding on-chain. The kept lines stay settled to the seller.

The whole flow is auditable end to end: a signed dispute receipt, the on-chain `resolveDispute` split, and the withdraw receipt, each verifiable against the merchant's own keys. Confirm every fund-moving step with the user before running it.

## The receipt: your portable proof

Every settled purchase leaves a signed receipt on the Facet ledger. It is what makes an agent purchase auditable: a compact Ed25519 JWS (RFC 7515) the merchant Terminal signs over the settled order, and that anyone can verify with a stock JOSE library against the Terminal's published keys, with no call back to Facet. A receipt you have to phone the issuer to check is a service; this one is evidence, because verifying it needs only the issuer's public keys.

The receipt JWS is deliberately compact (order, amount, currency, line items). To make the whole cryptographic chain visible, a settled `facet_buy` and `facet_mpp_charge` also return a `provenance` block: the buyer KYA's identity (`aid` / issuer / expiry, decoded from the token, never the raw bearer); the payment leg (on Boson, the buyer's ERC-3009 token authorization plus the seller's offer signature; on x402 / MPP, the ERC-3009 authorization and signature); the settlement chain (checkout, order, settlement id); and whether the signed receipt verified offline against the merchant's JWKS. It notes the one leg it cannot show, the platform's RFC 9421 co-signature, which the Terminal records server-side in its own signatures ledger that no buyer endpoint exposes.

A settled `facet_buy` returns it inline under `receipt`, and `facet_get_receipt` (with `order_id`) re-fetches it for any past order (re-authorizing with the paying wallet if the original short-lived buyer identity has expired). The `receipt` object carries the compact JWS (`jws`), the signing key id (`kid`), `verified` (true or false), and the decoded `claims`. What the claims attest:

- `iss` : the merchant Terminal that issued and signed it (the host you transacted with).
- `sub` : your agent identity (the KYA `aid` that made the purchase).
- `jti` : the order id. One receipt per order.
- `settlement` : `{ rail, amount_minor, currency, settled_at, livemode }`, the money that actually moved.
- `chain` : `{ this_hash, prev_hash }`, this order's link into Facet's tamper-evident, hash-chained ledger.
- `attestations` : counterparty signatures (`{ party, says, signed_at }`). Empty right after a fresh buy and NOT a negative signal; merchant and agent countersignatures accrue over time, and re-fetching with `facet_get_receipt` picks them up.
- `split` (when recorded) : `{ goods_minor, tax_minor, shipping_minor, duty_minor, discount_minor }`.

How `verified: true` is reached: decode the compact JWS, confirm the header `typ` is `facet-receipt+jws` and `alg` is `EdDSA`, confirm the signed `iss` is the exact Terminal host you bought from, fetch that host's `/.well-known/jwks.json`, and verify the Ed25519 signature with the key named by `kid`. The trust anchor is the host you transacted with, never the receipt itself: the receipt's own `provider_jwks` hint sits outside the signature and is ignored, so a receipt can never nominate the key that would validate it. The skill does all of this in `verifyReceipt`; a third party runs the same checks with any JOSE library. See [references/receipt-verification.md](references/receipt-verification.md).

Receipts are also archived, tracked like wallets. Every receipt a settled `facet_buy` or `facet_get_receipt` fetches is written to a durable folder (default `~/.facet/receipts`, override `FACET_RECEIPTS_DIR`): one `<order_id>.json` per order holding the full signed JWS, the decoded claims, and the verified flag, plus an `index.jsonl` that `facet_receipts` lists. This is automatic; the buy or receipt output reports `saved: true` and `saved_path`. Saving needs the server's write grant to that folder (already in the standard launch); without it the receipt is still fetched and verified and the output shows `saved: false` with a note. When a user asks about their past purchases, list the archive with `facet_receipts` rather than re-fetching each order.

When a purchase settles, tell the user their order is receipted and, in one line, what the proof says (the amount, the rail, and that it verifies against the merchant's own keys). Then tell them what protection the order ACTUALLY has, straight from the result's `buyer_protection`, and never over-promise escrow. A Boson escrow order (the WooCommerce default) holds the funds and releases on fulfillment: the buyer can `facet_cancel` before it ships for a full refund, or `facet_dispute` after. An x402-direct order (the Shopify default) is the merchant's money on settlement, NOT held in escrow and not ship-gated, so its recourse is to come back and open a Terminal request against the receipt: `facet_refund` (with `order_id` and `reason`; whole-order, or `items` for specific lines), a REQUEST the merchant reviews and approves in a Coinbase authorization window, signing a gasless send-back from its own payout wallet (non-custodial; Facet never holds the merchant's key). Relay `buyer_protection.recourse` rather than assuming escrow; escrow is only half the network. On a deferred-settlement escrow rail the anchor may appear a moment later; if `receipt.available` is `false`, call `facet_get_receipt` (with `order_id`) shortly after. A receipt that returns `verified: false` is worth surfacing plainly with its `reason`, never hiding.

### Showing a detailed, shareable receipt view

There is ONE official way to render a receipt: `facet_render_receipt` (with `terminal` and `order_id`). It fetches and verifies the receipt, embeds the merchant's Ed25519 public key, fills the canonical template at `references/receipt-template.html`, and writes a self-contained, self-verifying HTML page (default under the receipts archive; `out` to place it). Open it in a browser and the verify seal runs a real in-browser Ed25519 check; every field is derived from the embedded signed JWS, and the identity, payment, and verification provenance chain renders when it is available (from the archive a settled `facet_buy` wrote, or an explicit `provenance_file`). Optional `merchant_name` / `merchant_location` / `order_url` set the masthead and the order link. Line items (name, SKU, quantity) are read from the buyer's own order history when available; without them, the receipt shows the money breakdown alone. Use this whenever the user wants a receipt they can look at or share; do not hand-roll a one-off page, and do not just dump JSON. The page is what it shows:

- the order and the money: order id, rail, amount and currency, settled-at, live mode, the line items (name, SKU, quantity) when available, and the goods / tax / shipping / duty / discount split;
- the buyer identity and payment provenance: the KYA `aid` and issuer, and the buyer's own signature moving the funds (the ERC-3009 token authorization plus the seller signature on Boson, the ERC-3009 authorization on x402);
- the full authorization trail (server-recorded): every credential the Terminal verified across the purchase, read back at render time over the owner-scoped `get_signatures` endpoint: the KYA by hash, the UCP RFC 9421 platform signature, the ERC-3009 payment authorization, the seller offer, and a count of Facet's own Ed25519 response signatures and counterparty attestations. Shown in the reveal; omitted when the endpoint is unavailable, and the KYA is never returned in cleartext;
- who signed it: the merchant Terminal (`iss`), the signing key (`kid`), the algorithm, and the checkout origin;
- the tamper-evident ledger link: this order's `this_hash` and the `prev_hash` before it;
- the signed proof: the raw compact JWS with its decoded header and payload, and a JOSE snippet to reproduce the check anywhere;
- and, front and center, the verification verdict, checked live against the merchant JWKS with no call back to Facet.

For the underlying fields, the `receipt` object and its archived `<order_id>.json` hold everything the view shows, laid out as checkable rows:

- the order and the money: `jti` (order id), `settlement.rail`, `amount_minor` + `currency`, `settled_at`, `livemode`, and, when recorded, the `split` (goods, tax, shipping, duty, discount);
- who signed it and the on-chain trail: `iss` (the merchant Terminal), `kid` (the signing key), and the settlement's on-chain reference, the Boson `exchange_id` or the x402 transaction the `settlement` correlates to, so the actual tx hash is visible;
- the tamper-evident ledger link: `chain.this_hash` and `prev_hash`, this order's place in the hash chain;
- the counterparty `attestations` (`party`, `says`, `signed_at`) as they accrue;
- and, front and center, the verification verdict: that the compact JWS verifies as `facet-receipt+jws` / `EdDSA` against the merchant Terminal's published JWKS, offline, with no call back to Facet.

The point of the view is that every row is checkable evidence, not a claim: the raw JWS stays right there so the reader (or any third party) can re-run the exact verification with a stock JOSE library. Offer this rendered view whenever the user wants a receipt they can look at or share, and point them at the archived `<order_id>.json` as the durable copy.

**A reversal amends the original receipt, in place, not a separate page.** After a cancel, withdraw, refund, or dispute, RE-RENDER the ORDER's settlement receipt with `facet_render_receipt` (the same `order_id`). The original signed settlement is preserved untouched, and an **Amendments** section is added below it showing the reversed line(s), the amount returned, a **Net now** total, and each reversal's own signed lifecycle receipt (the compact `facet-lifecycle+jws`, embedded and verifiable in-browser) recorded inline. It builds this from the order's archived escrow lines plus the archived `lifecycle-<kind>-<handle>.json` receipts, so it works AFTER the order has settled with no live call. ALWAYS re-render and hand over the amended receipt right after a reversal, exactly the way you render one after a purchase (see the always-render rule): never generate a separate reversal page, and never ask first. The durable copies are the archived `<order_id>.json` (the settlement + its escrow lines) and each `lifecycle-<kind>-<handle>.json` (a reversal's signed proof).

## Safety rules (non-negotiable)

- Non-custodial, always. The wallet key signs locally and never leaves the machine. If any step would send a raw private key anywhere, stop; it is a bug.
- Checkout is the signed rail, never a web form. The native browser is for browsing and selection ONLY; never use it to check out. Do not add to the store's cart, do not open the store's checkout, and never type a card or touch a pay button (Google Pay, and the like) on the merchant's page. The only checkout is the Facet Terminal's signed UCP session, run through `facet_buy`.
- DRY first, every time. Never set `settle: true` until you have run a DRY `facet_buy`, shown the user the exact total, and gotten an explicit yes for that specific purchase.
- One confirmation per settlement. A yes for one purchase is not a yes for the next. Re-confirm each cart.
- Never handle the secrets yourself. Do not read, print, echo, or pass `FACET_KYA` or `FACET_WALLET_KEY` as a tool argument. They live in the environment; the child helper reads them.
- Respect the guardrails. The helper refuses a checkout that is not on the expected chain, or whose price exceeds the cap (default 25 USDC; raise with `max_usdc` only when the user's cart genuinely needs it and they have confirmed), or that the wallet cannot cover. Relay a refusal to the user; do not try to bypass it.
- Money is Base USDC. Settlement is real USDC on Base. Treat every settle as spending real money.
- The full agent-behavior safety layer, external content treated as data, what the agent will not buy, purchase intent and authority, identity and privacy, advice limits, and refusals, is in [references/safety.md](references/safety.md). These rules summarize it; that document is the behavioral contract. The terms, acceptable use, and data-handling policy is in [references/legal.md](references/legal.md).

## Identity and wallet-bound checkout

Many Facet stores tie identity to the paying wallet: they require the checkout to present a KYA bound to the exact wallet whose USDC moves. A plain KYA that is not bound to the paying wallet is rejected before any money moves. The helper handles this by default: after the wallet is chosen it self-serve mints a wallet-bound KYA from the Facet issuer (`issuer.facet.llc`, the default trusted issuer) by proving control of that wallet, so no pre-set token is needed. Set `FACET_KYA` yourself only to pin a specific trusted, wallet-bound identity for the same address behind `FACET_WALLET_KEY`.

Some production stores also require a co-signature from the shopping platform itself, on top of the buyer's own identity and payment. A caller that authenticates with only its own KYA and wallet cannot supply that co-signature. Against such a store this helper browses and prices a cart (DRY), then reports plainly that the store will not settle a buyer-only checkout; it does not retry or try to route around the rejection. Where a store does accept a buyer-only checkout, settlement proceeds normally. Either way the buyer's key stays local and the flow is non-custodial.

## Getting a wallet (for a walletless user)

A user with no wallet is not stuck: they can mint one here and start shopping in three steps, no exchange account or manual seed-phrase setup required. Think of the wallet as a capped spend instrument, a prepaid card the user tops up with only what they mean to spend.

1. Mint it. Call `facet_wallet_new` (add `label` for a second wallet). It generates a fresh recovery phrase, derives the wallet, and stores the private key securely: the macOS keychain first, or an AES-256-GCM encrypted keystore under `~/.facet/keys` (off any synced folder), protected by a passphrase the user sets at a no-echo prompt. The recovery phrase is shown ONCE, on stderr, with a write-it-down warning. Relay that to the user and tell them to record it offline: it is the only backup and it will not be shown again. The private key and the phrase never reach a tool result or a log; the result carries only the public address, the label, where the key was stored, and a fund hint.

2. Fund it. Call `facet_fund` with `await_funding: true` (optionally `min_usdc`). It prints the wallet's address and watches its USDC-on-Base balance, reporting when funds arrive. Give the user the address and have them send USDC on Base to it (an exchange withdrawal to Base, a transfer from another wallet, anything). Only USDC on Base counts toward the balance.

3. Shop. Once funded, the minted wallet behaves exactly like an env-configured one: `facet_wallet_list` lists it, and `facet_provision`, `facet_search`, and `facet_buy` sign with it, all selected by `wallet` (the label). The user never exports `FACET_WALLET_KEY`. When that variable is unset, the helper loads the key from the keychain or the encrypted keystore (prompting for the keystore passphrase) for the single moment it signs, then drops it. This is exactly as non-custodial as the env path: the key stays on the machine and only a signature ever leaves the process.

The wallet as a capped spend instrument: fund it with what the user plans to spend, not their whole balance. Every `facet_buy` is still bounded per order by `max_usdc` under an absolute ceiling (the default cap applies unchanged, and a garbage value can never disable it); a per-session cap is a separate Terminal-side control, not something this skill sets.

Onboarding runs through two tool calls: `facet_wallet_new` (optionally `label`), then `facet_fund` with `await_funding: true`. The server launches the child with the grants these need: a write scoped to `~/.cache` and `~/.facet`, and, for the macOS keychain tier, run access (to call `security`). Without run access the keychain tier is skipped and the encrypted keystore is used instead. Never pass the private key, the passphrase, or the recovery phrase as an argument: the child reads the passphrase from a no-echo prompt and the key from its secure store, and nothing secret is ever an argument.

## Getting a KYA (identity)

The helper mints the KYA for you, self-serve, and does so by default. `facet_provision` (and `facet_buy` on demand) mints a wallet-bound KYA from the Facet issuer (`issuer.facet.llc`, the default trusted issuer) using the chosen wallet: it enrolls a fresh identity key, then the wallet signs a challenge locally so the issuer binds the KYA to that wallet. No issuer service key is involved and the wallet key never leaves the process. Stores advertise which issuers they trust in the `kya_issuers` field from `facet_discover`.

- This needs no setup beyond `FACET_WALLET_KEY`. Reach for `facet_provision` to pre-mint, or let `facet_buy` mint on demand.
- If the user already holds a KYA from an issuer the store trusts, they set it as `FACET_KYA` and it is used as-is; a stale or untrusted one is skipped and a fresh wallet-bound one is minted instead.
- Wallet-bound identity is required on stores that tie identity to the payer (see "Identity and wallet-bound checkout" above): the KYA must be bound to the exact address behind `FACET_WALLET_KEY`. The self-serve mint produces exactly that.

## Honest scope

This skill exists to guide the agent through Facet identity and checkout: discovering the Terminal, the KYA handshake, quoting the cart, and settling on the signed rail. It is deliberately not a human-facing shopping experience. Browsing the storefront, rendering products, and helping the user choose belong to the host assistant (Claude, ChatGPT, Gemini) and its own web browsing; this skill takes the cart the user approved and completes the purchase on the Facet rail.

- Selection leans on the client's own web browsing of the merchant's real storefront and on the Facet directory. This skill does not rebuild the catalog; where neither the browser nor the Terminal `facet_search` is available, `facet_browse_storefront` returns a lean public list.
- Settlement rides the merchant's DEFAULT rail, set by the merchant's OMS (Facet's rail-split): Shopify stores default to x402-direct on testnet and mainnet (the buyer's ERC-3009 settles straight to the merchant's payout wallet, no escrow); WooCommerce stores default to Boson escrow (buyer protection: funds sit in escrow, not straight to the merchant). This reference client settles BOTH rails: it settles the merchant's own default rail (the checkout's `default_rail`), so a WooCommerce store's Boson escrow default is honored and never silently downgraded to x402-direct, signing a Boson commit for an escrow offer or an ERC-3009 TransferWithAuthorization for an x402-direct offer, always with the buyer's own wallet and the same hard guardrails on the server-advertised terms (recipient, chain, EIP-712 domain, USDC token, amount cap). `FACET_RAIL=x402` or `FACET_RAIL=boson` forces a rail; the default (`auto`) follows the checkout's `default_rail`, preferring Boson escrow (buyer protection) when a store advertises both without a stated default. The escrow lifecycle below (redeem, cancel, dispute) applies to Boson orders; an x402-direct order has no escrow and reverses through `facet_refund` instead.
- Some stores require a co-signature from the shopping platform that a buyer-only install cannot supply. Against those, the helper browses and prices but does not settle, and says so (see "Identity and wallet-bound checkout").
- It targets Base mainnet USDC by default. The chain, token, and cap are overridable through environment variables for advanced or test use, but the safe defaults are mainnet.
- Its job is the checkout rail, not the shopping UI. Selection happens in the host assistant's own browser; this skill carries the approved cart into checkout. It also drives the post-purchase lifecycle (redeem, cancel, dispute, refund; see "After the purchase"). Order tracking beyond those states is a separate Facet surface.

## License

Apache-2.0. Copyright 2026 Facet, LLC. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
