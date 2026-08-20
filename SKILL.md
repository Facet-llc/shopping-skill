---
name: shopping
description: Shop any Facet-enabled website and buy on the user's behalf using the user's OWN agent identity (a self-issued, wallet-bound Facet KYA) and their OWN self-custodied wallet, non-custodially. Trigger when the user says "go shopping", or asks to shop, browse, or buy from a named store or site, add items to a cart, or check out somewhere that runs a Facet Terminal, or to redeem, cancel, dispute, refund, fetch and verify the signed settlement receipt for a past Facet order, or list saved receipts. Browses the merchant's human-facing site first; only when it discovers the site is agent-ready does it alert the user, offer agent checkout, and ask which of the user's own wallets to pay from. Checkout runs on the signed, agent-native rail (a UCP checkout session, on-chain USDC on Base) that the user confirms before any money moves. Never types a card into a merchant's web form.
---

# Shopping on a Facet-enabled store

This skill lets you shop a website for the user and complete a real purchase, end to end, without any middleman ever holding their money or their keys. The purchase is what makes it a skill; the browsing is just how the user picks.

## Non-custodial, and the open rail (read first)

This skill signs a payment with the user's wallet key, so the trust model comes first. The key is read from the environment, signs locally inside the Deno helper, and is never transmitted, logged, or written to disk; only the resulting signature leaves the process. Funds settle on-chain straight from the user's wallet into the merchant's escrow or, on the x402-direct rail, straight to the merchant's own payout wallet, so no Facet server ever holds the money or the key. Which rail is the merchant's default is set by the merchant's OMS (Facet's rail-split): Shopify stores default to x402-direct on both testnet and mainnet, and WooCommerce stores default to Boson escrow. The identity is a wallet-bound Facet KYA the user self-issues by proving control of the wallet, with no issuer service key anywhere in this skill.

These scripts are an auditable reference client for an open, published rail (agents.txt, the Facet KYA, the UCP checkout, x402 over HTTP-402, ERC-3009 on USDC, RFC 9421), and a fallback for agents that cannot sign on their own, not a required intermediary. For depth, one level down: [references/architecture.md](references/architecture.md) for the flow and rails, [references/security-model.md](references/security-model.md) for the threat model and every guardrail, and [references/troubleshooting.md](references/troubleshooting.md) for the error taxonomy, and [references/legal.md](references/legal.md) for terms, acceptable use, and data handling.

## The two surfaces (read this first)

"Shopping" hides two different jobs behind one word, and they call for opposite tools.

- Discovery and selection: finding the store, seeing what it sells, picking items. The best front end for this is the client's OWN web browsing on the merchant's real storefront, the same pages a person sees. Do not rebuild the merchant's catalog into a panel; their own site renders it better than anything this skill could assemble, and the catalog is not the moat. Trim your instinct to reconstruct a shopping mall in the chat.
- Checkout and settlement: identifying as the buyer, paying, getting a receipt. This is the whole point of the skill, and it runs on Facet's signed, agent-native rail: a UCP checkout session, a KYA-bearer identity, a non-custodial on-chain settlement, and a signed receipt. It NEVER means typing the user's card into the merchant's human checkout form in a browser tab. That would expose their card, carry no verifiable agent identity, and leave no provenance. The signed rail is strictly higher trust, and it is what "check out through Facet" means.

The mental model is Apple Pay. The merchant's storefront is the web page you browse (keep it, do not rebuild it). The little "agent checkout" badge on the page is the "Buy with Apple Pay" button. How the phone knows that button is real is the Facet directory plus the store's own `agents.txt`. And the Apple Pay rail itself, the part that moves money without ever handing the merchant a card, is the Facet Terminal.

Non-custodial by construction: the user's wallet key signs the payment inside a local helper process and never leaves the machine. Funds move straight from the user's wallet into the merchant's escrow. Nothing sits with a third party.

## When to use this

Trigger on natural intent, not just the exact words:
- "go shopping", "shop at acme.com", "buy the birthday bundle from that flower store"
- "add two of those to my cart", "check out", "what does this store sell?"

If the user names a site, start there. If they say "go shopping" with no site, either ask which store or use the directory (below) to find Facet-enabled merchants that fit what they want.

## One-time setup (tell the user once, then proceed)

The user provides two things through their environment. You never type, echo, or pass either value as a command argument.

1. Deno (the helper runtime). If missing, point them to https://deno.com. Nothing else installs; the helper pulls its two dependencies (a wallet signer and the escrow client) on first run.
2. Two environment variables in their shell (a profile export, or a local env file they source):
   - `FACET_KYA` (optional) : a Facet KYA, an ES256 bearer token from an issuer the store trusts, used as the agent identity for directory search and checkout. If it is absent, expired, or from an untrusted issuer, the helper self-serve mints a fresh wallet-bound KYA from the Facet issuer using `FACET_WALLET_KEY` (see "Getting a KYA"). Set it only to pin a specific identity.
   - `FACET_WALLET_KEY` : their wallet private key (`0x` + 64 hex). It signs the payment locally and is never transmitted. Ideally this is the SAME wallet their KYA is bound to (see "Getting a KYA" below). No wallet yet? The user can mint one with `wallet new` and skip this variable entirely (see "Getting a wallet (for a walletless user)" below); the minted wallet is then used automatically by label.

A walletless user is not a dead end: instead of asking them to produce a key, guide them through "Getting a wallet (for a walletless user)" below (`wallet new`, then `fund`). For any other missing variable the helper returns a clear error; relay it and ask the user to set it, and never try to work around a guardrail.

More than one wallet (optional): a user who shops from several wallets can register them by setting `FACET_WALLETS` to a JSON array, one entry per wallet, for example:

    [{"label":"personal","key_env":"FACET_WALLET_KEY","kya_env":"FACET_KYA"},
     {"label":"business","key_env":"FACET_BIZ_WALLET_KEY","kya_env":"FACET_BIZ_KYA"}]

Each entry names the env vars that hold that wallet's key and KYA; the values themselves stay in the environment and are never written into the registry. With no `FACET_WALLETS` set, the single default wallet (`FACET_WALLET_KEY` + `FACET_KYA`) is used. You never need a key to list or pick a wallet: the `wallets` subcommand shows each wallet's label, address, and balance so the user can choose.

## The tools

These tools do the work, and they stay in their lanes.

- Your native browser is the DEFAULT and required way to see a storefront: on any shopping request, open the store in the real, visible browser you can drive and navigate it live so the user watches (to the category, the products, an item's page). Do not present a link the user must click, an "open in your browser" card, or a headless read as the way the user sees the store, and never lead with the Terminal. See "Browsing the storefront" under the flow.
- `scripts/facet-checkout.ts` is the identity-and-money path: `wallet new`, `wallets`, `fund`, `directory`, `discover`, `search`, `product`, `provision`, `buy`, `mpp-charge`, `reorder`, `receipt`, `render-receipt`. It reads the wallet key and KYA from the environment (the `FACET_WALLETS` registry, or the default `FACET_WALLET_KEY` plus `FACET_KYA`), so never put a secret on the command line.
- `scripts/kya-provision.ts` is the self-serve identity minter used by `provision` and by `buy` on demand: it enrolls a fresh identity key and mints a wallet-bound KYA from the Facet issuer with NO service key, then caches it for reuse. It never prints the token.
- `scripts/browse-storefront.ts` is a LAST-RESORT fallback reader for the rare case where the client cannot browse the site AND the Terminal's own `search` is unavailable. It reads a store's public catalog into a lean list. No secrets, no rendering, no panel.

The product SKU is the join key from selection to checkout: a storefront `sku` is the same string as the Terminal product `id`. You pick by SKU and you buy by SKU.

Run the scripts with Deno from your Bash tool, using this skill's base directory as `$SKILL` (the absolute path shown in this skill's header when it loads). Each prints ONE JSON object to stdout per call; parse that. Progress notes go to stderr. The `--allow-write` grant is what lets `provision` cache the minted KYA under `~/.cache/facet`, so `search`, `product`, and `buy` reuse it instead of re-minting; omit it and each identity-gated call re-mints (correct, just slower). `wallet new` and `fund` (and any command resolving a wallet minted by `wallet new`) also touch the encrypted keystore and the wallet index under `~/.facet`, so grant `--allow-write="$HOME/.cache,$HOME/.facet"` for those; the macOS keychain tier additionally needs `--allow-run` (to call `security`), and without `--allow-run` the encrypted keystore is used instead. The `~/.facet` grant also lets every fetched settlement receipt be archived under `~/.facet/receipts` (see "The receipt"); omit it and receipts are still fetched and verified, just not saved.

### facet-checkout.ts (reads secrets from env)

```bash
deno run --allow-env --allow-read --allow-write="$HOME/.cache,$HOME/.facet" --allow-net "$SKILL/scripts/facet-checkout.ts" <subcommand> [flags]
```

- `wallet new [--label <name>] [--keystore] [--force]` : mint a fresh wallet for a walletless user. It generates a recovery phrase, derives the wallet, and stores the private key securely (macOS keychain first, else an AES-256-GCM encrypted keystore under `~/.facet/keys`). The recovery phrase is shown ONCE on stderr with a write-it-down warning; the phrase and the private key are NEVER printed to stdout, returned, or logged. stdout carries only the public address, the label, where the key was stored, and a fund hint. Refuses to overwrite an existing label without `--force`; `--keystore` forces the encrypted-keystore tier. See "Getting a wallet (for a walletless user)" below.
- `wallets` : list the user's configured wallets so they can choose which to shop with. For each it shows the `label`, the derived `address`, the `usdc_balance` on Base, and whether a KYA is present. It reads only the user's own env (the `FACET_WALLETS` registry, or the single default wallet); it never derives or displays a key, and it has no knowledge of any wallet the user did not configure. Run this FIRST, before searching, then pass the chosen `--wallet <label>` to the other subcommands. A wallet minted by `wallet new` appears here too (listed from its public address, with no key load or passphrase prompt).
- `fund [--label <name>] [--await] [--min-usdc <n>]` : show the wallet's address and current USDC-on-Base balance so the user can send funds. With `--await` it polls (progress on stderr) until the balance is positive (or reaches `--min-usdc`), then reports funded. It loads no key and moves no money; it just watches the address. USDC on Base only.
- `directory --query <q> [--near "<lat>,<lng>"] [--radius-km N] [--capabilities a,b] [--taxonomy a,b] [--min-reputation N] [--claimed-only] [--limit n] [--wallet <label>]` : search the Facet directory across the network to find merchants that fit, and see which ones have a live Terminal. Needs at least one filter and a valid KYA (the directory is identity-gated); `--wallet <label>` selects which configured wallet's KYA to present. Returns `{ ok, count, with_terminal, total_estimate, next_offset, results }`; each result carries `name`, `address`, `reputation`, `capabilities`, and a `terminal_url` that is non-null exactly when that merchant has a live Terminal.
- `discover --site <host>` : resolve ONE host's `agents.txt` (unauthenticated, no identity needed). This is the authoritative "does THIS store have a Terminal, and where" check. Returns `terminal`, `kya_issuers`, `commerce_rails`, `capabilities`, and, when the host serves the Machine Payments Protocol (mpp.dev), `mpp_endpoint` / `mpp_method` (`evm/charge`) / `mpp_auth` (`payment-scheme`). If the site is not Facet-enabled it returns `{ ok:false, facet_enabled:false }`.
- `search --terminal <url> [--query q] [--category c] [--tags a,b] [--limit n] [--wallet <label>]` : the Terminal's own transaction catalog (lean: ids, pricing, stock, no images). Use it to confirm a SKU is purchasable on the rail, or as a selection source when the client cannot browse the storefront. `--wallet <label>` selects which wallet's KYA authenticates the call.
- `product --terminal <url> --id <product_id> [--wallet <label>]` : one product's rail detail.
- `provision [--wallet <label>]` : self-serve mint a wallet-bound KYA for the chosen wallet from the Facet issuer (`issuer.facet.llc`), with NO issuer service key. The wallet signs a challenge locally (never transmitted); the issuer binds the KYA to that wallet. The token is cached and used automatically by `search` and `buy`; it is never printed. `buy` also does this on demand, so you rarely call `provision` directly.
- `buy --terminal <url> --items '<json>' --ship '<json>' [--gift-message "..."] [--delivery-date YYYY-MM-DD] [--occasion "..."] [--shipping-email <addr>] [--max-usdc N] [--wallet <label>] [--settle --confirm <atomic> --confirm-pay-to <addr>]` : the checkout, signed and paid from the chosen `--wallet`. On the x402-direct rail, `--settle` also requires `--confirm-pay-to <addr>` matching the recipient the DRY run returned as `confirm_pay_to` (that rail settles straight to a per-merchant, server-advertised address that is not escrow-pinned, so the recipient is confirmed like the amount); the Boson escrow rail pins its recipient and needs only `--confirm`. The gift and delivery flags are applied to the merchant order at settlement. When the buyer opted into shipping confirmations (see `email-pref`), the stored throwaway email rides `order_attributes.contact_email` automatically; `--shipping-email <addr>` overrides it for one purchase without changing the stored default. Every buy result carries `shipping_email_pref` (`unset` | `opted_in` | `opted_out` | `override`) so you know whether to ask. See "Buying" and "Shipping confirmations" below.
- `mpp-charge --terminal <url> --reservation-id <id> [--max-usdc N] [--wallet <label>] [--settle --confirm <atomic> --confirm-pay-to <addr>]` : pay a held reservation through the Machine Payments Protocol (mpp.dev) charge envelope, for an mpp.dev-native flow. MPP is NOT a separate rail: it is the same on-chain x402 settlement re-dressed in mpp.dev's challenge / credential / receipt shape, so an mpp.dev-native agent can pay a Facet order without Facet-specific checkout code. Reserve first: run `buy` in DRY mode and use its `checkout_id` (a UCP checkout session id is a valid reservation id), then pass it as `--reservation-id`. Because MPP settles x402-direct (no escrow), it must NOT stand in for an escrow checkout: BEFORE charging, it reads the reservation's own checkout session and REFUSES (`reason: escrow_available_mpp_refused`) if the merchant advertises Boson escrow, sending you to `buy` instead (no bypassing escrow). It also fails closed if it cannot confirm the merchant is x402-only. DRY by default: it probes the charge endpoint with no credential, reads the server-derived challenge (amount, recipient, currency, chain, none of them client-set), verifies it against the same guardrails as `buy` (chain, USDC, the per-checkout cap), and stops, returning `confirm_atomic` and `confirm_pay_to`. Nothing moves. `--settle` requires `--confirm <atomic>` matching that amount AND `--confirm-pay-to <addr>` matching that recipient (the MPP recipient is the merchant's own server-derived payout, not escrow-pinned, so it is confirmed like the x402-direct recipient); then mppx builds the evm/charge credential (an ERC-3009 authorization whose nonce is bound to the challenge), the wallet signs it LOCALLY, and it is resubmitted. The receipt (with the on-chain reference) is returned. The escrow guard reads the session owner-scoped, so it presents the wallet's KYA; the charge credential itself carries no KYA (the unguessable reservation id is the capability and the credential moves the signer's OWN funds). See "Paying through MPP" below.
- `email-pref set <address>` | `email-pref set --none` | `email-pref show` : record the buyer's throwaway shipping-email choice ONCE so you never ask again. `set <address>` opts in and stores the address; `set --none` opts out (stored, so you stop asking); `show` prints the current preference as JSON. Stored as plain, non-secret JSON under `~/.cache/facet/order-prefs.json` (never the `~/.facet` keystore). The address is buyer-provided and non-secret, so it may ride the command line. See "Shipping confirmations" below.
- `redeem --terminal <url> --exchange-id <id> [--wallet <label>]` : confirm receipt to release the escrow toward the seller. Signs a Boson redeem meta-tx locally (gasless). On an OMS-connected store the merchant marking the order fulfilled fires this automatically (deferred-redeem-on-fulfillment), so it is usually optional for the buyer; reach for it to release early. `--exchange-id` is the `settlement_id` from the buy receipt. See "After the purchase" below.
- `cancel --terminal <url> --exchange-id <id> [--wallet <label>] [--withdraw] [--amount <atomic>]` : cancel a committed order before redemption; the full escrow returns to the buyer's Boson protocol available-funds. Signs a Boson cancelVoucher locally (gasless). Add `--withdraw` to also cash the returned escrow out to the buyer's own wallet in the same call (a gasless Boson withdrawFunds); `--amount <atomic>` overrides the withdrawn amount (default: the full available balance).
- `withdraw --terminal <url> --exchange-id <id> [--wallet <label>] [--amount <atomic>] [--dry-run]` : cash a Boson escrow's returned available-funds out to the buyer's OWN wallet, gaslessly. After a cancel (or a seller revoke) the escrowed USDC sits in the buyer's Boson protocol available-funds; this signs the buyer's `withdrawFunds` meta-tx locally and a gas-only relayer submits it. `withdrawFunds` is self-binding on-chain, so the funds can only go to the buyer's own wallet. `--amount` overrides the atomic amount (default: the full balance); `--dry-run` gathers, signs, and returns the exact request body WITHOUT posting, for inspection before a real cash-out.
- `dispute --terminal <url> --exchange-id <id> [--action raise|retract|escalate] [--wallet <label>]` : raise (or retract or escalate) a dispute into adjudication. Signs the Boson dispute meta-tx locally. To complete a partial-refund split, use `resolve` (it carries the seller's counter-signature).
- `refund --terminal <url> --order-id <id> --reason "<why>" [--items '<json>'] [--wallet <label>]` : open a refund ticket for a settled order. REQUEST only, no money moves: the merchant reviews the `--reason` and approves, and only the approve moves money. What it does depends on the rail and escrow state: an x402 order sends the USDC back from the merchant wallet; a still-committed Boson escrow is RELEASED by the approve itself (the Terminal signs the seller revoke, the whole escrow returns to the buyer, then `withdraw` cashes it to the wallet, with no `resolve` step); a disputed Boson order (a post-redeem partial) offers a seller-signed resolveDispute split the buyer completes with `resolve`. `--items` is a JSON array of `{ id, qty }` (the same SKUs as `buy`) for a PARTIAL refund of just those lines, with shipping retained; omit it to request the whole order. The rail is chosen at the merchant's approve from live on-chain state. On a store that gates the refund request behind a platform co-signature (a dual-auth money path), the request authorizes itself autonomously: the client signs a single-use, order-bound wallet attestation locally (only the signature leaves the process), which the Terminal verifies against the buyer's wallet-bound KYA before opening the ticket. This lets a buyer-only client open the ticket with no platform in the loop, the refund analogue of the buyer-signed meta-tx on `cancel` and `dispute`; a single-factor store ignores the attestation. The attestation is signed for you, so no extra flag is needed.
- `resolve --terminal <url> ( --refund-id <id> | --exchange-id <id> --buyer-percent-bps <n> --seller-sig <hex> ) [--wallet <label>]` : complete a Boson partial-refund split after the merchant approves. Signs the buyer half of the mutual `resolveDispute` locally (gasless) and submits it; the Terminal validates the split against the merchant's stored offer, so the buyer cannot alter the percentage or the seller half. `--refund-id` auto-reads the approved offer from the buyer's own refund ticket (`get_refund`); or pass the offer explicitly.
- `reorder --terminal <url> [--order-id <id>] [--limit <n>] [--wallet <label>]` : buy a past order again. Reads the user's own order history (owner-scoped to their identity at the Terminal), then for each past item reads the CURRENT price and availability from `get_product`, and returns the reorder candidates. It settles nothing on its own and buys nothing on its own: the actual purchase runs through the same `buy` flow (DRY, explicit confirmation, then `--settle`). A SKU that is gone or out of stock is marked unavailable and skipped, never fatal to the reorder. Without `--order-id` it uses the most recent order; with it, that order. See "Reordering a past order" below.
- `revise --terminal <url> --exchange-id <id> --keep '<json>' [--wallet <label>]` : plan a change to a multi-item order BEFORE it ships. Boson cannot partially refund a committed escrow, so the non-custodial equivalent is cancel-and-rebuy: cancel the WHOLE order (the full escrow refunds, cashed back to the wallet with `--withdraw`) then re-buy only the kept items. Returns the two-step plan (the exact `cancel` and `buy` commands to run) and moves NO money on its own, exactly like `reorder`. `--exchange-id` is the escrow to cancel; `--keep` is a JSON array of `{ id, qty }` for the items to keep. Each leg leaves a signed receipt (the cancel a `facet-lifecycle+jws`, the rebuy a settlement receipt). See "Revising an order before fulfillment" below.
- `receipt --terminal <url> --order-id <id> [--no-verify] [--wallet <label>]` : fetch the Facet ledger's signed receipt for a settled order and verify it offline against the merchant Terminal's published JWKS. `buy --settle` already returns this inline; use `receipt` to re-fetch it later or to verify any past order independently. If the original (short-lived) buyer identity has expired, it re-authorizes automatically by signing a challenge with the paying wallet, so a past order stays retrievable by the wallet that paid for it. Every fetched receipt is also saved to the archive. See "The receipt" below.
- `receipts` : list the saved receipt archive (default `~/.facet/receipts`, override `FACET_RECEIPTS_DIR`), most recent first, with each order's rail, amount, and verified flag. Reads only local files; needs no wallet or network. The full signed JWS for any order is in `<order_id>.json` in that folder.
- `lifecycle-receipt --terminal <url> --kind <cancel|withdraw|dispute|refund> ( --exchange-id <id> | --order-id <id> ) [--wallet <label>]` : fetch, verify, and archive the signed REVERSAL receipt for a cancel / withdraw / dispute / refund (a compact Ed25519 JWS with typ `facet-lifecycle+jws`, the lifecycle analogue of `receipt`). Pass `--exchange-id` for a cancel / withdraw / dispute, or `--order-id` for a refund. `cancel`, `withdraw`, and `dispute` already archive their receipt inline when you run them; use this to re-fetch one, or to fetch a reversal performed earlier in the same wallet-bound identity. Owner-scoped at the Terminal (a foreign caller is a 404, never a leak) with no wallet-auth fallback, so it resolves only for the identity that performed the reversal. Saved under `lifecycle-<kind>-<handle>.json` in the archive.

### browse-storefront.ts (fallback reader, no secrets)

```bash
deno run --allow-net "$SKILL/scripts/browse-storefront.ts" --site <host> [--query q] [--limit n]
```

Reads the store's public catalog (WooCommerce Store API first, then generic JSON-LD Product data) and returns a lean normalized list: `{ ok, source, store, count, total, products: [ { sku, name, price, regular, currency, on_sale, in_stock, short, url, img_url, img_full } ] }`. The image fields are remote URLs on the merchant's own host, kept for reference only; the script does not fetch, inline, or render them. Reach for this only when the client has no way to browse the real site and the Terminal `search` is not usable.

## Driving this skill over MCP (for autonomous agents)

Facet is built to be walked by agents, not humans, so the same buyer workflow is exposed as an MCP (Model Context Protocol) server over stdio, at `scripts/mcp-server.ts`. An autonomous agent that speaks MCP can discover, identify, browse, and check out with no human at a keyboard. The server is a thin wrapper: nearly every tool spawns the same `facet-checkout.ts` or `browse-storefront.ts` subcommand documented above and relays the one JSON object it prints, so for those tools no checkout, wallet, or KYA logic is reimplemented and the guardrails and the non-custodial invariant are identical to the CLI. The one deliberate exception is the per-line Boson escrow tools (redeem, cancel, and dispute over a selection of `exchange_ids`, plus the `facet_lines` reader): they run in-process and import the audited signing helpers, so for those tools the server itself reads the wallet key to sign each line locally. That is necessary because a per-line action posts one request whose body is a set of line items, each carrying its own locally signed payload, which the single-exchange CLI cannot assemble. The key still signs only locally, and no key or raw signed payload ever enters a tool result.

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

The server spawns each subcommand with the narrow grants that command needs (network only for the public storefront reader; env, read, a write scoped to `~/.cache` and `~/.facet`, run, and network for the checkout script). The wallet key and KYA are read by the child from the environment exactly as with the CLI, so set `FACET_WALLET_KEY` (or a `FACET_WALLETS` registry) in the environment the MCP client launches the server with. The server process itself never reads the key into a variable.

### The tools

The server advertises the buyer surface via `tools/list`. Each maps to a subcommand above:

- `facet_wallet_list` : list wallets (label, address, USDC balance, identity present). Wraps `wallets`.
- `facet_wallet_new` : mint a self-custodied wallet; returns the public address and storage location only. Wraps `wallet new`.
- `facet_fund` : show a wallet's address and USDC balance so the user can fund it (set `await_funding: true` to poll until funded); loads no key and moves no money. Wraps `fund`.
- `facet_provision` : self-issue a wallet-bound KYA identity. Wraps `provision`.
- `facet_discover` : resolve one host's `agents.txt`. Wraps `discover`.
- `facet_directory` : search the Facet directory. Wraps `directory`.
- `facet_search` : read a Terminal's own transaction catalog. Wraps `search`.
- `facet_product` : one product's rail detail. Wraps `product`.
- `facet_buy` : the UCP checkout, DRY by default; settle with `settle: true` plus `confirm` (and `confirm_pay_to` on the x402-direct rail, echoing the DRY run's recipient). Wraps `buy`.
- `facet_mpp_charge` : pay a held reservation through the Machine Payments Protocol (mpp.dev) charge envelope, for an mpp.dev-native flow. Reserve first (call `facet_buy` in DRY mode, use its `checkout_id`), then charge; DRY by default, settle with `settle: true` plus `confirm` and `confirm_pay_to` echoing the DRY run. Wraps `mpp-charge`.
- `facet_email_pref` : record or read the buyer's throwaway shipping-confirmation email (`action: "show"`, or `action: "set"` with an `address` to opt in or `none: true` to opt out), asked once and reused after. Wraps `email-pref`.
- `facet_browse_storefront` : last-resort public catalog reader. Wraps `browse-storefront.ts`.
- `facet_redeem`, `facet_cancel`, `facet_withdraw`, `facet_dispute`, `facet_refund`, `facet_resolve` : the post-purchase lifecycle. Wrap the matching subcommands (`facet_cancel` takes `withdraw: true` to chain the cash-out in one call; `facet_withdraw` is the standalone gasless withdraw; `facet_refund` takes a required `reason` and an optional `items` array for a partial refund, and on a dual-auth store it authorizes the request with a locally signed, single-use wallet attestation so a buyer-only agent can open the ticket with no platform co-signature; `facet_resolve` completes a Boson partial-refund split, taking `refund_id` to auto-read the offer or the explicit `exchange_id` + `buyer_percent_bps` + `seller_sig`).
- `facet_reorder` : buy a past order again. Resolves the candidates from a past order at CURRENT prices and returns a buy plan; it settles nothing and buys nothing on its own, and an unavailable SKU is skipped, not fatal. The purchase runs through `facet_buy` (DRY, confirm, settle) exactly like any other checkout. Wraps `reorder`.
- `facet_revise` : plan a cancel-and-rebuy revision of a multi-item order before it ships (Boson cannot partially refund a committed escrow). Returns the two-step plan (cancel the whole order for a full refund, then re-buy the kept items) and moves no money on its own. Wraps `revise`.
- `facet_get_receipt`, `facet_lifecycle_receipt`, `facet_receipts` : fetch and verify a settled order's signed settlement receipt or a reversal's signed lifecycle receipt (typ `facet-lifecycle+jws`, for a cancel / withdraw / dispute / refund), and list the local receipt archive. Wrap `receipt`, `lifecycle-receipt`, and `receipts`.
- `facet_render_receipt` : render a settled order's receipt into the official self-contained, self-verifying HTML page (identity, payment, settlement, and live in-browser verification), and return its path. Wraps `render-receipt`.

Tool arguments use the CLI flag names in snake_case (for example `exchange_id` for `--exchange-id`, `max_usdc` for `--max-usdc`); `items` and `ship` accept either a JSON string or a native array or object. A tool result is the child's stdout JSON, with `isError` set when the child failed or returned `ok: false`.

### The secret invariant on MCP

A tool result is logged and persisted by the calling agent, so it is held to the same bar the secret-egress rule holds stdout to: it carries an address or a status, never a secret. The wallet key and the recovery mnemonic never appear in a tool argument or a tool result. The one place a secret is revealed, the one-time recovery phrase from `facet_wallet_new`, goes to the child process stderr, which the server runs with `stderr: "null"` so it is discarded by the OS and never captured, forwarded, or returned. A human who needs that recovery phrase must mint in a terminal where that stderr is visible only to them.

## The flow

The first job is ordinary web shopping; Facet only enters once you discover the store is agent-ready. Never lead with the Terminal.

1. Open the store in your native browser and navigate it live for the user to see. The moment the user asks to shop, open the merchant's real storefront in your own native browser, the real, visible browser you can drive and that the user can watch, and navigate it in front of them: go to the matching category or use the site's search box (for "birthday flowers", open the birthday collection or search "birthday", do not stop at the home page), scroll the products into view, and open an item's page when they want a closer look. On a request to shop or to see a store's products, this is the default first action, not a fallback. Do NOT hand the user a link to click, do NOT open the page only as an "open in your browser" card, and do NOT lead with a headless fetch or a plain-text description: drive the visible browser yourself so the user watches their own shopping happen. As you go, read the arrangements off the page (name, price, sale price, rating, image) and keep a short running list with prices. You are the cart: hold the user's choices and quantities in your own memory.

The browser is for looking, not buying. Use it to browse and select only. Never add items to the store's cart, never open the store's own checkout, and never touch a pay button (Google Pay, a card field, anything) on the merchant's page. Do not raise wallets or payment yet. When the user is ready to buy, STOP driving the store and switch to the Facet Terminal (steps 4 to 8): checkout is ALWAYS the Facet Terminal's signed rail, never the store's own checkout. This step works on any store, Facet-enabled or not. See "Browsing the storefront" below for the concrete loop.
2. In the same browser pass, spot the agent-checkout badge and read it. Look for the "agent checkout" badge on the page (usually near the human cart or checkout, often labeled for Facet). It is the visual signal that the store may accept agent checkout, the "Buy with Apple Pay" button in the Apple Pay model. Click it to read it: the badge links straight to the store's `agents.txt`, the discovery pointer that says whether the store really runs a Terminal and where. Treat the badge itself as a hint to verify, never as proof (see "The badge is a hint").
3. Discover and alert. Confirm agent-readiness by resolving the store's `agents.txt` (`discover --site <host>`). If it carries a `Terminal`, tell the user plainly: this site is agent-ready and supports agent checkout. If it does not, the store is not Facet-enabled; stay in ordinary browsing and let the user check out however they normally would. Never touch the Terminal for a non-agent store.
4. Offer agent checkout and choose the wallet. Ask the user two things together: do they want to use agent checkout for this purchase, and which of their own wallets to pay from. Run `wallets` and show each label, address, and USDC balance so they can choose, then carry the chosen `--wallet <label>` through the rest. This is the handoff and the "pick your card" step, and it happens now, at discovery, not before browsing. If the user declines, stop here; nothing else runs.
5. Self-issue the wallet-bound identity. Mint a wallet-bound KYA for the chosen wallet from an issuer the store trusts (`provision --wallet <label>`), self-serve and with no service key: the wallet signs a challenge locally so the issuer binds the KYA to it. The wallet key never leaves the machine, and the token is never printed (see "Identity and wallet-bound checkout"). You need this before the next step, because the directory and the Terminal are identity-gated.
6. Find the Terminal in the Facet directory. Search the directory for the business name without the `.com` (`directory --query "<business name>"`, authenticated with the KYA from step 5) and read the matching result's `terminal_url`. This resolves the store's canonical Terminal from Facet's own records, so it stays correct even if the merchant's `agents.txt` is stale. Cross-check it against the `Terminal` value from step 3.
7. Quote and price it (DRY). Run `buy --terminal <terminal>` WITHOUT `--settle`, keyed by the SKUs and the chosen `--wallet <label>`. This creates the UCP checkout, reads the merchant's offer, verifies it against the guardrails, signs the payment authorization locally, and stops. It returns the exact `price_usdc` and a `confirm_atomic` value. Nothing has moved. Show the user a thin confirmation (item, price, terms), not a rebuilt storefront (see "The confirmation surface"). If this is a gift, ask the user for a card message and a delivery date first and pass them as `--gift-message "..."` and `--delivery-date YYYY-MM-DD` (and `--occasion` if useful): the signed UCP checkout supports these order attributes and carries them to the merchant order, so the message lands on the order and a future delivery date is requested. They do not change the price. The DRY result also carries `shipping_email_pref`; if it is `unset`, ask the buyer once about shipping confirmations before you settle (see "Shipping confirmations"), record the answer with `email-pref`, then re-run the DRY buy so the stored choice is applied.
8. Confirm and settle. Show the real total, the items, and the wallet it pays from, and get an explicit yes for this purchase. Only then run `buy` again WITH `--settle --confirm <confirm_atomic>` (the exact value from step 7), same `--wallet <label>`. Report the settlement: status, order id, settlement id, and the signed receipt. This confirmation is required every time; never skip, batch, or infer it.

### Browsing the storefront (drive it live, do not just describe it)

Steps 1 and 2 are an active job in your native browser, driven live in front of the user, not a passive one. Open the real, visible browser and navigate it so the user watches their shopping happen. This is what makes it feel real, so do it every time, proactively, before you ever mention Facet:

- Open the merchant's site in your native browser (the visible one the user can watch) and navigate to their intent: use the store's own search box, or the category that matches ("birthday", "roses", "sympathy"), rather than stopping at the home page.
- Read the products off the rendered page: name, price, sale price, rating, availability, and image.
- Show the user visually: a screenshot or a rendered view of the arrangements, plus a concise list (name, price, the sale price when on sale, rating). Let them see the flowers and pick.
- Refine by what they say ("something brighter", "under $30", "add a card"), and offer to open any single item for a closer look.
- Fallbacks, and only when you genuinely cannot drive a browser: the Terminal's own `search` (after identity is set) or `scripts/browse-storefront.ts` for a lean public list. These are backups for a headless environment, never the default, and neither one replaces showing the user.

This whole loop is browsing, not buying. Never proceed into the store's cart or checkout, and never touch a pay button on the merchant's page. The moment the user picks, switch to the Facet Terminal (steps 4 to 8); checkout is always the signed rail, never the store's own checkout.

## Choosing the wallet (at the handoff)

Picking the wallet is the "pick your card" step in the Apple Pay model, and it happens at the handoff: once the store is discovered as agent-ready and the user opts into agent checkout (step 4), not before browsing. The wallet the user chooses sets three things at once: their identity (the wallet-bound KYA), the balance they can spend, and the address the USDC actually moves from. So the skill asks at that moment, then carries that one choice all the way through checkout.

Run `wallets` and read it back to the user: label, address, and USDC balance for each. If they configured only one wallet, say which it is and confirm. If they configured several (via `FACET_WALLETS`), list them and let the user pick by label. Pass the chosen `--wallet <label>` to `provision`, `search`, `product`, and `buy` so identity and payment both come from the same wallet.

This lists the user's OWN wallets only. It reads their `FACET_WALLETS` registry, or the single default `FACET_WALLET_KEY` plus `FACET_KYA`, and nothing else. It derives each address locally from the user's own key and never prints, echoes, or transmits a key. It cannot see, recommend, or list any wallet the user did not configure in their own environment.

## Does this merchant have a Terminal?

Two mechanisms, one answer.

- Per host, `discover --site <host>` resolves the store's own `agents.txt`. This is authoritative for a single site: it is the store telling you, on its own domain, that it runs a Terminal and where that Terminal is. Use it whenever the user names a specific store.
- Across the network, `directory` searches the Facet directory for merchants that fit a query, a location, a capability, or a taxonomy, and tells you which of them have a live Terminal (`terminal_url` non-null). Use it to find a store when the user has an intent but not a URL.

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

Checkout is the signed, agent-native rail, and only that. It creates a UCP checkout session at the merchant's Terminal, presents the user's KYA as the buyer identity, signs an on-chain payment authorization locally with the user's wallet, and settles non-custodially into the merchant's escrow, returning a signed receipt. It is NEVER Claude typing a card number into the merchant's human web checkout. If you ever find yourself about to fill a card field in a browser tab to "complete the purchase," stop: that is not this skill, and it breaks identity, provenance, and the non-custodial invariant all at once.

`--items` is a JSON array of `{ "id": "<product_id>", "qty": <n> }`. `--ship` is a JSON object: `{ "recipient", "line1", "locality", "region", "postal_code", "country" }`.

Optional gift and delivery flags are applied to the merchant order at settlement: `--gift-message "Happy birthday!"` writes a card message on the order, `--delivery-date YYYY-MM-DD` requests a future delivery date, and `--occasion "birthday"` tags the occasion. The Terminal validates and length-caps them and the store maps them through (on a WooCommerce store the card message becomes the order note and the date becomes the requested delivery date). They are display-only, never change the price, and never block settlement: a malformed value is dropped rather than failing the purchase.

### Shipping confirmations (ask once, then reuse)

Shipping-confirmation emails are OFF by default, for privacy: with no email on the order the store never sees the buyer's real address. On the buyer's FIRST purchase you offer them a choice, once, and then you honor that choice on every order after without asking again.

How to tell it is the first time: the DRY `buy` result carries `shipping_email_pref`. When it is `unset`, the buyer has never been asked. Ask them plainly, before you settle: shipping confirmations are off by default; if they want them, give a throwaway email (not their real one) and it will be reused for every future order so the store never sees their real address, or they can decline and keep confirmations off. Record the answer, once:

- They want confirmations: `email-pref set <the throwaway address>`. Stored as opted in.
- They decline: `email-pref set --none`. Stored as opted out, so you never ask again.

After that, reuse is automatic and silent. `email-pref set` stores the choice under `~/.cache/facet/order-prefs.json`, and every later `buy` reads it: an opted-in address rides `order_attributes.contact_email` on the checkout automatically (the store un-suppresses the shipping-confirmation email and sends it to the throwaway address), and an opted-out or already-answered buyer is never asked again. `shipping_email_pref` on the buy result reflects the state each time (`opted_in`, `opted_out`, or `override`); you only ever ask on `unset`. To use a different address for a single order without changing the stored default, pass `--shipping-email <addr>` on that one `buy`.

The email is buyer-provided. It is a preference, not a secret, so it lives as plain JSON in the cache (never the `~/.facet` keystore) and may be passed on the command line. A Facet-generated relay alias, so the buyer need not supply their own throwaway address, is a planned follow-up and is not part of this flow yet.

DRY (default, safe):

```bash
deno run --allow-env --allow-read --allow-write="$HOME/.cache,$HOME/.facet" --allow-net "$SKILL/scripts/facet-checkout.ts" buy \
  --terminal <terminal> \
  --wallet <label> \
  --items '[{"id":"SKU-1","qty":1}]' \
  --ship '{"recipient":"Jane Doe","line1":"123 Main St","locality":"Austin","region":"TX","postal_code":"78701","country":"US"}'
```

Settle (real money, only after the user confirms the DRY total):

```bash
deno run --allow-env --allow-read --allow-write="$HOME/.cache,$HOME/.facet" --allow-net "$SKILL/scripts/facet-checkout.ts" buy \
  --terminal <terminal> \
  --wallet <label> \
  --items '[{"id":"SKU-1","qty":1}]' \
  --ship '{...same as above...}' \
  --settle --confirm <confirm_atomic-from-the-DRY-result>
```

(`--wallet <label>` is the wallet the user chose in step 1. With a single default wallet it can be omitted, but pass it explicitly once the user has picked so identity and payment stay pinned to that one wallet.)

The `--confirm` value must equal the price the DRY run just advertised. If the store's price changed in between, the helper refuses to settle. That is intended; re-run DRY, show the new total, and confirm again.

## Paying through MPP (mpp.dev)

Most checkouts should just use `buy`: it creates the UCP checkout AND settles it in one signed flow, and it is what "check out through Facet" means. `mpp-charge` is for the case where the payer is an mpp.dev-native agent, or where you want to settle a reservation through the Machine Payments Protocol's own challenge / credential / receipt envelope. MPP is not a different rail or a different pot of money: it is the SAME on-chain settlement `buy` performs, expressed in mpp.dev's shape, so an agent that already speaks mpp.dev can pay a Facet order with no Facet-specific code. A host advertises it in `agents.txt` (`discover` surfaces `mpp_endpoint` / `mpp_method: evm/charge` / `mpp_auth: payment-scheme`); a host without those lines does not serve MPP, so use `buy`.

One hard rule: **MPP never bypasses escrow.** MPP settles x402-direct (straight to the merchant's payout, no escrow, no buyer protection), so `mpp-charge` reads the reservation's own checkout session first and REFUSES if the merchant offers Boson escrow, pointing you to `buy` (which settles into that escrow). In practice MPP is for x402-native merchants; a Boson-default store like Pecan & Petal is always settled through `buy`. The guard fails closed: if it cannot confirm the merchant is x402-only (for example the reservation was made by a different wallet, so its session is not readable), it refuses rather than risk bypassing escrow.

The flow is two commands, and it keeps the same non-custodial invariant and the same DRY-then-confirm discipline as `buy`:

1. Reserve. Run `buy` in DRY mode (no `--settle`) for the cart and shipping address. It creates the UCP checkout, and its result carries `checkout_id`. A UCP checkout session id IS a reservation id, so that value is what MPP charges. (Do not settle the `buy`; you are only using it to hold the priced reservation.)
2. Charge, DRY. Run `mpp-charge --terminal <url> --reservation-id <checkout_id>`. It probes the charge endpoint with no credential to draw the 402 challenge, in which the amount, recipient, currency and chain are all server-derived from the reservation and the merchant's own payout row (never anything the client wrote), verifies those terms against the buyer guardrails, and stops. It returns `confirm_atomic` and `confirm_pay_to`. Nothing has moved. Show the user the amount and the recipient.
3. Charge, settle. After the user approves, run `mpp-charge ... --settle --confirm <confirm_atomic> --confirm-pay-to <confirm_pay_to>`, passing back the exact values the DRY run returned. mppx builds the evm/charge credential (an ERC-3009 authorization whose nonce is bound to this challenge), the wallet signs it locally, and it is resubmitted as `Authorization: Payment`. The result carries the receipt, including the on-chain `reference`.

```
mpp-charge --terminal https://<merchant>.facet.llc --reservation-id <checkout_id>
# then, after the user confirms the amount AND recipient:
mpp-charge --terminal https://<merchant>.facet.llc --reservation-id <checkout_id> \
  --settle --confirm <confirm_atomic> --confirm-pay-to <confirm_pay_to> --wallet <label>
```

Both `--confirm` (the amount) and `--confirm-pay-to` (the recipient) must equal what the DRY run just returned, or the helper refuses to settle. The recipient is confirmed as well as the amount because, like the x402-direct rail, the MPP recipient is the merchant's own server-derived payout address and is not escrow-pinned. The escrow guard reads the reservation's session owner-scoped, so it presents the wallet's KYA; the charge credential itself carries no KYA (the reservation id is the capability and the credential moves the signer's own funds, so charging only ever spends the chosen wallet). After settlement, fetch and verify the signed receipt exactly as for any order (see "The receipt").

MPP has no refund or return leg of its own: an MPP charge is an ordinary x402-direct order (its rail is `coin/usdc-base`), so refunds run through the standard path. The settle result carries `order_id`; to refund, run `refund --order-id <id> --reason "..."` (a REQUEST, no money moves), and the merchant's approve sends the USDC back from its own payout wallet over x402-direct (non-custodial, gasless). There is no escrow and no dispute fallback, which is the same reason the escrow guard above sends any escrow-offering merchant to `buy`: an x402-direct refund depends on the merchant approving it.

## Reordering a past order ("buy that again")

When the user wants to buy a past order again, `reorder` does the legwork: it reads their own order history from the Terminal, then re-prices each item against the store's CURRENT catalog, and hands the result back for a normal, confirmed checkout. It is pure orchestration of calls that already exist (`order_history` then `get_product`), and it adds no new money path: reorder itself settles nothing and buys nothing.

1. Resolve the candidates. Run `reorder --terminal <terminal> [--order-id <id>] --wallet <label>`. Without `--order-id` it uses the most recent order; with it, that specific order. For each past line item it reads the CURRENT price and availability, so the user sees today's prices, not what they paid before. A SKU that is gone or out of stock comes back marked unavailable and is skipped, never erroring the whole reorder.

2. Show the user the candidates. Present the available items with their current price (and a note when the price changed since the last order), plus any items that are no longer available. This is a thin confirmation surface, the same as a normal cart, not a rebuilt catalog.

3. Route the purchase through the normal buy flow. Reorder returns the available items as a buy plan; take those SKUs into the ordinary `buy` DRY quote (step 7 of the flow), show the user the real total, get an explicit yes, then settle with `--settle --confirm <atomic>`. This is the same confirm-then-settle path as any other purchase: one explicit confirmation per settlement, and no auto-buy. Reorder never settles on its own; it only prepares the cart.

Reorder needs the buyer's shipping address at buy time (order history does not carry it), so supply `--ship` on the `buy` step as usual. Everything else (the guardrails, the wallet-bound identity, the non-custodial settlement) is identical to a fresh purchase.

## Revising an order before fulfillment ("drop one item, keep the rest")

A buyer sometimes wants to remove one line from a multi-item order that has not shipped yet, and keep the rest. A Boson escrow cannot be partially refunded while it is still committed (the on-chain dispute path that could split it only opens after the order is redeemed), and a cart settles as ONE escrow, not one per line. So "partial cancel before shipping" is not a single move. The non-custodial equivalent is **cancel-and-rebuy**: cancel the whole order for a full refund, then re-buy only the items the buyer is keeping.

`revise --terminal <url> --exchange-id <id> --keep '[{"id":"SKU","qty":1}]'` plans this. Like `reorder`, it is a PLANNER: it returns the two ordered steps and moves no money on its own.

1. **Cancel the whole order.** Step 1 is `cancel --exchange-id <id> --withdraw`: the full escrow returns to the buyer and is cashed back to their wallet in one gasless call, and the signed cancel receipt (a `facet-lifecycle+jws`) is archived. The removed item is now fully refunded along with everything else.
2. **Re-buy the kept items.** Step 2 is an ordinary `buy` with just the `--keep` SKUs: run the DRY quote, show the user today's real total, get an explicit yes, then `--settle`. This is a fresh signed purchase and leaves its own settlement receipt. Supply `--ship` as usual.

The net effect is the buyer keeps what they wanted, is made whole on the dropped line, and the whole revision is auditable end to end: a signed cancel receipt for the refund and a signed settlement receipt for the new order. Confirm each step with the user before running it; `revise` itself settles nothing.

## After the purchase: redeem, cancel, withdraw, dispute, refund, resolve, receipt

Checkout is not the end. Once a purchase settles into escrow, the buyer can act on it, and this skill drives the full lifecycle non-custodially. Each Boson action is signed locally and gasless with the buyer's own wallet; the wallet key never leaves the machine, and only the wallet that owns the on-chain voucher can act, so an agent cannot touch an exchange it does not hold the key for. Keep the buy receipt: `--exchange-id` is the `settlement_id` it returned, and `--order-id` is its order id.

- **redeem** (`redeem --exchange-id <id>`): the buyer confirming receipt to release the escrow toward the seller, signed locally and gasless. On an order-management-connected store (WooCommerce, Shopify) the buyer usually does NOT need to do this for the seller to be paid: when the merchant marks the order fulfilled or shipped, a fulfillment webhook tells the Terminal to fire the buyer's held redeem automatically (deferred-redeem-on-fulfillment), so fulfillment starts the release with no buyer action. Reach for `redeem` to release early ("I already have it, release now"), or on a store with no fulfillment webhook where the buyer's redeem is what moves the escrow. It is the buyer saying "I got what I paid for."
- **cancel** (`cancel --exchange-id <id> [--withdraw]`): before redemption, cancel the order and the full escrow returns to the buyer. The refund lands in the buyer's Boson protocol available-funds first; moving it to the wallet is a separate withdraw. Add `--withdraw` to do both in one call: the gasless cancel returns the escrow, then the gasless withdraw cashes it out to the buyer's own wallet.
- **withdraw** (`withdraw --exchange-id <id> [--amount <atomic>] [--dry-run]`): cash a Boson escrow's returned available-funds out to the buyer's own wallet, gaslessly. Signs the buyer's `withdrawFunds` meta-tx locally and a gas-only relayer submits it; `withdrawFunds` is self-binding on-chain, so the funds can only reach the buyer's own wallet. Use it after a plain `cancel`, or standalone whenever available-funds are sitting in the buyer's Boson entity. `--dry-run` returns the signed request body without posting.
- **dispute** (`dispute --exchange-id <id> [--action raise|retract|escalate]`): if something is wrong, raise a dispute into adjudication, then retract or escalate as it proceeds. To settle a disputed order as a partial refund, use `resolve` below.
- **refund** (`refund --order-id <id> --reason "<why>" [--items '<json>']`): open a refund ticket for a settled order. REQUEST only: it opens the ticket and moves no money. The merchant reviews the `--reason` and approves, and only the approve moves money, in one of three ways by rail and escrow state. An x402 order sends USDC back from the merchant wallet. A still-committed Boson escrow (the common case, a whole-order refund before redemption) is RELEASED by the approve itself: the Terminal signs the seller revoke, the whole escrow returns to the buyer's Boson available-funds, and `withdraw` cashes it to the wallet, with no `resolve` step. A disputed Boson order (a post-redeem partial) offers a seller-signed `resolveDispute` split the buyer completes with `resolve`. Pass `--items` (a JSON array of `{ id, qty }`) for a PARTIAL refund of just those lines, with shipping retained; omit it to request the whole order. Post-delivery returns run here: on an x402 order the send-back settles straight to the buyer once approved.
- **resolve** (`resolve --refund-id <id>`, or the explicit `--exchange-id --buyer-percent-bps --seller-sig`): complete a Boson partial-refund split after the merchant approves. When a disputed Boson order is refunded partially, the merchant offers a seller-signed split; this signs the buyer half of the mutual `resolveDispute` locally and gaslessly and submits it. The Terminal validates the split against the merchant's stored offer before relaying, so the buyer can never change the percentage or forge the seller half. Give `--refund-id` to auto-read the approved offer from the buyer's own refund ticket, or pass the offer explicitly.
- **receipt** (`receipt --order-id <id>`): fetch and verify the signed settlement receipt for a settled order, and archive it. Read-only proof, not a fund-moving action; see "The receipt" below.
- **lifecycle-receipt** (`lifecycle-receipt --kind <cancel|withdraw|dispute|refund> ( --exchange-id <id> | --order-id <id> )`): fetch, verify, and archive the signed REVERSAL receipt (typ `facet-lifecycle+jws`) for one of those actions. Read-only; the reversal already happened. `cancel`, `withdraw`, and `dispute` archive their receipt inline, so a reversal leaves the same portable, JWKS-verifiable proof a purchase does; use this to re-fetch one.

Each returns the Terminal's result. These move real funds, so treat them like settlement: confirm the action and the order with the user before running it. The exceptions are `receipt` and `lifecycle-receipt`, which only read and verify proof and move nothing. A reversal (cancel / withdraw / dispute) now also carries its own signed lifecycle receipt in its result under `receipt` and in the archive, so a cancelled order no longer reads as "settled" with only a tx hash: it has portable, verifiable proof of the reversal.

## The receipt: your portable proof

Every settled purchase leaves a signed receipt on the Facet ledger. It is what makes an agent purchase auditable: a compact Ed25519 JWS (RFC 7515) the merchant Terminal signs over the settled order, and that anyone can verify with a stock JOSE library against the Terminal's published keys, with no call back to Facet. A receipt you have to phone the issuer to check is a service; this one is evidence, because verifying it needs only the issuer's public keys.

The receipt JWS is deliberately compact (order, amount, currency, line items). To make the whole cryptographic chain visible, `buy --settle` and `mpp-charge` also return a `provenance` block: the buyer KYA's identity (`aid` / issuer / expiry, decoded from the token, never the raw bearer); the payment leg (on Boson, the buyer's ERC-3009 token authorization plus the seller's offer signature; on x402 / MPP, the ERC-3009 authorization and signature); the settlement chain (checkout, order, settlement id); and whether the signed receipt verified offline against the merchant's JWKS. It notes the one leg it cannot show, the platform's RFC 9421 co-signature, which the Terminal records server-side in its own signatures ledger that no buyer endpoint exposes.

`buy --settle` returns it inline under `receipt`, and `receipt --order-id <id>` re-fetches it for any past order (re-authorizing with the paying wallet if the original short-lived buyer identity has expired). The `receipt` object carries the compact JWS (`jws`), the signing key id (`kid`), `verified` (true or false), and the decoded `claims`. What the claims attest:

- `iss` : the merchant Terminal that issued and signed it (the host you transacted with).
- `sub` : your agent identity (the KYA `aid` that made the purchase).
- `jti` : the order id. One receipt per order.
- `settlement` : `{ rail, amount_minor, currency, settled_at, livemode }`, the money that actually moved.
- `chain` : `{ this_hash, prev_hash }`, this order's link into Facet's tamper-evident, hash-chained ledger.
- `attestations` : counterparty signatures (`{ party, says, signed_at }`). Empty right after a fresh buy and NOT a negative signal; merchant and agent countersignatures accrue over time, and re-fetching with `receipt` picks them up.
- `split` (when recorded) : `{ goods_minor, tax_minor, shipping_minor, duty_minor, discount_minor }`.

How `verified: true` is reached: decode the compact JWS, confirm the header `typ` is `facet-receipt+jws` and `alg` is `EdDSA`, confirm the signed `iss` is the exact Terminal host you bought from, fetch that host's `/.well-known/jwks.json`, and verify the Ed25519 signature with the key named by `kid`. The trust anchor is the host you transacted with, never the receipt itself: the receipt's own `provider_jwks` hint sits outside the signature and is ignored, so a receipt can never nominate the key that would validate it. The skill does all of this in `verifyReceipt`; a third party runs the same checks with any JOSE library. See [references/receipt-verification.md](references/receipt-verification.md).

Receipts are also archived, tracked like wallets. Every receipt `buy --settle` or `receipt` fetches is written to a durable folder (default `~/.facet/receipts`, override `FACET_RECEIPTS_DIR`): one `<order_id>.json` per order holding the full signed JWS, the decoded claims, and the verified flag, plus an `index.jsonl` that the `receipts` subcommand lists. This is automatic; the buy or receipt output reports `saved: true` and `saved_path`. Saving needs `--allow-write` to that folder (already in the standard invocation); without it the receipt is still fetched and verified and the output shows `saved: false` with a note. When a user asks about their past purchases, list the archive with `receipts` rather than re-fetching each order.

When a purchase settles, tell the user their order is receipted and, in one line, what the proof says (the amount, the rail, and that it verifies against the merchant's own keys). On a deferred-settlement escrow rail the anchor may appear a moment later; if `receipt.available` is `false`, run `receipt --order-id <id>` shortly after. A receipt that returns `verified: false` is worth surfacing plainly with its `reason`, never hiding.

### Showing a detailed, shareable receipt view

There is ONE official way to render a receipt: `render-receipt --terminal <url> --order-id <id>`. It fetches and verifies the receipt, embeds the merchant's Ed25519 public key, fills the canonical template at `references/receipt-template.html`, and writes a self-contained, self-verifying HTML page (default under the receipts archive; `--out <path>` to place it). Open it in a browser and the verify seal runs a real in-browser Ed25519 check; every field is derived from the embedded signed JWS, and the identity, payment, and verification provenance chain renders when it is available (from the archive a `buy --settle` wrote, or an explicit `--provenance-file`). Optional `--merchant-name` / `--merchant-location` / `--order-url` set the masthead and the order link. Line items (name, SKU, quantity) are read from the buyer's own order history, or supplied with `--items-file <path>` (a JSON array of `{ name, sku, qty, amount_minor? }`) for an order the buyer's identity does not own, such as a platform-originated one; without either, the receipt shows the money breakdown alone. Use this whenever the user wants a receipt they can look at or share; do not hand-roll a one-off page, and do not just dump JSON. The page is what it shows:

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

The point of the view is that every row is checkable evidence, not a claim: the raw JWS stays right there so the reader (or any third party) can re-run the exact verification with a stock JOSE library. A reversal's `facet-lifecycle+jws` receipt renders the same way under its `event` block (kind, rail, amount, tx hash), so a cancel, withdraw, dispute, or refund gets the same portable, seeable proof a purchase does. Offer this rendered view whenever the user wants a receipt they can look at or share, and point them at the archived `<order_id>.json` (or `lifecycle-<kind>-<handle>.json`) as the durable copy.

## Safety rules (non-negotiable)

- Non-custodial, always. The wallet key signs locally and never leaves the machine. If any step would send a raw private key anywhere, stop; it is a bug.
- Checkout is the signed rail, never a web form. The native browser is for browsing and selection ONLY; never use it to check out. Do not add to the store's cart, do not open the store's checkout, and never type a card or touch a pay button (Google Pay, and the like) on the merchant's page. The only checkout is the Facet Terminal's signed UCP session, run through the scripts.
- DRY first, every time. Never pass `--settle` until you have run a DRY `buy`, shown the user the exact total, and gotten an explicit yes for that specific purchase.
- One confirmation per settlement. A yes for one purchase is not a yes for the next. Re-confirm each cart.
- Never handle the secrets yourself. Do not read, print, echo, or pass `FACET_KYA` or `FACET_WALLET_KEY` on a command line. They live in the environment; the helper reads them.
- Respect the guardrails. The helper refuses a checkout that is not on the expected chain, or whose price exceeds the cap (default 25 USDC; raise with `--max-usdc` only when the user's cart genuinely needs it and they have confirmed), or that the wallet cannot cover. Relay a refusal to the user; do not try to bypass it.
- Money is Base USDC. Settlement is real USDC on Base. Treat every settle as spending real money.
- The full agent-behavior safety layer, external content treated as data, what the agent will not buy, purchase intent and authority, identity and privacy, advice limits, and refusals, is in [references/safety.md](references/safety.md). These rules summarize it; that document is the behavioral contract. The terms, acceptable use, and data-handling policy is in [references/legal.md](references/legal.md).

## Identity and wallet-bound checkout

Many Facet stores tie identity to the paying wallet: they require the checkout to present a KYA bound to the exact wallet whose USDC moves. A plain KYA that is not bound to the paying wallet is rejected before any money moves. The helper handles this by default: after the wallet is chosen it self-serve mints a wallet-bound KYA from the Facet issuer (`issuer.facet.llc`, the default trusted issuer) by proving control of that wallet, so no pre-set token is needed. Set `FACET_KYA` yourself only to pin a specific trusted, wallet-bound identity for the same address behind `FACET_WALLET_KEY`.

Some production stores also require a co-signature from the shopping platform itself, on top of the buyer's own identity and payment. A caller that authenticates with only its own KYA and wallet cannot supply that co-signature. Against such a store this helper browses and prices a cart (DRY), then reports plainly that the store will not settle a buyer-only checkout; it does not retry or try to route around the rejection. Where a store does accept a buyer-only checkout, settlement proceeds normally. Either way the buyer's key stays local and the flow is non-custodial.

## Getting a wallet (for a walletless user)

A user with no wallet is not stuck: they can mint one here and start shopping in three steps, no exchange account or manual seed-phrase setup required. Think of the wallet as a capped spend instrument, a prepaid card the user tops up with only what they mean to spend.

1. Mint it. Run `wallet new` (add `--label <name>` for a second wallet). It generates a fresh recovery phrase, derives the wallet, and stores the private key securely: the macOS keychain first, or an AES-256-GCM encrypted keystore under `~/.facet/keys` (off any synced folder), protected by a passphrase the user sets at a no-echo prompt. The recovery phrase is shown ONCE, on stderr, with a write-it-down warning. Relay that to the user and tell them to record it offline: it is the only backup and it will not be shown again. The private key and the phrase never reach stdout, the result object, or a log; stdout carries only the public address, the label, where the key was stored, and a fund hint.

2. Fund it. Run `fund --await` (optionally `--min-usdc <n>`). It prints the wallet's address and watches its USDC-on-Base balance, reporting when funds arrive. Give the user the address and have them send USDC on Base to it (an exchange withdrawal to Base, a transfer from another wallet, anything). Only USDC on Base counts toward the balance.

3. Shop. Once funded, the minted wallet behaves exactly like an env-configured one: `wallets` lists it, and `provision`, `search`, and `buy` sign with it, all selected by `--label`. The user never exports `FACET_WALLET_KEY`. When that variable is unset, the helper loads the key from the keychain or the encrypted keystore (prompting for the keystore passphrase) for the single moment it signs, then drops it. This is exactly as non-custodial as the env path: the key stays on the machine and only a signature ever leaves the process.

The wallet as a capped spend instrument: fund it with what the user plans to spend, not their whole balance. Every `buy` is still bounded per order by `--max-usdc` under an absolute ceiling (the default cap applies unchanged, and a garbage value can never disable it); a per-session cap is a separate Terminal-side control, not something this skill sets.

Onboarding invocations. Grant a write to `~/.facet` and, for the macOS keychain tier, `--allow-run`:

```bash
deno run --allow-env --allow-read --allow-write="$HOME/.cache,$HOME/.facet" --allow-run --allow-net "$SKILL/scripts/facet-checkout.ts" wallet new
deno run --allow-env --allow-read --allow-write="$HOME/.cache,$HOME/.facet" --allow-run --allow-net "$SKILL/scripts/facet-checkout.ts" fund --await
```

Without `--allow-run` the keychain tier is skipped and the encrypted keystore is used instead. Never pass the private key, the passphrase, or the recovery phrase on a command line: the helper reads the passphrase from a no-echo prompt and the key from its secure store, and nothing secret is ever an argument.

## Getting a KYA (identity)

The helper mints the KYA for you, self-serve, and does so by default. `provision` (and `buy` on demand) mints a wallet-bound KYA from the Facet issuer (`issuer.facet.llc`, the default trusted issuer) using the chosen wallet: it enrolls a fresh identity key, then the wallet signs a challenge locally so the issuer binds the KYA to that wallet. No issuer service key is involved and the wallet key never leaves the process. Stores advertise which issuers they trust in the `kya_issuers` field from `discover`.

- This needs no setup beyond `FACET_WALLET_KEY`. Reach for `provision` to pre-mint, or let `buy` mint on demand.
- If the user already holds a KYA from an issuer the store trusts, they set it as `FACET_KYA` and it is used as-is; a stale or untrusted one is skipped and a fresh wallet-bound one is minted instead.
- Wallet-bound identity is required on stores that tie identity to the payer (see "Identity and wallet-bound checkout" above): the KYA must be bound to the exact address behind `FACET_WALLET_KEY`. The self-serve mint produces exactly that.

## Honest scope

This skill exists to guide the agent through Facet identity and checkout: discovering the Terminal, the KYA handshake, quoting the cart, and settling on the signed rail. It is deliberately not a human-facing shopping experience. Browsing the storefront, rendering products, and helping the user choose belong to the host assistant (Claude, ChatGPT, Gemini) and its own web browsing; this skill takes the cart the user approved and completes the purchase on the Facet rail.

- Selection leans on the client's own web browsing of the merchant's real storefront and on the Facet directory. This skill does not rebuild the catalog; where neither the browser nor the Terminal `search` is available, the fallback reader returns a lean public list.
- Settlement rides the merchant's DEFAULT rail, set by the merchant's OMS (Facet's rail-split): Shopify stores default to x402-direct on testnet and mainnet (the buyer's ERC-3009 settles straight to the merchant's payout wallet, no escrow); WooCommerce stores default to Boson escrow (buyer protection: funds sit in escrow, not straight to the merchant). This reference client settles BOTH rails: it settles the merchant's own default rail (the checkout's `default_rail`), so a WooCommerce store's Boson escrow default is honored and never silently downgraded to x402-direct, signing a Boson commit for an escrow offer or an ERC-3009 TransferWithAuthorization for an x402-direct offer, always with the buyer's own wallet and the same hard guardrails on the server-advertised terms (recipient, chain, EIP-712 domain, USDC token, amount cap). `FACET_RAIL=x402` or `FACET_RAIL=boson` forces a rail; the default (`auto`) follows the checkout's `default_rail`, preferring Boson escrow (buyer protection) when a store advertises both without a stated default. The escrow lifecycle below (redeem, cancel, dispute) applies to Boson orders; an x402-direct order has no escrow and reverses through `refund` instead.
- Some stores require a co-signature from the shopping platform that a buyer-only install cannot supply. Against those, the helper browses and prices but does not settle, and says so (see "Identity and wallet-bound checkout").
- It targets Base mainnet USDC by default. The chain, token, and cap are overridable through environment variables for advanced or test use, but the safe defaults are mainnet.
- Its job is the checkout rail, not the shopping UI. Selection happens in the host assistant's own browser; this skill carries the approved cart into checkout. It also drives the post-purchase lifecycle (redeem, cancel, dispute, refund; see "After the purchase"). Order tracking beyond those states is a separate Facet surface.

## License

Apache-2.0. Copyright 2026 Facet, LLC. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
