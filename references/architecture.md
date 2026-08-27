# Architecture

How the shopping skill works end to end: the two surfaces, the flow, discovery,
the rail, and the environment contract. The skill is driven over MCP; the `facet_*`
tools are the only interface, and `scripts/facet-checkout.ts` is the internal
implementation they spawn, not a command line to run.

## Contents

- The two surfaces
- The shopping flow
- Discovery: agents.txt and the directory
- The SKU join key
- The settlement rail
- UCP checkout and platform origination
- Environment contract

## The two surfaces

"Shopping" is two jobs that call for opposite tools.

- **Discovery and selection.** Finding the store, seeing what it sells, picking
  items. The best front end is the assistant's own browser on the merchant's real
  storefront, the same pages a person sees. The catalog is not rebuilt into a
  panel.
- **Checkout and settlement.** Identifying as the buyer, paying, getting a receipt.
  This runs on Facet's signed, agent-native rail: a UCP checkout session, a
  KYA-bearer identity, a locally signed on-chain payment, and a signed receipt. It
  is never a card typed into a web form.

The mental model is Apple Pay. The storefront is the web page you browse. The
agent-checkout badge is the "Buy with Apple Pay" button. The Facet Terminal is the
rail that moves money without handing the merchant a card.

## The shopping flow

The first job is ordinary web shopping. Facet enters only once the store is
discovered as agent-ready. The flow never leads with the Terminal.

1. **Browse** the merchant's human-facing storefront in the assistant's browser.
   Help the user find and pick items. Hold the cart in working memory. This works
   on any store.
2. **Spot the agent-checkout badge** and read it. The badge links to the store's
   `agents.txt`. It is a hint to verify, never proof.
3. **Discover and alert.** Resolve the store's `agents.txt` (`facet_discover` with
   `site`). If it advertises a Terminal, tell the user the store is agent-ready. If
   not, stay in ordinary browsing.
4. **Offer agent checkout and choose the wallet.** Ask whether to use agent
   checkout and which wallet to pay from. `facet_wallet_list` lists label, address,
   and USDC balance. The chosen wallet sets identity, spendable balance, and funds
   source at once.
5. **Self-issue the wallet-bound identity.** Mint a wallet-bound KYA (an ES256 JWT
   from `issuer.facet.llc`) for the chosen wallet (`facet_provision` with `wallet`),
   self-serve, no service key. Needed because the directory
   and the Terminal are identity-gated.
6. **Find the Terminal in the directory.** Search the directory by business name
   (`facet_directory` with `query`) and read the matching `terminal_url`. This
   resolves the canonical Terminal from Facet's records even if the storefront
   `agents.txt` is stale. Cross-check against step 3.
7. **Quote (DRY).** Call `facet_buy` with `terminal`, `items`, and `ship`, and omit
   `settle`. This creates the UCP checkout, reads the merchant's offer, validates it
   against the guardrails, signs the payment authorization locally, and stops.
   Nothing moves. It returns the exact price and a confirm value.
8. **Confirm and settle.** Show the total, items, and paying wallet, get an explicit
   yes, then call `facet_buy` with `settle: true` and `confirm: <atomic>`. Report
   status, order id, settlement id, and the signed receipt. One confirmation per
   settlement.

## Discovery: agents.txt and the directory

Two mechanisms, one answer to "does this merchant have a Terminal."

- **Per host: `facet_discover` with `site`.** Resolves the store's own
  `/.well-known/agents.txt` (unauthenticated). Authoritative for a single site: the
  store telling you, on its own domain, that it runs a Terminal and where. The
  client then re-reads the manifest at the Terminal's own host and trusts that
  canonical copy over the storefront copy, because a storefront plugin can serve a
  drifted copy from stored settings while the Terminal generates the canonical
  manifest per request.
- **Across the network: `facet_directory` (with `query`, and `near`, `taxonomy`, or
  `capabilities`).** Searches the Facet directory (identity-gated) for merchants
  that fit a query, location, capability, or taxonomy, and reports which have a live
  Terminal. Use it to find a store from an intent, and to resolve the canonical
  Terminal by business name.

## The SKU join key

The product SKU is the join key from selection to checkout: a storefront `sku` is
the same string as the Terminal product `id`. You pick by SKU on the storefront and
buy by SKU at the Terminal.

## The settlement rail

This client settles on the **Boson escrow rail** (`llc.facet.boson_escrow`). Funds
sit in on-chain escrow rather than moving straight to the merchant, which gives the
buyer a cancel, dispute, and refund window. The buyer signs an ERC-3009 commit
authorization whose recipient is the Boson escrow Diamond for the expected chain.

A store that advertises only the direct `llc.facet.x402` rail is refused with a
clear message rather than settled on an unintended rail. Dual-rail support for the
x402-direct path is planned and not part of this client yet. Card and Stripe rails
are not agent-signable and are out of scope for a buyer-side client.

## UCP checkout and platform origination

Checkout is a UCP checkout session: a CREATE call that quotes and holds (no money),
then a COMPLETE call that carries the buyer's client-side ERC-3009 authorization.

- **Buyer-direct.** For a store that accepts a buyer-only checkout, CREATE and
  COMPLETE post straight to the merchant's Terminal.
- **Platform-originated.** For a first-party (`.facet.llc`) merchant, CREATE and
  COMPLETE route through the Facet platform origination surface, which adds the
  RFC 9421 co-signature a dual-auth store requires and forwards the buyer KYA
  verbatim. The buyer still signs its own payment client-side, so no key or custody
  reaches the server. If origination is not provisioned, the client falls back to
  buyer-direct.

The buyer's KYA is echoed into the payment instrument itself
(`instruments[0].kya`), not only the Authorization header, because the Terminal
binds identity at settlement to the instrument.

## Internal implementation

The `facet_*` MCP tools are the only interface. Under the hood, most spawn
`scripts/facet-checkout.ts` (the identity and money-path implementation) as a child
process and relay the single JSON object it prints; it reads the wallet key inside
that child and is not a command line to run. `scripts/browse-storefront.ts` is a
last-resort public-catalog reader (WooCommerce Store API, then JSON-LD), used only
when neither the assistant's browser nor the `facet_search` tool is available. It
touches no secrets.

## Environment contract

- `FACET_WALLET_KEY`: the wallet private key (`0x` + 64 hex). Read from the
  environment, signs locally, never transmitted.
- `FACET_KYA`: optional. A wallet-bound KYA. If absent, expired, or untrusted, a
  fresh one is self-issued.
- `FACET_WALLETS`: optional JSON registry to name more than one wallet by the env
  vars that hold each wallet's key and KYA (never the values).

Advanced overrides, with safe mainnet defaults: `FACET_EXPECT_CHAIN`,
`FACET_EXPECT_NETWORK`, `FACET_USDC_ADDRESS`, `FACET_BOSON_ESCROW`, `FACET_RPC`,
`FACET_MAX_USDC`, `FACET_MAX_USDC_CEILING`, `FACET_ISSUER_URL`,
`FACET_DIRECTORY_TERMINAL`. Change these only for test networks or a private issuer.
