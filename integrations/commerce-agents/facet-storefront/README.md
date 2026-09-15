# Facet storefront backend for `commerce-agents`

A `StorefrontBackend` implementation that puts Anthropic's
[`commerce-agents`](https://github.com/anthropics/commerce-agents) Shopping Agent
on top of a Facet merchant Terminal. Point any `commerce-agents` runtime at this
backend and the customer shops a Facet merchant's catalog and checks out
**non-custodially** through Facet: the agent never sees a checkout URL and never
moves money.

## Why this exists

`commerce-agents` is Anthropic's reference blueprint for a shopping agent. It
defines one integration surface, `StorefrontBackend`, and reserves a single seam
for a hosted, confirm-before-pay checkout: `checkout_handoff`, which the backend
fills with a URL the host completes payment against, out of the model's sight.

That seam maps exactly onto a Facet UCP checkout session. This adapter implements
the eleven `StorefrontBackend` methods against the Facet Terminal and returns a
Facet checkout-session URL from `checkout_handoff`. The result: any agent built on
`commerce-agents` can settle through Facet, with Facet's identity (the customer's
KYA) on every read and Facet's non-custodial settlement on checkout.

## How it maps

| `StorefrontBackend` method | Facet Terminal |
| --- | --- |
| `search_products` | `POST /v1/search` (price, rating, and sort filters applied client-side) |
| `get_product_details` | `POST /v1/get_product` |
| `get_cart` / `add_to_cart` / `update_cart_item` / `remove_from_cart` | held per session in the adapter, priced from the catalog reads |
| `get_preferences` | a guest profile keyed by the session identity (override to enrich) |
| `get_orders` / `get_order` | `POST /v1/order_history` (KYA-scoped to the customer) |
| `search_policies` | returns none (the buyer surface exposes no policy search) |
| `get_fulfillment_options` | a shipping option, with the exact fee priced into checkout |
| `checkout_handoff` | `POST /ucp/v1/checkout-sessions` (or `/ucp/v1/originated-checkouts` for a first-party merchant), returns the session URL |

The cart is local state until `checkout_handoff`, which is where the Facet session
is priced and reserved. Nothing in this adapter signs a payment or holds a wallet
key: creating the session only prices the cart, and the host completes payment on
the returned URL. That is what keeps the checkout non-custodial.

## Install

`shopping-agent-core` (the `StorefrontBackend` interface and the domain types) is
installed from the `commerce-agents` repository, not a public index. Install it
and its sibling `commerce-common` first, then this adapter into the same
environment:

```bash
# from a checkout of anthropics/commerce-agents
pip install -e commerce-common -e shopping-agent/core
# then this adapter
pip install -e integrations/commerce-agents/facet-storefront
```

## Use

```python
from facet_storefront import FacetStorefrontBackend
from shopping_agent.types import ShoppingSessionContext

backend = FacetStorefrontBackend(
    "https://pecanandpetal.facet.llc",   # the merchant Terminal
    kya_token=customer_kya,              # the customer's Facet KYA (ES256 JWT)
    platform_terminal_url="https://terminal.facet.llc",  # for a first-party merchant
    ship_to={                            # where checkout ships
        "first_name": "Ada", "last_name": "Lovelace",
        "street_address": "1 Analytical Way", "address_locality": "Austin",
        "address_region": "TX", "postal_code": "78701", "address_country": "US",
    },
)

# Then hand `backend` to any commerce-agents runtime (Messages API, Agent SDK,
# or the managed FastMCP server). The Shopping Agent calls its methods; the
# customer completes payment on the checkout_handoff URL.
```

## Run it as the front half (the storefront MCP server)

The adapter also ships the commerce-agents storefront MCP server wired to run over
Facet, so the shopping front half (catalog search, product details, cart, orders,
policies, fulfillment, and customer memory, all `<storefront_data>` fenced and
provenance gated) becomes a set of MCP tools any agent connects to, while checkout
and settlement stay Facet:

```bash
pip install -e '.[server]'   # commerce-common[mcp] + mcp (pinned to v1)

FACET_KYA="<es256 jwt>" \
FACET_STOREFRONT_TERMINAL="https://pecanandpetal.facet.llc" \
FACET_PLATFORM_TERMINAL="https://api.facet.llc" \
python -m facet_storefront.server        # streamable HTTP on 127.0.0.1:8200/mcp
```

Point any MCP-speaking agent at `http://127.0.0.1:8200/mcp`. It gets
commerce-agents' `search_products`, `get_product_details`, `get_cart`,
`add_to_cart`, `update_cart_item`, `remove_from_cart`, `get_preferences`,
`save_memory`, `recall_memories`, `get_orders`, `get_order_status`,
`search_policies`, and `get_fulfillment_options`, all backed by the Facet
merchant Terminal. Customer memory is persisted by commerce-agents'
`JsonFileMemoryStore` (default `~/.cache/facet/storefront-memory.json`). When the
customer checks out, the checkout card carries the Facet UCP checkout-session URL
from `checkout_handoff`, which the host completes non-custodially.

The server binds local-only by default and holds the customer's KYA as their
identity; expose it only behind your own authenticated gateway.

### Getting a KYA

The customer's KYA is an ES256 bearer JWT from a Facet-trusted issuer
(`issuer.facet.llc` by default). The Facet shopping skill mints one automatically;
a standalone integrator provisions one from the issuer and passes it as
`kya_token`. The catalog, order-history, and checkout surfaces are all
identity-gated, so a KYA is required.

## Test

Offline (no network), the mapping and cart logic:

```bash
pip install -e '.[test]'
pytest
```

Live, the full catalog-to-checkout flow against a real merchant (creates and
prices a checkout session, settles nothing):

```bash
FACET_KYA="<es256 jwt>" \
FACET_STOREFRONT_TERMINAL="https://pecanandpetal.facet.llc" \
FACET_PLATFORM_TERMINAL="https://terminal.facet.llc" \
python smoke.py
```

## License

Apache-2.0. This adapter depends on `commerce-agents` (Apache-2.0) and Facet's
own client surface.
