# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""``FacetStorefrontBackend``: a ``commerce-agents`` ``StorefrontBackend`` backed
by a Facet merchant Terminal.

Point any ``commerce-agents`` Shopping Agent at an instance of this class and the
customer shops a Facet merchant's catalog and checks out non-custodially through
Facet: the catalog and orders are read from the Terminal with the customer's KYA,
the cart is held per session, and ``checkout_handoff`` mints a real Facet UCP
checkout-session URL that the host completes payment against. The agent never
sees that URL and never moves money, which is exactly the seam
``commerce-agents`` reserves for a hosted, confirm-before-pay checkout.
"""

from __future__ import annotations

from typing import Any

import httpx
from shopping_agent.backend import StorefrontBackend, Unavailable
from shopping_agent.types import (
    Cart,
    CheckoutHandoff,
    FulfillmentOption,
    Order,
    Policy,
    Product,
    ProductDetails,
    SearchFilters,
    ShoppingSessionContext,
    UserPreferences,
)

from .cart import CartStore
from .client import FacetTerminalClient
from .mapping import (
    order_from_history,
    product_details_from_get_product,
    product_from_search,
)


class FacetStorefrontBackend(StorefrontBackend):
    """A storefront backed by one Facet merchant Terminal.

    Args:
        terminal_url: the merchant Terminal origin (e.g.
            ``https://pecanandpetal.facet.llc``).
        kya_token: the customer's Facet KYA (ES256 bearer JWT). Required.
        platform_terminal_url: the Facet platform Terminal origin, set when the
            merchant is first-party and its checkout must be platform-originated.
        ship_to: a shipping destination for checkout, either a full UCP
            ``fulfillment`` block (``{"methods": [...]}``) or a bare destination
            (``{"first_name", "last_name", "street_address", "address_locality",
            "address_region", "postal_code", "address_country"}``). When absent,
            ``checkout_handoff`` creates a session without a fulfillment block and
            lets the merchant collect shipping.
        rail_id: force a settlement rail; ``None`` uses the merchant's default
            (Shopify to x402-direct, WooCommerce to Boson escrow).
        seller: the label put on the ``CheckoutHandoff`` for this merchant;
            defaults to the Terminal host.
        timeout: per-request timeout in seconds.
        http_client: an ``httpx.AsyncClient`` to reuse.
    """

    def __init__(
        self,
        terminal_url: str,
        kya_token: str,
        *,
        platform_terminal_url: str | None = None,
        ship_to: dict[str, Any] | None = None,
        rail_id: str | None = None,
        seller: str | None = None,
        timeout: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._client = FacetTerminalClient(
            terminal_url,
            kya_token,
            platform_terminal_url=platform_terminal_url,
            timeout=timeout,
            http_client=http_client,
        )
        self._carts = CartStore()
        self._ship_to = ship_to
        self._rail_id = rail_id
        self._seller = seller or self._client.base.split("://", 1)[-1]

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- Catalog ------------------------------------------------------------------

    async def search_products(
        self,
        session: ShoppingSessionContext,
        query: str,
        filters: SearchFilters | None = None,
        limit: int = 8,
    ) -> list[Product]:
        # Facet's /v1/search takes query, category, tags, and limit. The price,
        # rating, and sort filters are applied here over the returned page, so a
        # richer request is honored without the Terminal having to model it. A
        # wider page is fetched first so local filtering still fills the limit.
        category = filters.category if filters else None
        raw = await self._client.search(
            query=query or None,
            category=category,
            limit=max(limit * 3, limit),
        )
        results = raw.get("results")
        products = [
            product_from_search(r) for r in results if isinstance(r, dict)
        ] if isinstance(results, list) else []

        if filters is not None:
            products = _apply_filters(products, filters)

        products = products[:limit]
        self._carts.remember(session.session_id, products)
        return products

    async def get_product_details(
        self, session: ShoppingSessionContext, product_id: str
    ) -> ProductDetails | None:
        raw = await self._client.get_product(product_id)
        if raw is None:
            return None
        details = product_details_from_get_product(raw)
        self._carts.remember(session.session_id, [details])
        return details

    # -- Cart ---------------------------------------------------------------------

    async def get_cart(self, session: ShoppingSessionContext) -> Cart:
        return self._carts.get_cart(session.session_id)

    async def add_to_cart(
        self, session: ShoppingSessionContext, product_id: str, quantity: int
    ) -> Cart:
        product = await self._resolve_seen(session, product_id)
        if product is None:
            raise Unavailable(f"{product_id} is not a product available to add")
        if product.has_options:
            raise Unavailable(
                f"{product_id} is sold as variants; add one of its variants instead"
            )
        if not product.in_stock:
            raise Unavailable(f"{product_id} is out of stock")
        return self._carts.add(session.session_id, product, quantity)

    async def update_cart_item(
        self, session: ShoppingSessionContext, product_id: str, quantity: int
    ) -> Cart:
        return self._carts.update(session.session_id, product_id, quantity)

    async def remove_from_cart(
        self, session: ShoppingSessionContext, product_id: str
    ) -> Cart:
        return self._carts.remove(session.session_id, product_id)

    # -- Customer context ---------------------------------------------------------

    async def get_preferences(self, session: ShoppingSessionContext) -> UserPreferences:
        # Facet's identity is the KYA; the Terminal exposes no separate customer
        # profile on the buyer surface, so a guest profile keyed by the session's
        # user id is returned. A deployment that holds richer customer facts can
        # subclass and override this.
        return UserPreferences(user_id=session.user_id)

    # -- Orders and policies ------------------------------------------------------

    async def get_orders(
        self, session: ShoppingSessionContext, limit: int = 5
    ) -> list[Order]:
        raw_orders = await self._client.order_history()
        orders = [order_from_history(o) for o in raw_orders]
        return orders[:limit]

    async def get_order(
        self, session: ShoppingSessionContext, order_id: str
    ) -> Order | None:
        for raw in await self._client.order_history():
            if str(raw.get("order_id", "")) == order_id:
                return order_from_history(raw)
        return None

    async def search_policies(
        self, session: ShoppingSessionContext, query: str
    ) -> list[Policy]:
        # The Facet buyer surface exposes no policy-search route, so this returns
        # nothing rather than inventing policy text. A merchant that publishes
        # policies can subclass and map them here.
        return []

    # -- Fulfillment --------------------------------------------------------------

    async def get_fulfillment_options(
        self, session: ShoppingSessionContext, product_ids: list[str]
    ) -> list[FulfillmentOption]:
        # Facet merchants ship; the exact fee and ETA are priced into the checkout
        # session at handoff (the Terminal computes shipping and tax there), so a
        # single shipping option is surfaced with the fee deferred to checkout
        # rather than a fabricated number.
        if not product_ids:
            return []
        return [
            FulfillmentOption(
                method="shipping",
                eta="Quoted at checkout",
                fee=0.0,
            )
        ]

    # -- Checkout handoff (the non-custodial seam) --------------------------------

    async def checkout_handoff(
        self, session: ShoppingSessionContext, cart: Cart
    ) -> list[CheckoutHandoff]:
        if not cart.items:
            return []
        line_items = [
            {"item": {"id": item.product_id}, "quantity": item.quantity}
            for item in cart.items
        ]
        created = await self._client.create_checkout_session(
            line_items=line_items,
            fulfillment=_fulfillment_block(self._ship_to),
            rail_id=self._rail_id,
        )
        session_id = created.get("id")
        if not isinstance(session_id, str) or not session_id:
            raise RuntimeError("checkout session create returned no id")
        return [
            CheckoutHandoff(
                url=self._client.checkout_session_url(session_id),
                label="Complete checkout with Facet",
                seller=self._seller,
            )
        ]

    # -- internals ----------------------------------------------------------------

    async def _resolve_seen(
        self, session: ShoppingSessionContext, product_id: str
    ) -> Product | None:
        product = self._carts.seen_product(session.session_id, product_id)
        if product is not None:
            return product
        # Not seen in this session: fetch it so a valid id still resolves. The
        # executor's provenance gate already restricts adds to seen ids, so this
        # is a fallback for a host that manages provenance differently.
        details = await self.get_product_details(session, product_id)
        return details


def _apply_filters(products: list[Product], filters: SearchFilters) -> list[Product]:
    out = products
    if filters.min_price is not None:
        out = [p for p in out if p.price >= filters.min_price]
    if filters.max_price is not None:
        out = [p for p in out if p.price <= filters.max_price]
    if filters.min_rating is not None:
        out = [p for p in out if p.rating is not None and p.rating >= filters.min_rating]
    if filters.sort == "price_asc":
        out = sorted(out, key=lambda p: p.price)
    elif filters.sort == "price_desc":
        out = sorted(out, key=lambda p: p.price, reverse=True)
    elif filters.sort == "rating":
        out = sorted(out, key=lambda p: p.rating or 0.0, reverse=True)
    return out


def _fulfillment_block(ship_to: dict[str, Any] | None) -> dict[str, Any] | None:
    """Wrap a configured destination into a UCP fulfillment block, or pass a
    full block through unchanged. Returns None when no destination is set."""
    if ship_to is None:
        return None
    if "methods" in ship_to:
        return ship_to
    return {"methods": [{"type": "shipping", "destinations": [ship_to]}]}
