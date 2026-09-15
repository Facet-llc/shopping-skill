# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""The customer's cart, held per shopping session in the adapter.

A Facet checkout session is priced and reserved at ``checkout_handoff`` time,
not on every add or remove, so the cart lives here as local state seeded from
the catalog reads (which carry the price and title). This mirrors the
``commerce-agents`` model exactly: the cart methods are the only writes, and the
real checkout URL is minted once, from the whole cart, at handoff. The executor
serializes a session's writes with its own lock, so no locking is needed here.
"""

from __future__ import annotations

from shopping_agent.types import Cart, CartItem, Product


class _SessionCart:
    """One session's cart lines plus the products it has seen (its provenance
    cache), so an add can resolve a product's title and price without a network
    round-trip."""

    def __init__(self) -> None:
        self.lines: dict[str, CartItem] = {}
        self.currency: str = "USD"
        self.seen: dict[str, Product] = {}

    def to_cart(self) -> Cart:
        return Cart(items=list(self.lines.values()), currency=self.currency)


class CartStore:
    """All in-flight session carts for one backend instance, keyed by
    ``session_id``. A single backend can serve many concurrent sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, _SessionCart] = {}

    def _session(self, session_id: str) -> _SessionCart:
        sc = self._sessions.get(session_id)
        if sc is None:
            sc = _SessionCart()
            self._sessions[session_id] = sc
        return sc

    def remember(self, session_id: str, products: list[Product]) -> None:
        """Record products returned from a catalog read so a later add can price
        them. Only in-stock, buyable records (not family records with options)
        need to be added, but remembering all of them is harmless."""
        sc = self._session(session_id)
        for product in products:
            if product.product_id:
                sc.seen[product.product_id] = product

    def seen_product(self, session_id: str, product_id: str) -> Product | None:
        return self._sessions.get(session_id, _SessionCart()).seen.get(product_id) \
            if session_id in self._sessions else None

    def get_cart(self, session_id: str) -> Cart:
        return self._session(session_id).to_cart()

    def set_line(self, session_id: str, product: Product, quantity: int) -> Cart:
        """Set the line for ``product`` to exactly ``quantity`` units (the caller
        has already clamped it to the per-item ceiling). A quantity of zero or
        less removes the line."""
        sc = self._session(session_id)
        if quantity <= 0:
            sc.lines.pop(product.product_id, None)
            return sc.to_cart()
        sc.currency = product.currency or sc.currency
        sc.lines[product.product_id] = CartItem(
            product_id=product.product_id,
            title=product.title,
            price=product.price,
            quantity=quantity,
            image_url=product.image_url,
            option_values=dict(product.option_values),
            variant_of=product.variant_of,
        )
        return sc.to_cart()

    def add(self, session_id: str, product: Product, quantity: int) -> Cart:
        """Add ``quantity`` to the existing line for ``product`` (or create it)."""
        existing = self._session(session_id).lines.get(product.product_id)
        current = existing.quantity if existing is not None else 0
        return self.set_line(session_id, product, current + quantity)

    def update(self, session_id: str, product_id: str, quantity: int) -> Cart:
        """Set an existing line to ``quantity``. A product not in the cart leaves
        the cart unchanged, per the ABC contract."""
        sc = self._session(session_id)
        existing = sc.lines.get(product_id)
        if existing is None:
            return sc.to_cart()
        if quantity <= 0:
            sc.lines.pop(product_id, None)
            return sc.to_cart()
        sc.lines[product_id] = existing.model_copy(update={"quantity": quantity})
        return sc.to_cart()

    def remove(self, session_id: str, product_id: str) -> Cart:
        """Remove a line. A product not in the cart leaves the cart unchanged."""
        sc = self._session(session_id)
        sc.lines.pop(product_id, None)
        return sc.to_cart()
