# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for the in-session cart store: add accumulates, update sets,
remove and a zero quantity clear a line, and a missing product is a no-op."""

from __future__ import annotations

from facet_storefront.cart import CartStore
from shopping_agent.types import Product

CANDLE = Product(product_id="HCF-ADDON-CANDLE", title="Candle", price=18.0, currency="USD")
BDAY = Product(product_id="HCF-BDAY", title="Birthday", price=15.0, currency="USD")

SID = "sess-1"


def _store_with_seen() -> CartStore:
    store = CartStore()
    store.remember(SID, [CANDLE, BDAY])
    return store


def test_add_accumulates_and_subtotal() -> None:
    store = _store_with_seen()
    store.add(SID, CANDLE, 1)
    cart = store.add(SID, CANDLE, 2)
    assert cart.item_count == 3
    assert cart.subtotal == 54.0  # 3 * 18
    assert cart.currency == "USD"


def test_update_sets_exact_quantity() -> None:
    store = _store_with_seen()
    store.add(SID, BDAY, 5)
    cart = store.update(SID, "HCF-BDAY", 2)
    assert cart.item_count == 2
    assert cart.items[0].quantity == 2


def test_update_missing_product_is_noop() -> None:
    store = _store_with_seen()
    cart = store.update(SID, "NOPE", 3)
    assert cart.item_count == 0


def test_remove_and_zero_quantity_clear_line() -> None:
    store = _store_with_seen()
    store.add(SID, CANDLE, 2)
    store.add(SID, BDAY, 1)
    assert store.get_cart(SID).item_count == 3
    store.remove(SID, "HCF-ADDON-CANDLE")
    assert store.get_cart(SID).item_count == 1
    store.update(SID, "HCF-BDAY", 0)
    assert store.get_cart(SID).item_count == 0


def test_sessions_are_isolated() -> None:
    store = _store_with_seen()
    store.add(SID, CANDLE, 1)
    store.remember("sess-2", [BDAY])
    store.add("sess-2", BDAY, 4)
    assert store.get_cart(SID).item_count == 1
    assert store.get_cart("sess-2").item_count == 4
