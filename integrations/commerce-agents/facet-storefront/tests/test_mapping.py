# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for the Facet-to-commerce-agents mappers. The fixtures are the
verbatim shapes a live Facet Terminal returned (pecanandpetal.facet.llc), so a
drift in the Terminal's response shape fails here before it reaches a customer."""

from __future__ import annotations

from datetime import datetime, timezone

from facet_storefront.mapping import (
    order_from_history,
    product_details_from_get_product,
    product_from_search,
)
from shopping_agent.types import OrderStatus

# A verbatim /v1/search result row.
SEARCH_ROW = {
    "id": "HCF-ADDON-CANDLE",
    "name": "Add a Scented Candle",
    "category": "Uncategorized",
    "tags": [],
    "pricing": {"currency": "USD", "per_case": 18},
    "pack": {"uom": "unit", "case_pack": 1},
    "in_stock": True,
}

# A verbatim /v1/get_product product.
PRODUCT = {
    "id": "HCF-BDAY",
    "name": "Birthday Flower Arrangement",
    "category": "Birthday",
    "description": None,
    "origin": None,
    "hts_code": None,
    "allergens": [],
    "tags": [],
    "pricing": {"currency": "USD", "per_case": 15},
    "pack": {"uom": "unit", "case_pack": 1},
    "in_stock": True,
    "inventory": 1000000,
    "coa_available": False,
    "document_ids": [],
}


def test_product_from_search_maps_price_and_stock() -> None:
    p = product_from_search(SEARCH_ROW)
    assert p.product_id == "HCF-ADDON-CANDLE"
    assert p.title == "Add a Scented Candle"
    assert p.price == 18.0
    assert p.currency == "USD"
    assert p.in_stock is True
    assert p.category == "Uncategorized"
    assert p.attributes["unit_of_measure"] == "unit"
    assert p.attributes["case_pack"] == "1"


def test_product_details_flat_no_variants() -> None:
    d = product_details_from_get_product(PRODUCT)
    assert d.product_id == "HCF-BDAY"
    assert d.price == 15.0
    assert d.category == "Birthday"
    assert d.variants == []
    assert d.specs["inventory"] == "1000000"


def test_missing_pricing_degrades_to_zero_usd() -> None:
    p = product_from_search({"id": "X", "name": "No price"})
    assert p.price == 0.0
    assert p.currency == "USD"


def test_order_from_history_maps_items_and_status() -> None:
    raw = {
        "order_id": "ord_123",
        "status": "fulfilled",
        "placed_at": "2026-08-20T14:30:00Z",
        "currency": "USD",
        "line_items": [
            {"product_id": "HCF-BDAY", "qty": 2, "unit_price": 15.0},
            {"product_id": "HCF-ADDON-CANDLE", "qty": 1, "unit_price": 18.0},
        ],
    }
    order = order_from_history(raw)
    assert order.order_id == "ord_123"
    assert order.status == OrderStatus.SHIPPED  # "fulfilled" maps to SHIPPED
    assert order.placed_at == datetime(2026, 8, 20, 14, 30, tzinfo=timezone.utc)
    assert len(order.items) == 2
    assert order.items[0].product_id == "HCF-BDAY"
    assert order.items[0].quantity == 2
    # total falls back to the sum of line prices when no explicit total is present.
    assert order.total == 48.0


def test_order_from_history_epoch_when_no_timestamp() -> None:
    order = order_from_history(
        {"order_id": "ord_x", "line_items": [{"product_id": "A", "qty": 1, "unit_price": 5}]}
    )
    assert order.placed_at == datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert order.status == OrderStatus.PROCESSING  # unknown status default
    assert order.total == 5.0


def test_order_total_prefers_explicit_total() -> None:
    order = order_from_history(
        {
            "order_id": "ord_y",
            "total": 99.5,
            "line_items": [{"product_id": "A", "qty": 3, "unit_price": 10}],
        }
    )
    assert order.total == 99.5
