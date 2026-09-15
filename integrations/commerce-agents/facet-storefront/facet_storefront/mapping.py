# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""Pure mappers from the Facet Terminal's JSON onto the ``commerce-agents``
domain models. No I/O here: every function takes a decoded dict and returns a
typed model, so the mapping is unit-tested offline against captured fixtures.

Facet's product price is ``pricing.per_case`` in whole currency units (not
minor units), verified against a live Terminal. A missing or malformed field
degrades to a safe default rather than raising, because a catalog read that the
model will only ever display should not fail a whole turn over one odd row.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shopping_agent.types import (
    Order,
    OrderItem,
    OrderStatus,
    Product,
    ProductDetails,
)

# Facet order-status strings mapped onto the commerce-agents enum. Facet uses a
# superset; anything unrecognized falls back to PROCESSING so an order still maps.
_STATUS_MAP: dict[str, OrderStatus] = {
    "processing": OrderStatus.PROCESSING,
    "pending": OrderStatus.PROCESSING,
    "committed": OrderStatus.PROCESSING,
    "paid": OrderStatus.PROCESSING,
    "fulfilled": OrderStatus.SHIPPED,
    "shipped": OrderStatus.SHIPPED,
    "out_for_delivery": OrderStatus.OUT_FOR_DELIVERY,
    "delivered": OrderStatus.DELIVERED,
    "redeemed": OrderStatus.DELIVERED,
    "delayed": OrderStatus.DELAYED,
    "cancelled": OrderStatus.CANCELLED,
    "canceled": OrderStatus.CANCELLED,
    "return_initiated": OrderStatus.RETURN_INITIATED,
    "refunded": OrderStatus.REFUNDED,
}

# The keys Facet has been seen to use for an order's placed-at time, in priority
# order. When none is present the epoch is used as an explicit "time unknown"
# marker rather than a fabricated recent timestamp.
_PLACED_AT_KEYS = ("placed_at", "created_at", "ordered_at", "settled_at", "committed_at")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _price_and_currency(raw: dict[str, Any]) -> tuple[float, str]:
    pricing = raw.get("pricing")
    if isinstance(pricing, dict):
        per_case = pricing.get("per_case")
        currency = pricing.get("currency")
        price = float(per_case) if isinstance(per_case, (int, float)) else 0.0
        cur = currency if isinstance(currency, str) and currency else "USD"
        return price, cur
    return 0.0, "USD"


def _base_attributes(raw: dict[str, Any]) -> dict[str, str]:
    attrs: dict[str, str] = {}
    pack = raw.get("pack")
    if isinstance(pack, dict):
        if isinstance(pack.get("uom"), str):
            attrs["unit_of_measure"] = pack["uom"]
        if pack.get("case_pack") is not None:
            attrs["case_pack"] = str(pack["case_pack"])
    return attrs


def product_from_search(raw: dict[str, Any]) -> Product:
    """Map one ``/v1/search`` result onto a :class:`Product`."""
    price, currency = _price_and_currency(raw)
    tags = raw.get("tags")
    return Product(
        product_id=str(raw.get("id", "")),
        title=str(raw.get("name", "")),
        price=price,
        currency=currency,
        category=raw.get("category") if isinstance(raw.get("category"), str) else None,
        labels=[t for t in tags if isinstance(t, str)] if isinstance(tags, list) else [],
        attributes=_base_attributes(raw),
        in_stock=bool(raw.get("in_stock", True)),
    )


def product_details_from_get_product(raw: dict[str, Any]) -> ProductDetails:
    """Map a ``/v1/get_product`` product onto :class:`ProductDetails`. Facet
    products are flat (no variant families), so ``variants`` is always empty."""
    price, currency = _price_and_currency(raw)
    tags = raw.get("tags")
    description = raw.get("description")
    desc = description if isinstance(description, str) and description else None

    specs = _base_attributes(raw)
    for key in ("origin", "hts_code"):
        val = raw.get(key)
        if isinstance(val, str) and val:
            specs[key] = val
    inventory = raw.get("inventory")
    if isinstance(inventory, int):
        specs["inventory"] = str(inventory)
    allergens = raw.get("allergens")
    if isinstance(allergens, list) and allergens:
        specs["allergens"] = ", ".join(str(a) for a in allergens)

    return ProductDetails(
        product_id=str(raw.get("id", "")),
        title=str(raw.get("name", "")),
        price=price,
        currency=currency,
        category=raw.get("category") if isinstance(raw.get("category"), str) else None,
        labels=[t for t in tags if isinstance(t, str)] if isinstance(tags, list) else [],
        attributes=_base_attributes(raw),
        in_stock=bool(raw.get("in_stock", True)),
        short_description=desc,
        long_description=desc,
        specs=specs,
        variants=[],
    )


def _parse_placed_at(raw: dict[str, Any]) -> datetime:
    for key in _PLACED_AT_KEYS:
        val = raw.get(key)
        if isinstance(val, str) and val:
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00"))
            except ValueError:
                continue
        if isinstance(val, (int, float)):
            try:
                return datetime.fromtimestamp(float(val), tz=timezone.utc)
            except (ValueError, OSError):
                continue
    return _EPOCH


def _order_total(raw: dict[str, Any], items: list[OrderItem]) -> float:
    total = raw.get("total")
    if isinstance(total, (int, float)):
        return round(float(total), 2)
    total_minor = raw.get("total_minor")
    if isinstance(total_minor, (int, float)):
        return round(float(total_minor) / 100.0, 2)
    return round(sum(i.price * i.quantity for i in items), 2)


def order_from_history(raw: dict[str, Any]) -> Order:
    """Map one ``/v1/order_history`` order onto an :class:`Order`.

    The line-item shape (``product_id``, ``qty``, ``unit_price``) is grounded
    against the buyer client's reorder path. The order's status, placed-at, and
    total are read opportunistically across the keys Facet has been seen to use,
    because those are not part of the adapter's frozen contract; a missing
    placed-at maps to the epoch (an explicit "unknown"), never a faked time."""
    raw_items = raw.get("line_items")
    items: list[OrderItem] = []
    if isinstance(raw_items, list):
        for li in raw_items:
            if not isinstance(li, dict):
                continue
            pid = li.get("product_id")
            if not isinstance(pid, str) or not pid:
                continue
            qty = li.get("qty")
            quantity = qty if isinstance(qty, int) and qty > 0 else 1
            unit_price = li.get("unit_price")
            price = float(unit_price) if isinstance(unit_price, (int, float)) else 0.0
            name = li.get("name")
            title = name if isinstance(name, str) and name else pid
            items.append(
                OrderItem(product_id=pid, title=title, quantity=quantity, price=price)
            )

    status_raw = raw.get("status")
    status = _STATUS_MAP.get(
        status_raw.lower() if isinstance(status_raw, str) else "", OrderStatus.PROCESSING
    )
    currency = raw.get("currency")
    return Order(
        order_id=str(raw.get("order_id", "")),
        status=status,
        placed_at=_parse_placed_at(raw),
        items=items,
        total=_order_total(raw, items),
        currency=currency if isinstance(currency, str) and currency else "USD",
    )
