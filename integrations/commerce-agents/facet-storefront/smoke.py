# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""A live smoke test for FacetStorefrontBackend: search a Facet merchant, add an
item, and mint a real UCP checkout-session URL, asserting the agent-facing flow
reaches a non-custodial handoff. It settles nothing and moves no money (the
checkout session is created and priced only).

Run it with a Facet KYA in the environment:

    FACET_KYA="<es256 jwt>" \
    FACET_STOREFRONT_TERMINAL="https://pecanandpetal.facet.llc" \
    FACET_PLATFORM_TERMINAL="https://terminal.facet.llc" \
    python smoke.py

Ship-to is read from FACET_SHIP_TO (a JSON destination); a sensible default is
used when it is unset. Exits non-zero on any failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from facet_storefront import FacetStorefrontBackend
from shopping_agent.types import ShoppingSessionContext

DEFAULT_SHIP_TO = {
    "first_name": "Test",
    "last_name": "Buyer",
    "street_address": "100 Congress Ave",
    "address_locality": "Austin",
    "address_region": "TX",
    "postal_code": "78701",
    "address_country": "US",
}


async def main() -> int:
    kya = os.environ.get("FACET_KYA", "")
    if not kya:
        print("FACET_KYA is required (a Facet ES256 bearer JWT).", file=sys.stderr)
        return 2
    terminal = os.environ.get("FACET_STOREFRONT_TERMINAL", "https://pecanandpetal.facet.llc")
    platform = os.environ.get("FACET_PLATFORM_TERMINAL") or None
    ship_to = json.loads(os.environ["FACET_SHIP_TO"]) if os.environ.get("FACET_SHIP_TO") else DEFAULT_SHIP_TO

    backend = FacetStorefrontBackend(
        terminal,
        kya,
        platform_terminal_url=platform,
        ship_to=ship_to,
    )
    session = ShoppingSessionContext(session_id="smoke-sess", user_id="smoke-user")

    try:
        products = await backend.search_products(session, "flower", limit=5)
        print(f"search_products -> {len(products)} result(s)")
        if not products:
            print("no products returned; cannot exercise checkout.", file=sys.stderr)
            return 1
        for p in products[:3]:
            print(f"  {p.product_id}  {p.title}  {p.currency} {p.price}  in_stock={p.in_stock}")

        first = products[0]
        details = await backend.get_product_details(session, first.product_id)
        print(f"get_product_details({first.product_id}) -> {'ok' if details else 'None'}")

        cart = await backend.add_to_cart(session, first.product_id, 2)
        cart = await backend.add_to_cart(session, first.product_id, 1)
        print(f"add_to_cart -> {cart.item_count} unit(s), subtotal {cart.currency} {cart.subtotal}")

        prefs = await backend.get_preferences(session)
        print(f"get_preferences -> user_id={prefs.user_id}")
        fulfillment = await backend.get_fulfillment_options(session, [first.product_id])
        print(f"get_fulfillment_options -> {[f.method for f in fulfillment]}")

        handoffs = await backend.checkout_handoff(session, cart)
        if not handoffs:
            print("checkout_handoff returned no handoff.", file=sys.stderr)
            return 1
        url = handoffs[0].url
        print(f"checkout_handoff -> {url}  (seller={handoffs[0].seller})")

        expected_prefix = terminal.rstrip("/") + "/ucp/v1/checkout-sessions/"
        if not url.startswith(expected_prefix):
            print(f"FAIL: checkout URL did not match {expected_prefix}", file=sys.stderr)
            return 1
        print("PASS: reached a real Facet UCP checkout-session URL, non-custodially.")
        return 0
    finally:
        await backend.aclose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
