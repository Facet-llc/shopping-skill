# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""A thin async client over the Facet Terminal's agent-facing surface.

Every call carries the customer's Facet KYA (an ES256 bearer JWT) as
``Authorization: Bearer <kya>``. The client never holds a wallet key and never
signs a payment: creating a checkout session only prices and reserves the cart,
and the customer completes payment out of band on the returned session. That is
what keeps a Facet checkout non-custodial.

The endpoint shapes below were verified against a live Terminal
(``pecanandpetal.facet.llc``): search and get_product return a product whose
price is ``pricing.per_case`` in whole currency units; checkout-session create
returns ``{id, totals, ...}`` and, for a first-party merchant, is routed through
the platform origination surface so the platform can add the RFC 9421
co-signature a dual-auth store requires.
"""

from __future__ import annotations

from typing import Any

import httpx


class FacetTerminalError(RuntimeError):
    """A non-success response from the Facet Terminal, carrying the status and a
    short body excerpt so the caller can tell an auth failure (401/402/403) from
    a missing route (404) from a server fault (5xx)."""

    def __init__(self, endpoint: str, status: int, body: str) -> None:
        self.endpoint = endpoint
        self.status = status
        self.body = body
        super().__init__(f"{endpoint} failed HTTP {status}: {body[:300]}")


def _terminal_base(url: str) -> str:
    """Normalize a terminal URL to an origin with no trailing slash. Accepts a
    bare host and defaults it to https, matching the Deno buyer client."""
    u = url.strip()
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    return u.rstrip("/")


class FacetTerminalClient:
    """Server-side calls to one Facet merchant Terminal for one customer identity.

    Args:
        terminal_url: the merchant's Terminal origin, e.g.
            ``https://pecanandpetal.facet.llc``.
        kya_token: the customer's Facet KYA (ES256 JWT). Required: the catalog,
            order-history, and checkout surfaces are all identity-gated.
        platform_terminal_url: the Facet platform Terminal origin. When set, a
            checkout for a first-party merchant is routed through
            ``/ucp/v1/originated-checkouts`` there so the platform adds the
            co-signature; on a 404 (origination not provisioned) it falls back to
            a buyer-direct create. Leave ``None`` for a merchant that accepts a
            buyer-direct checkout.
        timeout: per-request timeout in seconds.
        http_client: an existing ``httpx.AsyncClient`` to reuse. When omitted the
            client owns one and closes it in :meth:`aclose`.
    """

    def __init__(
        self,
        terminal_url: str,
        kya_token: str,
        *,
        platform_terminal_url: str | None = None,
        timeout: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not kya_token:
            raise ValueError(
                "a Facet KYA bearer token is required; the Terminal's catalog and "
                "checkout surfaces are identity-gated"
            )
        self.base = _terminal_base(terminal_url)
        self.platform_base = (
            _terminal_base(platform_terminal_url) if platform_terminal_url else None
        )
        self._kya = kya_token
        self._timeout = timeout
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": f"Bearer {self._kya}",
            "content-type": "application/json",
            "accept": "application/json",
        }

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> "FacetTerminalClient":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def _post(self, endpoint: str, body: dict[str, Any]) -> tuple[int, str]:
        resp = await self._http.post(
            f"{self.base}{endpoint}", headers=self._headers(), json=body
        )
        return resp.status_code, resp.text

    # -- Catalog ------------------------------------------------------------------

    async def search(
        self,
        *,
        query: str | None = None,
        category: str | None = None,
        tags: list[str] | None = None,
        limit: int = 20,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """``POST /v1/search`` -> ``{results: [...], next_cursor}``."""
        body: dict[str, Any] = {"limit": limit}
        if query is not None:
            body["query"] = query
        if category is not None:
            body["category"] = category
        if tags:
            body["tags"] = tags
        if cursor is not None:
            body["cursor"] = cursor
        status, text = await self._post("/v1/search", body)
        if status != 200:
            raise FacetTerminalError("/v1/search", status, text)
        return _json_obj(text)

    async def get_product(self, product_id: str) -> dict[str, Any] | None:
        """``POST /v1/get_product`` -> the product object, or ``None`` on 404."""
        status, text = await self._post("/v1/get_product", {"product_id": product_id})
        if status == 404:
            return None
        if status != 200:
            raise FacetTerminalError("/v1/get_product", status, text)
        obj = _json_obj(text)
        # The route returns either the bare product or ``{product: {...}}``.
        inner = obj.get("product")
        return inner if isinstance(inner, dict) else obj

    # -- Orders -------------------------------------------------------------------

    async def order_history(self) -> list[dict[str, Any]]:
        """``POST /v1/order_history`` -> the caller's own orders (newest first).

        The Terminal scopes this to the KYA's ``aid``, so a customer only ever
        reads back their own orders. An empty list is returned when the identity
        has no orders at this merchant."""
        status, text = await self._post("/v1/order_history", {})
        if status in (401, 402, 403):
            raise FacetTerminalError("/v1/order_history", status, text)
        if status != 200:
            raise FacetTerminalError("/v1/order_history", status, text)
        obj = _json_obj(text)
        orders = obj.get("orders")
        return [o for o in orders if isinstance(o, dict)] if isinstance(orders, list) else []

    async def get_receipt(self, order_id: str) -> dict[str, Any] | None:
        """``POST /v1/get_receipt`` -> one order's receipt, or ``None`` on 404."""
        status, text = await self._post("/v1/get_receipt", {"order_id": order_id})
        if status == 404:
            return None
        if status != 200:
            raise FacetTerminalError("/v1/get_receipt", status, text)
        return _json_obj(text)

    # -- Checkout (non-custodial: create + price only, never settle) --------------

    async def create_checkout_session(
        self,
        *,
        line_items: list[dict[str, Any]],
        fulfillment: dict[str, Any] | None = None,
        rail_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a UCP checkout session for the cart and return it (``{id, totals,
        ...}``). This prices and reserves the cart only; no payment is signed or
        settled here, so no wallet key is involved.

        For a first-party merchant (when ``platform_terminal_url`` is configured),
        the create is routed through the platform's
        ``/ucp/v1/originated-checkouts`` so the platform adds the co-signature a
        dual-auth store requires, with a buyer-direct fallback on a 404. The buyer
        KYA is forwarded verbatim as the merchant KYA factor, exactly as the Deno
        buyer client does.
        """
        checkout: dict[str, Any] = {"line_items": line_items}
        if fulfillment is not None:
            checkout["fulfillment"] = fulfillment
        if rail_id is not None:
            checkout["rail_id"] = rail_id

        if self.platform_base is not None:
            originate_url = f"{self.platform_base}/ucp/v1/originated-checkouts"
            resp = await self._http.post(
                originate_url,
                headers=self._headers(),
                json={"target": self.base, "checkout": checkout},
            )
            if not (resp.status_code == 404 and "origination" in resp.text.lower()):
                if resp.status_code != 201:
                    raise FacetTerminalError(
                        "/ucp/v1/originated-checkouts", resp.status_code, resp.text
                    )
                return _json_obj(resp.text)
            # else: origination not provisioned, fall through to buyer-direct.

        resp = await self._http.post(
            f"{self.base}/ucp/v1/checkout-sessions",
            headers=self._headers(),
            json=checkout,
        )
        if resp.status_code != 201:
            raise FacetTerminalError(
                "/ucp/v1/checkout-sessions", resp.status_code, resp.text
            )
        return _json_obj(resp.text)

    def checkout_session_url(self, session_id: str) -> str:
        """The resource URL for a created session. This is the handoff target the
        host completes payment against; the shopping model never sees it."""
        return f"{self.base}/ucp/v1/checkout-sessions/{session_id}"


def _json_obj(text: str) -> dict[str, Any]:
    import json

    value = json.loads(text)
    if not isinstance(value, dict):
        raise FacetTerminalError("(response)", 200, "expected a JSON object")
    return value
