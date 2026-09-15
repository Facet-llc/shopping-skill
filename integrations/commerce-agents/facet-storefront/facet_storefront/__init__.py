# Copyright 2026 Facet, LLC
# SPDX-License-Identifier: Apache-2.0

"""Facet storefront backend for Anthropic's ``commerce-agents`` Shopping Agent.

Import :class:`FacetStorefrontBackend`, construct it with a merchant Terminal URL
and the customer's Facet KYA, and hand it to any ``commerce-agents`` runtime.
"""

from __future__ import annotations

from .backend import FacetStorefrontBackend
from .client import FacetTerminalClient, FacetTerminalError

__all__ = [
    "FacetStorefrontBackend",
    "FacetTerminalClient",
    "FacetTerminalError",
]

__version__ = "0.1.0"
