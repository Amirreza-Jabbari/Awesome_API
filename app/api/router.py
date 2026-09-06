"""Versioned API router aggregation.

V1 is intentionally kept intact. Future versions can be mounted beside it
without changing existing consumers or importing V1 internals into V2.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.router import api_router as v1_router

API_V1_PREFIX = "/api/v1"


def build_api_router() -> APIRouter:
    router = APIRouter()
    # Version boundary: add ``/api/v2`` here when a genuinely breaking API is
    # introduced. V1 remains frozen and independently mountable.
    router.include_router(v1_router)
    return router


api_router = build_api_router()
