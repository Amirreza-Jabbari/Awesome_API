"""API v1 routers.

Each router maps an HTTP request to one application service. Services are
injected via ``request.app.state`` so routing stays thin and testable.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    cron_tools,
    data_tools,
    dev_tools,
    disposable_email,
    dns,
    domain,
    email,
    http_tools,
    ip,
    mx,
    password,
    phone,
    toolbox,
    url,
    user_agent,
    webpage,
    whois,
    design_system,
    browser_intelligence,
)

api_router = APIRouter()

api_router.include_router(disposable_email.router)
api_router.include_router(dns.router)
api_router.include_router(domain.router)
api_router.include_router(email.router)
api_router.include_router(ip.router)
api_router.include_router(mx.router)
api_router.include_router(password.router)
api_router.include_router(phone.router)
api_router.include_router(url.router)
api_router.include_router(user_agent.router)
api_router.include_router(webpage.router)
api_router.include_router(design_system.router)
api_router.include_router(browser_intelligence.router)
api_router.include_router(whois.router)

api_router.include_router(toolbox.router)

api_router.include_router(data_tools.router)
api_router.include_router(http_tools.router)
api_router.include_router(dev_tools.router)
api_router.include_router(cron_tools.router)
