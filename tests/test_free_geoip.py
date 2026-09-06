"""Offline tests for the no-key IP intelligence provider."""

from __future__ import annotations

import httpx
from app.providers.geoip.free import FreeIPIntelligenceProvider


async def test_free_provider_combines_sources() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "ipwho.is":
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "country": "United States",
                    "country_code": "US",
                    "region": "Illinois",
                    "region_code": "IL",
                    "city": "Chicago",
                    "postal": "60620",
                    "latitude": 41.7405,
                    "longitude": -87.6587,
                    "timezone": {"id": "America/Chicago"},
                    "connection": {
                        "asn": 7922,
                        "org": "Comcast Cable Communications, LLC",
                        "isp": "Comcast Cable Communications, LLC",
                    },
                },
            )
        if request.url.host == "api.ipapi.is":
            return httpx.Response(
                200,
                json={
                    "ip": "73.9.149.180",
                    "is_bogon": False,
                    "is_datacenter": False,
                    "is_tor": False,
                    "is_vpn": False,
                    "is_abuser": False,
                    "company_name": "Comcast Cable Communications, LLC",
                    "asn_num": 7922,
                    "asn_org": "Comcast Cable Communications, LLC",
                    "cc": "US",
                },
            )
        return httpx.Response(
            200,
            json={
                "cidr0_cidrs": [{"v4prefix": "73.0.0.0", "length": 8}],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse@example.com"]],
                        ],
                    }
                ],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await FreeIPIntelligenceProvider(client).lookup("73.9.149.180")

    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.city == "Chicago"
    assert result.asn == "AS7922"
    assert result.is_datacenter is False
    assert result.is_tor is False
    assert result.is_vpn is False
    assert result.route == "73.0.0.0/8"
    assert result.abuse_email == "abuse@example.com"
