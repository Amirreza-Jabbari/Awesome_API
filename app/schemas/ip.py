"""IP lookup schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.utils.ip import parse_ip


class IPLookupRequest(BaseModel):
    ip: str = Field(description="The IPv4 or IPv6 address to inspect.", min_length=1, max_length=45)

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        try:
            return str(parse_ip(v))
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc


class IPLookupResponse(BaseModel):
    address: str = Field(description="The canonical IP address.")
    ip_version: int
    is_valid: bool = True
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    region_code: str | None = None
    city: str | None = None
    zip: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None
    isp: str | None = None
    is_datacenter: bool | None = None
    is_hosting: bool | None = None
    is_tor: bool | None = None
    is_vpn: bool | None = None
    is_icloud_relay: bool | None = None
    is_bogon: bool | None = None
    is_abuser: bool | None = None
    threat_level: str | None = None
    asn: str | None = None
    asn_name: str | None = None
    route: str | None = None
    abuse_email: str | None = None
    is_private: bool = False
    is_loopback: bool = False
    is_multicast: bool = False
