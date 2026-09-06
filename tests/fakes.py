"""Offline fakes for external providers.

Used by the test suite so no test depends on the internet, public DNS,
third-party APIs or WHOIS servers. Each fake stores recorded calls so tests can
assert on provider interaction.
"""

from __future__ import annotations

from app.core.exceptions import (
    ProviderTimeoutError,
    WHOISUnavailableError,
)
from app.providers.dns.models import (
    DNSLookupResult,
    DNSQuery,
    DNSRecord,
    MXData,
)
from app.providers.geoip.base import GeoIPResult
from app.providers.ipintel.base import IPIntelligence
from app.providers.whois.base import (
    RegistryNotFoundError,
    RegistryRecord,
)


class FakeDNSProvider:
    """Deterministic DNS provider.

    Maps domains to a hand-built A/AAAA/MX/NS/TXT record set. Raises
    ``ProviderTimeoutError`` for the special domain ``timeout.test`` to exercise
    the service-level timeout branch, and returns empty results for unknown
    domains so NXDOMAIN behaviour is represented.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []
        # Map a hostname to specific addresses for SSRF/blocking tests.
        self.addr_table: dict[str, list[str]] = {}
        self._mx_override: dict[str, list[str]] = {}

    async def lookup(self, query: DNSQuery) -> DNSLookupResult:
        self.calls.append(f"lookup:{query.domain}")
        return self._result(query.domain, query.record_types)

    async def lookup_mx(self, domain: str) -> DNSLookupResult:
        self.calls.append(f"lookup_mx:{domain}")
        return self._result(domain, ("MX",))

    async def resolve_a(self, domain: str) -> list[str]:
        self.calls.append(f"resolve_a:{domain}")
        table = {
            "example.com": ["93.184.216.34"],
            "github.com": ["140.82.112.3"],
            "gmail.com": ["142.250.4.13"],
            "google.com": ["142.250.4.14"],
        }
        return list(table.get(domain, []))

    async def resolve_a_aaaa(self, host: str) -> list[str]:
        self.calls.append(f"resolve_a_aaaa:{host}")
        if host in self.addr_table:
            return list(self.addr_table[host])
        if host == "ipv6.test":
            return ["2606:2800:220:1:248:1893:25c8:1946"]
        if host == "timeout.test":
            raise ProviderTimeoutError("dns timeout")
        return await self.resolve_a(host)

    async def get_mx_hosts(self, domain: str) -> list[MXData]:
        self.calls.append(f"get_mx:{domain}")
        if domain in self._mx_override:
            return [MXData(10, hostname) for hostname in self._mx_override[domain]]

        table = {
            "gmail.com": [MXData(10, "aspmx.l.google.com")],
            "example.com": [MXData(10, "mx.example.net")],
            "nomx.test": [],
            "google.com": [MXData(10, "aspmx.l.google.com")],
        }
        return list(table.get(domain, []))

    def _result(self, domain: str, types: tuple[str, ...]) -> DNSLookupResult:
        records: dict[str, list[DNSRecord]] = {
            "A": [
                DNSRecord(record_type="A", value="93.184.216.34", ttl=3600),
                DNSRecord(record_type="A", value="93.184.215.34", ttl=3600),
            ],
            "AAAA": [DNSRecord(record_type="AAAA", value="2606:2800:220:1:248:1893:25c8:1946")],
            "MX": [DNSRecord(record_type="MX", value="mx.example.net", priority=10)],
            "NS": [DNSRecord(record_type="NS", value="a.iana-servers.net")],
            "SOA": [
                DNSRecord(
                    record_type="SOA",
                    value="ns1.example.com hostmaster.example.com 2024010101",
                    mname="ns1.example.com",
                    rname="hostmaster.example.com",
                    serial=2024010101,
                )
            ],
            "TXT": [
                DNSRecord(record_type="TXT", value="v=spf1 -all"),
                DNSRecord(record_type="TXT", value="google-site-verification=abc"),
            ],
            "CNAME": [DNSRecord(record_type="CNAME", value="www.example.com")],
        }
        out: list[DNSRecord] = []
        resolved_types = types if types else tuple(records.keys())
        for rt in resolved_types:
            if rt in records:
                out.extend(records[rt])
        return DNSLookupResult(domain=domain, records=out)


class FakeGeoIPProvider:
    def __init__(self, result: GeoIPResult | None = None) -> None:
        self._result = result or GeoIPResult()
        self.calls: list[str] = []

    async def lookup(self, ip: str) -> GeoIPResult:
        self.calls.append(ip)
        return self._result


class FakeIPIntelligenceProvider:
    def __init__(self, result: IPIntelligence | None = None) -> None:
        self._result = result or IPIntelligence()
        self.calls: list[str] = []

    async def lookup(self, ip: str) -> IPIntelligence:
        self.calls.append(ip)
        return self._result


class _FailingWhoIsProvider:
    async def lookup(self, domain: str) -> RegistryRecord:
        raise WHOISUnavailableError("registry unavailable")


class FakeRDPAProvider:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self._registered = True
        self._unavailable = False

    def set_registered(self, registered: bool) -> None:
        self._registered = registered

    def set_unavailable(self, unavailable: bool) -> None:
        self._unavailable = unavailable

    async def lookup(self, domain: str) -> RegistryRecord:
        self.calls.append(domain)
        if self._unavailable:
            raise WHOISUnavailableError("rdap unavailable")
        if not self._registered:
            raise RegistryNotFoundError("no match")
        return RegistryRecord(
            domain_name=domain.upper(),
            registrar="Example Registrar",
            registrar_url="https://example.com/registrar",
            whois_server="whois.example.com",
            updated_date=1700000000,
            creation_date=1600000000,
            expiration_date=1800000000,
            name_servers=["ns1.example.com"],
            dnssec="signed",
            status=["clientTransferProhibited"],
            source="rdap",
        )


class FakeWhoIsProvider:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self._unavailable = False

    def set_unavailable(self, value: bool) -> None:
        self._unavailable = value

    async def lookup(self, domain: str) -> RegistryRecord:
        self.calls.append(domain)
        if self._unavailable:
            raise WHOISUnavailableError("no whois server")
        return RegistryRecord(
            domain_name=domain.upper(),
            registrar="Whois Registrar Ltd",
            registrar_url="https://whois.example.com",
            whois_server="whois.whois.example.com",
            creation_date=1640000000,
            source="whois",
        )
