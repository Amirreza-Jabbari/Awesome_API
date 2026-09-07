from __future__ import annotations

from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core.exceptions import (
    DNSLookupError,
    DNSNoDataError,
    DNSNXDomainError,
    DNSTimeoutError,
)
from app.providers.dns.models import (
    DNSLookupResult,
    DNSQuery,
    DNSRecord,
    MXData,
)


class DNSPythonProvider:
    """
    DNS provider backed by dnspython's native asynchronous resolver.

    The provider translates dnspython-specific exceptions into application
    exceptions and normalizes DNS records into application models.
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 3.0,
        lifetime: float = 5.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError(
                "DNS timeout must be greater than zero."
            )

        if lifetime <= 0:
            raise ValueError(
                "DNS lifetime must be greater than zero."
            )

        if lifetime < timeout:
            raise ValueError(
                "DNS lifetime must be greater than or equal to timeout."
            )

        self._nameservers = [
            nameserver.strip()
            for nameserver in (nameservers or [])
            if isinstance(nameserver, str)
            and nameserver.strip()
        ]

        self._timeout = float(timeout)
        self._lifetime = float(lifetime)

        self._resolver: dns.asyncresolver.Resolver | None = None

    @property
    def resolver(self) -> dns.asyncresolver.Resolver:
        """
        Lazily construct the dnspython resolver.
        """
        if self._resolver is None:
            resolver = dns.asyncresolver.Resolver(
                configure=not bool(self._nameservers)
            )

            if self._nameservers:
                resolver.nameservers = list(self._nameservers)

            resolver.timeout = self._timeout
            resolver.lifetime = self._lifetime

            self._resolver = resolver

        return self._resolver

    async def lookup(
        self,
        query: DNSQuery,
    ) -> DNSLookupResult:
        """
        Resolve all requested record types.

        NODATA is treated as an empty result for that particular type.

        Other DNS failures propagate because the caller may need to
        distinguish a successful empty result from an unsuccessful lookup.
        """
        records: list[DNSRecord] = []

        for record_type in query.record_types:
            try:
                if record_type == "A":
                    records.extend(
                        await self._resolve_a_records(query.domain)
                    )

                elif record_type == "AAAA":
                    records.extend(
                        await self._resolve_aaaa_records(query.domain)
                    )

                elif record_type == "MX":
                    records.extend(
                        await self._resolve_mx_records(query.domain)
                    )

                elif record_type == "NS":
                    records.extend(
                        await self._resolve_ns_records(query.domain)
                    )

                elif record_type == "SOA":
                    records.extend(
                        await self._resolve_soa_records(query.domain)
                    )

                elif record_type == "TXT":
                    records.extend(
                        await self._resolve_txt_records(query.domain)
                    )

                elif record_type == "CNAME":
                    records.extend(
                        await self._resolve_cname_records(query.domain)
                    )

                else:
                    raise ValueError(
                        f"Unsupported DNS record type: {record_type}"
                    )

            except DNSNoDataError:
                # No records for this specific type is a valid DNS result.
                continue

        return DNSLookupResult(
            domain=query.domain,
            records=records,
        )

    async def lookup_mx(
        self,
        domain: str,
    ) -> DNSLookupResult:
        """
        Convenience method for MX-only lookups.
        """
        return await self.lookup(
            DNSQuery(
                domain=domain,
                record_types=("MX",),
            )
        )

    async def _query(
        self,
        domain: str,
        record_type: str,
    ) -> Any:
        """
        Execute one native asynchronous DNS query and translate exceptions.
        """
        try:
            return await self.resolver.resolve(
                domain,
                record_type,
                lifetime=self._lifetime,
            )

        except dns.resolver.NXDOMAIN as exc:
            raise DNSNXDomainError(
                f"DNS domain does not exist: {domain}"
            ) from exc

        except dns.resolver.NoAnswer as exc:
            raise DNSNoDataError(
                f"No {record_type} records found for {domain}"
            ) from exc

        except dns.resolver.NoNameservers as exc:
            raise DNSLookupError(
                f"No DNS nameservers available for {domain}"
            ) from exc

        except dns.resolver.LifetimeTimeout as exc:
            raise DNSTimeoutError(
                f"DNS lookup timed out for {domain}"
            ) from exc

        except dns.exception.Timeout as exc:
            raise DNSTimeoutError(
                f"DNS lookup timed out for {domain}"
            ) from exc

        except TimeoutError as exc:
            raise DNSTimeoutError(
                f"DNS lookup timed out for {domain}"
            ) from exc

        except dns.exception.DNSException as exc:
            raise DNSLookupError(
                f"DNS lookup failed for {domain}"
            ) from exc

    async def _resolve_a_records(
        self,
        domain: str,
    ) -> list[DNSRecord]:
        answer = await self._query(domain, "A")

        ttl = self._extract_ttl(answer)

        return [
            DNSRecord(
                record_type="A",
                value=str(record.address),
                ttl=ttl,
            )
            for record in answer
        ]

    async def _resolve_aaaa_records(
        self,
        domain: str,
    ) -> list[DNSRecord]:
        answer = await self._query(domain, "AAAA")

        ttl = self._extract_ttl(answer)

        return [
            DNSRecord(
                record_type="AAAA",
                value=str(record.address),
                ttl=ttl,
            )
            for record in answer
        ]

    async def _resolve_mx_records(
        self,
        domain: str,
    ) -> list[DNSRecord]:
        answer = await self._query(domain, "MX")

        ttl = self._extract_ttl(answer)

        records = [
            DNSRecord(
                record_type="MX",
                priority=int(record.preference),
                value=str(record.exchange).rstrip("."),
                ttl=ttl,
            )
            for record in answer
        ]

        records.sort(
            key=lambda record: (
                record.priority if record.priority is not None else 0,
                record.value,
            )
        )

        return records

    async def _resolve_ns_records(
        self,
        domain: str,
    ) -> list[DNSRecord]:
        answer = await self._query(domain, "NS")

        ttl = self._extract_ttl(answer)

        records = [
            DNSRecord(
                record_type="NS",
                value=str(record.target).rstrip("."),
                ttl=ttl,
            )
            for record in answer
        ]

        records.sort(key=lambda record: record.value)

        return records

    async def _resolve_soa_records(
        self,
        domain: str,
    ) -> list[DNSRecord]:
        answer = await self._query(domain, "SOA")

        ttl = self._extract_ttl(answer)

        record = answer[0]

        return [
            DNSRecord(
                record_type="SOA",
                value=str(record.mname).rstrip("."),
                ttl=ttl,
                mname=str(record.mname).rstrip("."),
                rname=str(record.rname).rstrip("."),
                serial=int(record.serial),
                refresh=int(record.refresh),
                retry=int(record.retry),
                expire=int(record.expire),
                minimum=int(record.minimum),
            )
        ]

    async def _resolve_txt_records(
        self,
        domain: str,
    ) -> list[DNSRecord]:
        answer = await self._query(domain, "TXT")

        ttl = self._extract_ttl(answer)

        records: list[DNSRecord] = []

        for record in answer:
            parts: list[str] = []

            for value in record.strings:
                if isinstance(value, bytes):
                    parts.append(
                        value.decode(
                            "utf-8",
                            errors="replace",
                        )
                    )
                else:
                    parts.append(str(value))

            records.append(
                DNSRecord(
                    record_type="TXT",
                    value="".join(parts),
                    ttl=ttl,
                )
            )

        return records

    async def _resolve_cname_records(
        self,
        domain: str,
    ) -> list[DNSRecord]:
        answer = await self._query(domain, "CNAME")

        ttl = self._extract_ttl(answer)

        return [
            DNSRecord(
                record_type="CNAME",
                value=str(record.target).rstrip("."),
                ttl=ttl,
            )
            for record in answer
        ]

    @staticmethod
    def _extract_ttl(answer: Any) -> int | None:
        """
        Extract the common TTL from a dnspython answer.

        dnspython answers normally expose TTL through the response's
        rrset. Return None defensively when it is unavailable.
        """
        try:
            rrset = answer.rrset

            if rrset is None:
                return None

            return int(rrset.ttl)

        except (AttributeError, TypeError, ValueError):
            return None

    async def resolve_a(
        self,
        domain: str,
    ) -> list[str]:
        """
        Best-effort A resolution.

        DNS errors are intentionally swallowed because this convenience
        method historically returns a list rather than exposing DNS state.
        """
        try:
            answer = await self._query(domain, "A")

        except (
            DNSNoDataError,
            DNSNXDomainError,
            DNSTimeoutError,
            DNSLookupError,
        ):
            return []

        return [
            str(record.address)
            for record in answer
        ]

    async def resolve_a_aaaa(
        self,
        host: str,
    ) -> list[str]:
        """
        Best-effort resolution of A and AAAA records.

        A and AAAA are resolved independently so that failure of one
        record type does not suppress successful results from the other.
        """
        addresses: list[str] = []
        seen: set[str] = set()

        try:
            a_records = await self._query(host, "A")

        except (
            DNSNoDataError,
            DNSNXDomainError,
            DNSTimeoutError,
            DNSLookupError,
        ):
            a_records = None

        if a_records is not None:
            for record in a_records:
                address = str(record.address)

                if address not in seen:
                    seen.add(address)
                    addresses.append(address)

        try:
            aaaa_records = await self._query(host, "AAAA")

        except (
            DNSNoDataError,
            DNSNXDomainError,
            DNSTimeoutError,
            DNSLookupError,
        ):
            aaaa_records = None

        if aaaa_records is not None:
            for record in aaaa_records:
                address = str(record.address)

                if address not in seen:
                    seen.add(address)
                    addresses.append(address)

        return addresses

    async def get_mx_hosts(
        self,
        domain: str,
    ) -> list[MXData]:
        """
        Return normalized MX records.

        Important semantic contract:

            []     = MX query completed successfully but there are no
                     usable MX records.

            raises = DNS lookup could not be completed or the domain
                     could not be resolved.

        Null MX (`MX 0 .`) is represented as an empty hostname here.
        Higher layers must not treat an empty hostname as an MX provider.
        """
        try:
            answer = await self._query(domain, "MX")
        except DNSNoDataError:
            # A valid DNS name may legitimately have no MX RRset.
            return []

        hosts: list[MXData] = []

        for record in answer:
            hostname = str(record.exchange).rstrip(".")

            # RFC 7505 Null MX (priority 0, exchange ".") means the domain
            # explicitly does not accept mail. It is not a usable MX host and
            # must never make has_mx=True or become a provider match.
            if not hostname:
                continue

            hosts.append(
                MXData(
                    priority=int(record.preference),
                    hostname=hostname,
                )
            )

        hosts.sort(
            key=lambda item: (
                item.priority,
                item.hostname,
            )
        )

        return hosts
