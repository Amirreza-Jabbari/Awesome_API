"""DNS-based analyzers: DNSSEC validation and email-domain intelligence."""
from __future__ import annotations

import logging
from typing import Any

import dns.dnssec
import dns.exception
import dns.resolver

from app.core.exceptions import (
    DNSLookupError,
    DNSNXDomainError,
    DNSTimeoutError,
)
from app.providers.dns.dns_python import DNSPythonProvider
from app.providers.dns.models import DNSQuery
from app.utils.domain import normalize_domain

logger = logging.getLogger(__name__)

# Mail-provider hostname → friendly name mapping (kept small, extensible).
_MAIL_PROVIDER_MAP: list[tuple[str, str]] = [
    ("google.com", "Google Workspace / Gmail"),
    ("googlemail.com", "Google Workspace / Gmail"),
    ("gmail-smtp-in.l.google.com", "Google Workspace / Gmail"),
    ("outlook.com", "Microsoft 365 / Outlook"),
    ("protonmail.ch", "ProtonMail"),
    ("proton.me", "ProtonMail"),
    ("mx.zoho.com", "Zoho Mail"),
    ("mx.sourceforge.net", "SourceForge"),
    ("amazonses.com", "Amazon SES"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint"),
]


class DNSToolsService:
    """Service for DNS-based analysis tools (DNSSEC, email domain)."""

    def __init__(
        self,
        dns_provider: DNSPythonProvider,
        disposable_repo: Any = None,
        free_hosts: Any = None,
    ) -> None:
        self._dns = dns_provider
        self._disposable_repo = disposable_repo
        self._free_hosts = free_hosts

    # ── DNSSEC Validator ──────────────────────────────────────────────────

    async def dnssec_validate(self, domain: str) -> dict[str, Any]:
        domain = normalize_domain(domain)
        records: list[dict[str, Any]] = []

        dnskey_records = await self._query_raw(domain, "DNSKEY")
        ds_records = await self._query_raw(domain, "DS")

        for rdata in dnskey_records:
            records.append({
                "record_type": "DNSKEY",
                "flags": rdata.flags,
                "protocol": rdata.protocol,
                "algorithm": rdata.algorithm,
                "value": rdata.to_text(),
            })

        for rdata in ds_records:
            records.append({
                "record_type": "DS",
                "key_tag": rdata.key_tag,
                "algorithm": rdata.algorithm,
                "digest_type": rdata.digest_type,
                "value": rdata.to_text(),
            })

        has_dnskey = bool(dnskey_records)
        has_ds = bool(ds_records)
        # A signed zone always carries RRSIGs over its authoritative records,
        # which requires a published DNSKEY. Deriving the flag this way avoids
        # the invalid standalone RRSIG lookup.
        has_rrsig = has_dnskey
        dnssec_enabled = has_dnskey or has_ds

        chain_valid: bool | None = None
        if has_dnskey and has_ds:
            chain_valid = self._check_chain(dnskey_records, ds_records)

        return {
            "domain": domain,
            "dnssec_enabled": dnssec_enabled,
            "has_dnskey": has_dnskey,
            "has_ds": has_ds,
            "has_rrsig": has_rrsig,
            "chain_valid": chain_valid,
            "records": records,
            "error": None,
        }

    def _check_chain(self, dnskey_rdata: list[Any], ds_rdata: list[Any]) -> bool:
        """Check whether any DS record tag matches a DNSKEY tag."""
        dnskey_tags = set()
        for r in dnskey_rdata:
            try:
                tag = dns.dnssec.key_id(r)
                dnskey_tags.add(tag)
            except Exception:
                continue
        return any(r.key_tag in dnskey_tags for r in ds_rdata)

    async def _query_raw(self, domain: str, rtype: str) -> list[Any]:
        """Query arbitrary DNS record types via the provider's resolver."""
        try:
            answer = await self._dns.resolver.resolve(domain, rtype)
            return [rdata for rdata in answer]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            raise DNSNXDomainError(f"Domain does not exist: {domain}") from None
        except dns.resolver.LifetimeTimeout:
            raise DNSTimeoutError(f"DNS lookup timed out for {domain}") from None
        except dns.resolver.NoNameservers:
            raise DNSLookupError(f"No nameservers for {domain}") from None
        except dns.exception.DNSException:
            return []

    # ── Email Domain Analyzer ─────────────────────────────────────────────

    async def email_domain_analyze(self, domain: str) -> dict[str, Any]:
        domain = normalize_domain(domain)

        mx_records = await self._get_mx(domain)
        spf_record = await self._get_txt_first(domain, "SPF")
        dmarc_record = await self._get_dmarc(domain)

        spf_valid = self._validate_spf(spf_record) if spf_record else None
        dmarc_policy = self._extract_dmarc_policy(dmarc_record)
        dmarc_pct = self._extract_dmarc_pct(dmarc_record)

        mail_provider = self._detect_mail_provider(mx_records)

        is_disposable = self._is_disposable(domain)
        is_free = self._is_free_provider(domain)

        return {
            "domain": domain,
            "has_mx": bool(mx_records),
            "mx_records": [{"priority": m["priority"], "host": m["host"]} for m in mx_records],
            "spf_record": spf_record,
            "spf_valid": spf_valid,
            "dmarc_record": dmarc_record,
            "dmarc_policy": dmarc_policy,
            "dmarc_pct": dmarc_pct,
            "is_disposable": is_disposable,
            "is_free_provider": is_free,
            "mail_provider": mail_provider,
            "has_dmarc": dmarc_record is not None,
            "has_spf": spf_record is not None,
        }

    def _is_disposable(self, domain: str) -> bool:
        holder = self._disposable_repo
        if holder is None:
            return False
        if hasattr(holder, "contains"):
            return bool(holder.contains(domain))
        if hasattr(holder, "is_disposable"):
            return bool(holder.is_disposable(domain))
        try:
            return domain in holder
        except TypeError:
            return False

    def _is_free_provider(self, domain: str) -> bool:
        holder = self._free_hosts
        if holder is None:
            return False
        if hasattr(holder, "contains"):
            return bool(holder.contains(domain))
        if hasattr(holder, "is_public"):
            return bool(holder.is_public(domain))
        try:
            return domain in holder
        except TypeError:
            return False

    async def _get_mx(self, domain: str) -> list[dict[str, Any]]:
        try:
            result = await self._dns.lookup(DNSQuery(domain=domain, record_types=("MX",)))
            return [
                {"priority": r.priority or 0, "host": r.value}
                for r in result.records
                if r.record_type == "MX"
            ]
        except (DNSLookupError, DNSNXDomainError, DNSTimeoutError):
            return []

    async def _get_txt_first(self, domain: str, prefix: str) -> str | None:
        """Return the first TXT record whose content starts with 'prefix'."""
        try:
            result = await self._dns.lookup(DNSQuery(domain=domain, record_types=("TXT",)))
            for r in result.records:
                if r.record_type == "TXT" and r.value.strip().lower().startswith(prefix.lower()):
                    return r.value.strip()
        except (DNSLookupError, DNSNXDomainError, DNSTimeoutError):
            pass
        return None

    async def _get_dmarc(self, domain: str) -> str | None:
        return await self._get_txt_first(f"_dmarc.{domain}", "v=DMARC1")

    @staticmethod
    def _validate_spf(record: str) -> bool:
        return record.strip().lower().startswith("v=spf1")

    @staticmethod
    def _extract_dmarc_policy(record: str | None) -> str | None:
        if not record:
            return None
        for part in record.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2 and kv[0].strip().lower() == "p":
                return kv[1].strip().lower()
        return None

    @staticmethod
    def _extract_dmarc_pct(record: str | None) -> int | None:
        if not record:
            return None
        for part in record.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2 and kv[0].strip().lower() == "pct":
                try:
                    return int(kv[1].strip())
                except ValueError:
                    pass
        return None

    @staticmethod
    def _detect_mail_provider(mx_records: list[dict[str, Any]]) -> str | None:
        for mx in mx_records:
            host = mx["host"].lower().rstrip(".")
            for pattern, name in _MAIL_PROVIDER_MAP:
                if pattern in host:
                    return name
        return None
