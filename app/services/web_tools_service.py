"""Network-backed analyzers built on the shared secure HTTP/SSRF infrastructure."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import tempfile
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

from defusedxml import ElementTree as ET

from app.core.exceptions import ProviderUnavailableError, ResolutionBlockedError, ResourceLimitError
from app.providers.web.ssrf import SSRFGuard
from app.services.ip_service import IPService
from app.services.webpage_service import WebpageService


class WebToolsService:
    def __init__(self, webpage: WebpageService, guard: SSRFGuard, ip_service: IPService) -> None:
        self._webpage = webpage
        self._guard = guard
        self._ip_service = ip_service

    async def security_headers(self, url: str) -> dict[str, Any]:
        result = await self._webpage.fetch(url)
        checks = [
            ("Content-Security-Policy", "content-security-policy", True),
            ("Strict-Transport-Security", "strict-transport-security", True),
            ("X-Content-Type-Options", "x-content-type-options", True),
            ("Referrer-Policy", "referrer-policy", True),
            ("Permissions-Policy", "permissions-policy", False),
            ("X-Frame-Options", "x-frame-options", False),
        ]
        items=[]
        for label,key,recommended in checks:
            present=key in {k.lower() for k in result.headers}
            items.append({"header":label,"present":present,"recommended":recommended,"value":result.headers.get(label) or result.headers.get(key)})
        score=round(sum(1 for x in items if x["present"]) / len(items) * 100)
        return {"url":result.url,"status_code":result.status_code,"headers":result.headers,"score":score,"checks":items}

    async def robots(self, url: str) -> dict[str, Any]:
        base = self._origin(url)
        result = await self._webpage.fetch(base + "/robots.txt")
        text=result.body.decode("utf-8", errors="replace")
        agents: dict[str, dict[str,list[str]]] = {}
        current: list[str] = []
        for raw in text.splitlines():
            line=raw.split("#",1)[0].strip()
            if not line or ":" not in line: continue
            key,val=[x.strip() for x in line.split(":",1)]
            low=key.lower()
            if low == "user-agent":
                current=[val]
                for agent in current: agents.setdefault(agent,{"allow":[],"disallow":[]})
            elif low in {"allow","disallow"}:
                for agent in current:
                    agents.setdefault(agent,{"allow":[],"disallow":[]})[low].append(val)
        sitemaps=[line.split(":",1)[1].strip() for line in text.splitlines() if line.strip().lower().startswith("sitemap:") and ":" in line]
        return {"url":result.url,"status_code":result.status_code,"user_agents":agents,"sitemaps":sitemaps}

    async def sitemap(self, url: str) -> dict[str, Any]:
        result=await self._webpage.fetch(url)
        try: root=ET.fromstring(result.body)
        except ET.ParseError: return {"url":result.url,"status_code":result.status_code,"is_index":False,"urls":[],"child_sitemaps":[],"valid_xml":False}
        def tag(x: str) -> str:
            return x.rsplit("}", 1)[-1]
        children=list(root)
        is_index=tag(root.tag)=="sitemapindex"
        urls=[]; child=[]
        if len(children) > 100_000:
            raise ResourceLimitError("Sitemap contains too many entries.")
        for item in children:
            data={}
            for node in list(item):
                data[tag(node.tag)]=node.text.strip() if node.text else None
            if is_index: child.append(data.get("loc"))
            else: urls.append({"loc":data.get("loc"),"lastmod":data.get("lastmod"),"changefreq":data.get("changefreq"),"priority":data.get("priority")})
        return {"url":result.url,"status_code":result.status_code,"is_index":is_index,"urls":urls,"child_sitemaps":child,"valid_xml":True}

    async def open_graph(self, url: str) -> dict[str, Any]:
        result=await self._webpage.fetch(url)
        parsed=self._webpage._parse_page(result.url,result.body,result.content_type)
        tags={k:v for k,v in parsed.get("meta_tags",{}).items() if k.lower().startswith("og:")}
        return {"url":result.url,"status_code":result.status_code,"tags":tags,"title":tags.get("og:title"),"description":tags.get("og:description"),"image":tags.get("og:image"),"canonical_url":tags.get("og:url"),"site_name":tags.get("og:site_name")}

    async def port_check(self, host: str, ports: list[int], timeout: float) -> dict[str, Any]:
        try:
            literal=ipaddress.ip_address(host.strip("[]"))
            if not literal.is_global: raise ResolutionBlockedError("Only public IP addresses are permitted.")
            addresses=[str(literal)]
        except ValueError:
            addresses=await self._guard.resolve_and_check(host)
        async def one(port: int) -> dict[str, Any]:
            last_error=None
            for addr in addresses[:4]:
                family=socket.AF_INET6 if ipaddress.ip_address(addr).version == 6 else socket.AF_INET
                try:
                    _,writer=await asyncio.wait_for(asyncio.open_connection(addr,port,family=family),timeout=timeout)
                    writer.close(); await writer.wait_closed()
                    return {"port":port,"open":True,"addresses":[addr],"error":None}
                except (TimeoutError, OSError) as exc: last_error=str(exc)
            return {"port":port,"open":False,"addresses":addresses,"error":last_error}
        return {"host":host,"results":await asyncio.gather(*(one(p) for p in ports))}

    async def tls_lookup(self, host: str, port: int) -> dict[str, Any]:
        try:
            literal=ipaddress.ip_address(host.strip("[]"))
            if not literal.is_global: raise ResolutionBlockedError("Only public TLS targets are permitted.")
            addresses=[str(literal)]
        except ValueError:
            addresses=await self._guard.resolve_and_check(host)
        addr=addresses[0]
        family=socket.AF_INET6 if ipaddress.ip_address(addr).version == 6 else socket.AF_INET
        context=ssl.create_default_context()
        context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
        try:
            raw_sock=socket.socket(family, socket.SOCK_STREAM)
            raw_sock.settimeout(5)
            raw_sock.connect((addr,port))
            try:
                host_ip = ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                host_ip = None
            server_name = None if isinstance(host_ip, ipaddress.IPv6Address) else host
            with context.wrap_socket(raw_sock, server_hostname=server_name) as sock:
                der=sock.getpeercert(binary_form=True)
                assert der is not None
                pem=ssl.DER_cert_to_PEM_cert(der)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as f:
                    f.write(pem); f.flush(); decoded=ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]
            fp=__import__("hashlib").sha256(der).hexdigest().upper()
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise ProviderUnavailableError(f"TLS certificate lookup failed: {exc}") from exc
        def pairs(items: Any) -> dict[Any, Any]: return {k:v for group in items for k,v in group}
        san=[v for k,v in decoded.get("subjectAltName",[]) if k == "DNS"]
        not_after=decoded.get("notAfter")
        expired=None
        if not_after:
            try: expired=datetime.strptime(not_after,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC) < datetime.now(UTC)
            except ValueError: pass
        return {"host":host,"port":port,"verified":False,"subject":pairs(decoded.get("subject",[])),"issuer":pairs(decoded.get("issuer",[])),"serial_number":decoded.get("serialNumber"),"version":decoded.get("version"),"not_before":decoded.get("notBefore"),"not_after":not_after,"san":san,"fingerprint_sha256":fp,"is_expired":expired}

    async def timezone(self, ip: str | None, latitude: float | None, longitude: float | None) -> dict[str, Any]:
        if ip:
            data=await self._ip_service.lookup(ip)
            return {"timezone":data.get("timezone"),"source":"ip-geo","country":data.get("country"),"country_code":data.get("country_code"),"latitude":data.get("lat"),"longitude":data.get("lon")}
        # 3geonames is a fixed, HTTPS, no-key coordinate lookup endpoint.
        # It is deliberately called through the same secure HTTP/SSRF layer
        # used by the other live analyzers, so outbound networking is centralized.
        target=f"https://api.3geonames.org/{latitude},{longitude}.json"
        result=await self._webpage.fetch(target)
        try:
            data=__import__("json").loads(result.body.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeError) as exc:
            raise ProviderUnavailableError("Coordinate timezone provider returned invalid data.") from exc
        zone=data.get("timezone") if isinstance(data,dict) else None
        if isinstance(zone,dict): zone=zone.get("name") or zone.get("id")
        if not isinstance(zone,str): zone=None
        return {"timezone":zone,"source":"3geonames","latitude":latitude,"longitude":longitude}

    # ── Website Technology Detector ───────────────────────────────────────

    async def detect_technologies(self, url: str) -> dict[str, Any]:
        result = await self._webpage.fetch(url)
        body = result.body.decode("utf-8", errors="replace").lower()
        headers_lower = {k.lower(): v for k, v in result.headers.items()}

        server = headers_lower.get("server")
        powered_by = headers_lower.get("x-powered-by")

        technologies: list[dict[str, str]] = []
        seen: set[str] = set()

        def _add(name: str, cat: str, conf: str, ev: str) -> None:
            if name not in seen:
                seen.add(name)
                technologies.append({"name": name, "category": cat, "confidence": conf, "evidence": ev})

        # ── Server / language detection from headers ──────────────────────
        if server:
            sl = server.lower()
            if "nginx" in sl: _add("Nginx", "server", "high", f"Server header: {server}")
            elif "apache" in sl: _add("Apache", "server", "high", f"Server header: {server}")
            elif "cloudflare" in sl: _add("Cloudflare", "cdn", "high", f"Server header: {server}")
            elif "microsoft-iis" in sl or "iis" in sl: _add("Microsoft IIS", "server", "high", f"Server header: {server}")
            elif "litespeed" in sl: _add("LiteSpeed", "server", "high", f"Server header: {server}")
            elif "openresty" in sl: _add("OpenResty", "server", "high", f"Server header: {server}")
            elif "caddy" in sl: _add("Caddy", "server", "high", f"Server header: {server}")
            elif "gunicorn" in sl: _add("Gunicorn", "server", "high", f"Server header: {server}")
            elif "uvicorn" in sl: _add("Uvicorn", "server", "medium", f"Server header: {server}")
            elif "node" in sl: _add("Node.js", "server", "medium", f"Server header: {server}")

        if powered_by:
            pl = powered_by.lower()
            if "php" in pl: _add("PHP", "language", "high", f"X-Powered-By: {powered_by}")
            elif "asp.net" in pl: _add("ASP.NET", "framework", "high", f"X-Powered-By: {powered_by}")
            elif "express" in pl: _add("Express.js", "framework", "high", f"X-Powered-By: {powered_by}")

        # ── CDN / infrastructure from headers ────────────────────────────
        if headers_lower.get("x-amz-cf-id") or headers_lower.get("x-amz-cf-pop"):
            _add("Amazon CloudFront", "cdn", "high", "AWS CloudFront headers present")
        if headers_lower.get("x-fastly-request-id"):
            _add("Fastly", "cdn", "high", "Fastly header present")
        if headers_lower.get("x-cdn") and "incapsula" in headers_lower.get("x-cdn", "").lower():
            _add("Incapsula/Imperva", "cdn", "medium", "Incapsula CDN header")
        if headers_lower.get("x-sucuri-id"):
            _add("Sucuri", "cdn", "high", "Sucuri header present")

        # ── HTML body pattern matching ────────────────────────────────────
        # CMS
        if "wp-content" in body or "wp-includes" in body:
            _add("WordPress", "cms", "high", "wp-content or wp-includes found")
        if "/sites/default/files/" in body or "drupal.js" in body or "drupal.min.js" in body:
            _add("Drupal", "cms", "high", "Drupal assets found")
        if "joomla" in body or "/media/jui/" in body:
            _add("Joomla", "cms", "high", "Joomla assets found")
        if "shopify" in body or "cdn.shopify.com" in body:
            _add("Shopify", "cms", "high", "Shopify CDN references found")
        if "squarespace" in body:
            _add("Squarespace", "cms", "medium", "Squarespace references found")
        if "wix.com" in body or "wixstatic" in body:
            _add("Wix", "cms", "high", "Wix assets found")
        if "ghost-portal" in body or "__ghost_context" in body:
            _add("Ghost", "cms", "high", "Ghost CMS markers found")
        if "contentful" in body:
            _add("Contentful", "cms", "medium", "Contentful references found")

        # Frameworks / JS
        if "react" in body or "_reactroot" in body or "data-reactroot" in body:
            _add("React", "framework", "medium", "React markers found")
        if "vue.js" in body or "vue.min.js" in body or "data-v-" in body or "v-cloak" in body:
            _add("Vue.js", "framework", "high", "Vue.js markers found")
        if "angular" in body or "ng-app" in body or "ng-version" in body or "ng-controller" in body:
            _add("Angular", "framework", "medium", "Angular markers found")
        if "jquery" in body or "jquery.min.js" in body:
            _add("jQuery", "library", "medium", "jQuery references found")
        if "bootstrap" in body or "bootstrap.min.css" in body or "bootstrap.min.js" in body:
            _add("Bootstrap", "library", "medium", "Bootstrap references found")
        if "tailwind" in body or "tailwindcss" in body:
            _add("Tailwind CSS", "library", "medium", "Tailwind references found")
        if "next.js" in body or "_next/" in body or "__next" in body:
            _add("Next.js", "framework", "high", "Next.js markers found")
        if "nuxt" in body or "_nuxt/" in body or "__nuxt" in body:
            _add("Nuxt.js", "framework", "high", "Nuxt.js markers found")
        if "gatsby" in body or "___gatsby" in body:
            _add("Gatsby", "framework", "high", "Gatsby markers found")
        if "svelte" in body or "svelte-" in body:
            _add("Svelte", "framework", "medium", "Svelte markers found")

        # Analytics
        if "google-analytics.com" in body or "googletagmanager.com" in body or "gtag(" in body:
            _add("Google Analytics", "analytics", "high", "Google Analytics/tracking found")
        if "googletagmanager.com" in body:
            _add("Google Tag Manager", "analytics", "high", "GTM container found")
        if "hotjar" in body:
            _add("Hotjar", "analytics", "medium", "Hotjar script found")
        if "plausible.io" in body or "plausible.js" in body:
            _add("Plausible Analytics", "analytics", "high", "Plausible script found")
        if "segment.com" in body or "segment.io" in body:
            _add("Segment", "analytics", "medium", "Segment analytics found")
        if "facebook.net" in body or "fbevents.js" in body:
            _add("Facebook Pixel", "analytics", "medium", "Facebook tracking found")
        if "doubleclick.net" in body:
            _add("DoubleClick", "analytics", "medium", "DoubleClick found")

        # Hosting / platforms
        if "vercel" in body or "vercel.app" in body:
            _add("Vercel", "hosting", "medium", "Vercel references found")
        if "netlify" in body:
            _add("Netlify", "hosting", "medium", "Netlify references found")
        if "firebase" in body or "firebaseapp.com" in body:
            _add("Firebase", "hosting", "medium", "Firebase references found")
        if "github.io" in body or "github.com" in body:
            _add("GitHub Pages", "hosting", "medium", "GitHub Pages references found")

        # Fonts
        if "fonts.googleapis.com" in body:
            _add("Google Fonts", "font", "high", "Google Fonts loaded")
        if "typekit" in body:
            _add("Adobe Typekit", "font", "medium", "Typekit references found")

        return {
            "url": result.url,
            "status_code": result.status_code,
            "technologies": technologies,
            "server": server,
            "powered_by": powered_by,
        }

    # ── Redirect Analyzer ─────────────────────────────────────────────────

    async def analyze_redirects(self, url: str, max_hops: int = 10) -> dict[str, Any]:
        from app.utils.url import normalize_url
        url = normalize_url(url)
        hops: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        current = url

        for _ in range(max_hops + 1):
            if current in seen_urls:
                hops.append({"url": current, "status_code": 0, "location": None, "redirect_type": None})
                break
            seen_urls.add(current)

            result = await self._webpage._fetch_once(current)
            status = result.status_code

            hop: dict[str, Any] = {
                "url": current,
                "status_code": status,
                "location": result.headers.get("location"),
                "redirect_type": None,
            }

            if status in (301, 302, 303, 307, 308):
                if status in (301, 308):
                    hop["redirect_type"] = "permanent"
                elif status in (302, 303, 307):
                    hop["redirect_type"] = "temporary"

            hops.append(hop)

            if status not in (301, 302, 303, 307, 308):
                break

            location = result.headers.get("location", "")
            if not location:
                break
            current = urljoin(current, location)
        else:
            # Exhausted hops — likely a loop.
            hops.append({"url": current, "status_code": 0, "location": None, "redirect_type": None})

        final_url = hops[-1]["url"] if hops else url
        is_loop = len(hops) > 1 and any(h["url"] == final_url for h in hops[:-1])

        orig_parsed = urlparse(url)
        has_https_redirect = orig_parsed.scheme == "http" and urlparse(final_url).scheme == "https"
        has_www_redirect = (orig_parsed.netloc or "").replace("www.", "") == (urlparse(final_url).netloc or "").replace("www.", "") and orig_parsed.netloc != urlparse(final_url).netloc

        return {
            "url": url,
            "final_url": final_url,
            "hops": hops,
            "total_hops": max(0, len(hops) - 1),
            "is_loop": is_loop,
            "has_https_redirect": has_https_redirect,
            "has_www_redirect": has_www_redirect,
        }

    # ── Content Type Detector ─────────────────────────────────────────────

    async def detect_content_type(self, url: str, check_body: bool = False) -> dict[str, Any]:
        result = await self._webpage.fetch(url)
        ct_header = result.headers.get("content-type", "")
        declared_type = ct_header.split(";")[0].strip() if ct_header else None
        charset = None
        if ";" in ct_header:
            for part in ct_header.split(";")[1:]:
                if "charset=" in part.lower():
                    charset = part.split("=", 1)[1].strip().strip('"')

        mime = declared_type
        is_html = bool(mime and "html" in mime.lower())
        is_json = bool(mime and "json" in mime.lower())
        is_xml = bool(mime and ("xml" in mime.lower()))
        is_binary = not (is_html or is_json or is_xml or (mime and "text/" in mime.lower()))

        body_sniffed = None
        if check_body and result.body:
            raw = result.body[:512]
            mime, _, _ = self._sniff_magic(raw)
            body_sniffed = mime

        return {
            "url": result.url,
            "declared_type": declared_type,
            "charset": charset,
            "mime_type": mime,
            "body_sniffed_type": body_sniffed,
            "is_html": is_html,
            "is_json": is_json,
            "is_xml": is_xml,
            "is_binary": is_binary,
        }

    @staticmethod
    def _sniff_magic(data: bytes) -> tuple[str, str | None, str]:
        _MAGIC: list[tuple[int, bytes, str, str, str]] = [
            (0, b"\x89PNG\r\n\x1a\n", "image/png", ".png", "PNG image"),
            (0, b"\xff\xd8\xff", "image/jpeg", ".jpg", "JPEG image"),
            (0, b"GIF87a", "image/gif", ".gif", "GIF image"),
            (0, b"GIF89a", "image/gif", ".gif", "GIF image"),
            (0, b"RIFF", "image/webp", ".webp", "WebP image"),
            (0, b"%PDF", "application/pdf", ".pdf", "PDF document"),
            (0, b"PK\x03\x04", "application/zip", ".zip", "ZIP archive"),
            (0, b"<!DOCTYPE", "text/html", ".html", "HTML document"),
            (0, b"<html", "text/html", ".html", "HTML document"),
            (0, b"<?xml", "text/xml", ".xml", "XML document"),
            (0, b"\x1f\x8b", "application/gzip", ".gz", "Gzip data"),
            (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ".7z", "7z archive"),
            (0, b"Rar!\x1a\x07", "application/x-rar-compressed", ".rar", "RAR archive"),
            (0, b"fLaC", "audio/flac", ".flac", "FLAC audio"),
            (0, b"ID3", "audio/mpeg", ".mp3", "MP3 audio"),
            (0, b"\x00\x00\x00\x1c\x66\x74\x79\x70", "video/mp4", ".mp4", "MP4 video"),
            (0, b"\x00\x00\x00\x20\x66\x74\x79\x70", "video/mp4", ".mp4", "MP4 video"),
            (0, b"\x1a\x45\xdf\xa3", "video/webm", ".webm", "WebM video"),
        ]
        for offset, magic, mime, ext, desc in _MAGIC:
            if data[offset:offset + len(magic)] == magic:
                return mime, ext, desc
        return "application/octet-stream", None, "Unknown binary data"

    # ── Canonical URL Checker ─────────────────────────────────────────────

    async def check_canonical(self, url: str) -> dict[str, Any]:
        result = await self._webpage.fetch(url)
        final_url = result.url

        canonical_url = None
        rel_canonical_header = None

        # Check HTTP Link header.
        link = result.headers.get("link", "")
        if link:
            for part in link.split(","):
                part = part.strip()
                if 'rel="canonical"' in part.lower() or "rel='canonical'" in part.lower():
                    if "<" in part and ">" in part:
                        rel_canonical_header = part.split("<")[1].split(">")[0]

        # Parse HTML for <link rel="canonical">.
        if result.body:
            body_text = result.body.decode("utf-8", errors="replace")
            import re
            m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', body_text, re.I)
            if not m:
                m = re.search(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']canonical["\']', body_text, re.I)
            if m:
                canonical_url = m.group(1)

        if not canonical_url and rel_canonical_header:
            canonical_url = rel_canonical_header

        has_canonical = canonical_url is not None
        is_self_referencing = canonical_url is not None and self._normalize_canonical(canonical_url) == self._normalize_canonical(final_url)

        return {
            "url": url,
            "final_url": final_url,
            "canonical_url": canonical_url,
            "has_canonical": has_canonical,
            "is_self_referencing": is_self_referencing,
            "is_valid_canonical": None,
            "status_code": result.status_code,
            "rel_canonical_header": rel_canonical_header,
        }

    @staticmethod
    def _normalize_canonical(u: str) -> str:
        p = urlparse(u)
        host = (p.netloc or "").lower().rstrip(".")
        path = (p.path or "/").rstrip("/") or "/"
        return f"{p.scheme}://{host}{path}"

    @staticmethod
    def _origin(url: str) -> str:
        p=urlparse(url)
        return f"{p.scheme}://{p.netloc}"
