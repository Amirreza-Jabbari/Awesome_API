"""Pure/local utility services with no external provider requirements."""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import re
import secrets
import uuid
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from typing import Any, ClassVar
from urllib.parse import quote, unquote
from zoneinfo import ZoneInfo

import jwt
import regex as safe_regex

from app.core.limits import load_json_limited

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_UUID_NS = {"dns": uuid.NAMESPACE_DNS, "url": uuid.NAMESPACE_URL, "oid": uuid.NAMESPACE_OID, "x500": uuid.NAMESPACE_X500}
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128, "blake2b": 128, "blake2s": 64}

class ToolboxService:
    @staticmethod
    def inspect_jwt(token: str) -> dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {"is_valid": False, "signature_present": False, "error": "JWT must contain three segments."}
        try:
            def dec(segment: str) -> Any:
                raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
                return json.loads(raw.decode("utf-8"))
            header = dec(parts[0]); payload = dec(parts[1])
            if not isinstance(header, dict) or not isinstance(payload, dict):
                raise ValueError("JWT header and payload must be JSON objects.")
            alg = header.get("alg")
            exp = payload.get("exp")
            now = int(datetime.now(UTC).timestamp())
            return {"is_valid": True, "header": header, "payload": payload, "signature_present": bool(parts[2]),
                    "algorithm": alg if isinstance(alg, str) else None, "token_type": header.get("typ"),
                    "issuer": payload.get("iss"), "audience": payload.get("aud"), "subject": payload.get("sub"),
                    "issued_at": payload.get("iat") if isinstance(payload.get("iat"), int) else None,
                    "expires_at": exp if isinstance(exp, int) else None,
                    "not_before": payload.get("nbf") if isinstance(payload.get("nbf"), int) else None,
                    "is_expired": exp < now if isinstance(exp, (int, float)) else None}
        except (ValueError, UnicodeError, json.JSONDecodeError, binascii.Error) as exc:
            return {"is_valid": False, "signature_present": bool(parts[2]), "error": f"Invalid JWT encoding: {exc}"}

    @staticmethod
    def generate_jwt(payload: dict[str, object], algorithm: str, secret: str, expires_in: int,
                     issuer: str | None, subject: str | None, audience: object | None,
                     token_id: str | None, headers: dict[str, str] | None) -> dict[str, Any]:
        now = int(datetime.now(UTC).timestamp())
        claims: dict[str, object] = {}
        claims.update(payload)
        if issuer is not None:
            claims["iss"] = issuer
        if subject is not None:
            claims["sub"] = subject
        if audience is not None:
            claims["aud"] = audience
        if token_id is not None:
            claims["jti"] = token_id
        claims["iat"] = now
        expires_at = now + expires_in
        claims["exp"] = expires_at
        extra_headers = dict(headers or {})
        extra_headers.pop("alg", None)
        extra_headers.pop("typ", None)
        extra_headers.setdefault("typ", "JWT")
        token = jwt.encode(claims, secret, algorithm=algorithm, headers=extra_headers)
        return {"token": token, "token_type": "JWT", "algorithm": algorithm,
                "header": jwt.get_unverified_header(token), "payload": claims,
                "issued_at": now, "expires_at": expires_at, "expires_in": expires_in}

    @staticmethod
    def _decode_input(value: str, encoding: str) -> bytes:
        if encoding == "utf-8": return value.encode("utf-8")
        if encoding == "base64": return base64.b64decode(value, validate=True)
        if encoding == "hex": return bytes.fromhex(value)
        raise ValueError("Unsupported encoding")

    @classmethod
    def hash_generate(cls, value: str, algorithm: str, encoding: str) -> dict[str, str]:
        digest = hashlib.new(algorithm, cls._decode_input(value, encoding)).digest()
        return {"algorithm": algorithm, "digest_hex": digest.hex(), "digest_base64": base64.b64encode(digest).decode(), "input_encoding": encoding}

    @staticmethod
    def hash_identify(value: str) -> dict[str, Any]:
        normalized = value.strip()
        candidates: list[dict[str, str]] = []
        if re.fullmatch(r"[0-9a-fA-F]+", normalized):
            length = len(normalized)
            for alg, size in _HASH_LENGTHS.items():
                if length == size:
                    candidates.append({"algorithm": alg, "confidence": "high" if alg in {"md5", "sha1", "sha256", "sha512"} else "medium", "reason": f"Hex digest length matches {size} characters."})
        elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", normalized) and len(normalized) % 4 == 0:
            try:
                raw = base64.b64decode(normalized, validate=True)
                for alg, size in _HASH_LENGTHS.items():
                    if len(raw) * 2 == size:
                        candidates.append({"algorithm": alg, "confidence": "medium", "reason": "Base64-decoded digest length matches the algorithm."})
            except binascii.Error: pass
        return {"normalized": normalized, "length": len(normalized), "candidates": candidates, "note": "Hash identification is heuristic; multiple algorithms/formats can share the same length."}

    @staticmethod
    def codec(value: str, mode: str, encoding: str) -> str:
        if mode == "encode":
            raw = value.encode("utf-8") if encoding == "utf-8" else bytes.fromhex(value) if encoding == "hex" else value.encode("utf-8")
            return base64.b64encode(raw).decode("ascii")
        raw = base64.b64decode(value, validate=True)
        if encoding == "utf-8": return raw.decode("utf-8")
        if encoding == "hex": return raw.hex()
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def url_codec(value: str, mode: str, component: bool) -> str:
        if mode == "encode": return quote(value, safe="" if component else "/:@?&=+$,#")
        return unquote(value)

    @staticmethod
    def html_codec(value: str, mode: str, quote_chars: bool) -> str:
        return html.escape(value, quote=quote_chars) if mode == "encode" else html.unescape(value)

    @staticmethod
    def uuid_generate(version: int, namespace: str | None, name: str | None) -> uuid.UUID:
        if version == 1: return uuid.uuid1()
        if version == 4: return uuid.uuid4()
        if version == 7:
            ms = int(datetime.now(UTC).timestamp() * 1000)
            rand = secrets.randbits(74)
            value = (ms << 80) | (0x7 << 76) | ((rand >> 62) << 64) | (0b10 << 62) | (rand & ((1 << 62) - 1))
            return uuid.UUID(int=value)
        ns = _UUID_NS.get((namespace or "").lower())
        if ns is None:
            try: ns = uuid.UUID(namespace or "")
            except ValueError as exc: raise ValueError("Namespace must be dns, url, oid, x500, or a UUID.") from exc
        return uuid.uuid3(ns, name or "") if version == 3 else uuid.uuid5(ns, name or "")

    @staticmethod
    def uuid_validate(value: str) -> dict[str, Any]:
        try:
            u = uuid.UUID(value)
            return {"uuid": str(u), "version": u.version or 0, "variant": u.variant, "is_valid": True}
        except ValueError as exc:
            raise ValueError("Invalid UUID.") from exc

    @staticmethod
    def ulid_generate(count: int) -> list[str]:
        out=[]
        for _ in range(count):
            ms = int(datetime.now(UTC).timestamp() * 1000)
            value = (ms << 80) | secrets.randbits(80)
            chars=[]
            for shift in range(125, -1, -5): chars.append(_ALPHABET[(value >> shift) & 31])
            out.append("".join(chars))
        return out

    @staticmethod
    def ulid_validate(value: str) -> dict[str, Any]:
        v=value.upper()
        if not re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", v) or v[0] > "7":
            return {"ulid": value, "is_valid": False, "error": "Invalid ULID format."}
        n=0
        for c in v: n=(n<<5)|_ALPHABET.index(c)
        ms=n>>80
        dt=datetime.fromtimestamp(ms/1000, tz=UTC)
        return {"ulid": v, "is_valid": True, "timestamp_ms": ms, "datetime_utc": dt.isoformat().replace("+00:00","Z")}

    @staticmethod
    def timestamp(timestamp: float | None, dt_value: str | None, tz_name: str) -> dict[str, Any]:
        zone=ZoneInfo(tz_name)
        if timestamp is not None: dt=datetime.fromtimestamp(timestamp, tz=UTC)
        else:
            raw=(dt_value or "").strip().replace("Z", "+00:00")
            dt=datetime.fromisoformat(raw)
            if dt.tzinfo is None: dt=dt.replace(tzinfo=zone)
            dt=dt.astimezone(UTC)
        local=dt.astimezone(zone)
        return {"unix_seconds": dt.timestamp(), "unix_milliseconds": int(dt.timestamp()*1000), "utc": dt.isoformat().replace("+00:00","Z"), "local": local.isoformat(), "timezone": tz_name, "iso8601": local.isoformat()}

    @staticmethod
    def analyze_headers(headers: dict[str, str]) -> dict[str, Any]:
        h={k.lower().strip(): str(v).strip() for k,v in headers.items()}
        def get(k: str) -> str | None: return h.get(k)
        security_names={"content-security-policy":"CSP","strict-transport-security":"HSTS","x-content-type-options":"X-Content-Type-Options","x-frame-options":"X-Frame-Options","referrer-policy":"Referrer-Policy","permissions-policy":"Permissions-Policy","cross-origin-opener-policy":"COOP","cross-origin-resource-policy":"CORP"}
        security={label: get(key) for key,label in security_names.items()}
        return {"headers":h,"security":security | {"present_count": sum(v is not None for v in security.values())},
                "caching":{"cache_control":get("cache-control"),"etag":get("etag"),"expires":get("expires"),"vary":get("vary"),"has_cache_control":get("cache-control") is not None},
                "cors":{"allow_origin":get("access-control-allow-origin"),"allow_methods":get("access-control-allow-methods"),"allow_headers":get("access-control-allow-headers"),"allow_credentials":get("access-control-allow-credentials")},
                "server":{"server":get("server"),"powered_by":get("x-powered-by"),"via":get("via")},
                "content":{"content_type":get("content-type"),"content_length":get("content-length"),"content_encoding":get("content-encoding"),"content_language":get("content-language")}}

    @staticmethod
    def parse_email_headers(raw: str) -> dict[str, Any]:
        msg=BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", errors="replace"))
        received=[]
        for value in msg.get_all("Received", []): received.append({"value": str(value), "from": None, "by": None, "with": None})
        auth=[str(v) for v in msg.get_all("Authentication-Results", [])]
        def auth_result(name: str) -> str | None:
            for item in auth:
                m=re.search(rf"\b{name}\s*=\s*([A-Za-z0-9._-]+)", item, re.I)
                if m: return m.group(1).lower()
            return None
        tos=[str(a) for a in msg.get_all("To", [])]
        ccs=[str(a) for a in msg.get_all("Cc", [])]
        replies=[str(a) for a in msg.get_all("Reply-To", [])]
        return {"from_address": str(msg.get("From")) if msg.get("From") else None, "to_addresses": tos, "cc_addresses": ccs, "reply_to": replies,
                "subject": str(msg.get("Subject")) if msg.get("Subject") else None, "message_id": str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
                "date": str(msg.get("Date")) if msg.get("Date") else None, "received_hops": received, "authentication_results": auth,
                "spf": auth_result("spf"), "dkim": auth_result("dkim"), "dmarc": auth_result("dmarc")}

    @staticmethod
    def json_tool(value: str, mode: str) -> dict[str, Any]:
        try:
            obj = load_json_limited(
                value, max_depth=100, max_nodes=100_000, error_message="Invalid JSON:"
            )
        except Exception as exc:
            return {"valid": False, "error": str(exc)}
        if mode == "pretty":
            out = json.dumps(obj, ensure_ascii=False, indent=2)
        elif mode == "minify":
            out = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        else:
            out = None
        return {"valid": True, "value": out, "type": type(obj).__name__}

    @staticmethod
    def regex_tool(pattern: str, text: str, flags_text: str) -> dict[str, Any]:
        """Evaluate a regex with a hard match timeout.

        The third-party ``regex`` engine supports a per-operation timeout,
        unlike Python's stdlib ``re``. Input length is additionally bounded by
        the request schema.
        """
        flags = 0
        mapping = {
            "i": safe_regex.I,
            "m": safe_regex.M,
            "s": safe_regex.S,
            "x": safe_regex.X,
            "a": safe_regex.A,
        }
        try:
            for flag in flags_text.lower():
                if flag not in mapping:
                    raise ValueError(f"Unsupported regex flag: {flag}")
                flags |= mapping[flag]
            rx = safe_regex.compile(pattern, flags)
            matches: list[dict[str, Any]] = []
            for match in rx.finditer(text, timeout=0.25):
                matches.append(
                    {
                        "match": match.group(0),
                        "start": match.start(),
                        "end": match.end(),
                        "groups": list(match.groups()),
                        "named_groups": match.groupdict(),
                    }
                )
                if len(matches) >= 10_000:
                    raise ValueError("Regex produced too many matches.")
            return {"valid": True, "matches": matches}
        except TimeoutError:
            return {"valid": False, "error": "Regex execution exceeded the time limit."}
        except (safe_regex.error, ValueError) as exc:
            return {"valid": False, "error": str(exc)}

    # ── Password Strength Analyzer ────────────────────────────────────────

    _COMMON_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"^(.)\1+$"),
        re.compile(r"^(012|123|234|345|456|567|678|789|890)+", re.I),
        re.compile(r"^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+", re.I),
        re.compile(r"^(qwerty|asdf|zxcv|password|letmein|welcome|monkey|dragon|master|login)", re.I),
    ]

    @classmethod
    def password_strength(cls, password: str) -> dict[str, Any]:
        import math

        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_numbers = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        has_unicode = any(ord(c) > 127 for c in password)

        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_numbers: charset_size += 10
        if has_special: charset_size += 33
        if has_unicode: charset_size += 100

        variety = sum([has_upper, has_lower, has_numbers, has_special, has_unicode])

        entropy = length * math.log2(max(charset_size, 1)) if charset_size > 0 else 0

        common = any(p.search(password) for p in cls._COMMON_PATTERNS)

        # Score: 0-5
        score = 0
        if length >= 8: score += 1
        if length >= 12: score += 1
        if variety >= 3: score += 1
        if variety >= 4: score += 1
        if entropy >= 60: score += 1
        if common and score > 0: score -= 1
        score = max(0, min(5, score))

        # Crack time estimate (assuming 10B guesses/sec offline, worst case).
        combinations = max(charset_size, 1) ** length
        seconds = combinations / 10_000_000_000
        crack_time = cls._format_time(seconds)

        feedback: list[str] = []
        if length < 12: feedback.append("Use at least 12 characters for better security.")
        if variety < 3: feedback.append("Mix uppercase, lowercase, numbers, and special characters.")
        if common: feedback.append("Avoid common patterns (repeated characters, sequential letters/numbers).")
        if has_unicode: feedback.append("Note: Unicode characters add complexity but some systems may not support them.")
        if not has_special: feedback.append("Add special characters (!@#$%%^&* etc.) to increase entropy.")
        if length < 8: feedback.append("This password is too short for most security requirements.")

        return {
            "score": score,
            "entropy_bits": round(entropy, 1),
            "crack_time_display": crack_time,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_numbers": has_numbers,
            "has_special": has_special,
            "has_unicode": has_unicode,
            "length": length,
            "character_variety": variety,
            "common_pattern": common,
            "feedback": feedback,
        }

    @staticmethod
    def _format_time(seconds: float) -> str:
        if seconds < 1: return "instantly"
        if seconds < 60: return f"{int(seconds)} seconds"
        if seconds < 3600: return f"{int(seconds / 60)} minutes"
        if seconds < 86400: return f"{int(seconds / 3600)} hours"
        if seconds < 2_592_000: return f"{int(seconds / 86400)} days"
        if seconds < 31_536_000: return f"{int(seconds / 2_592_000)} months"
        years = seconds / 31_536_000
        if years < 1_000: return f"{int(years)} years"
        if years < 1_000_000: return f"{int(years):,} years"
        if years < 1_000_000_000: return f"{years:.1e} years"
        return "longer than the age of the universe"

    # ── Unicode Inspector ─────────────────────────────────────────────────

    # Major Unicode blocks (start, end, block name, script family).
    _BLOCK_RANGES: tuple[tuple[int, int, str, str], ...] = (
        (0x0000, 0x007F, "Basic Latin", "Latin"),
        (0x0080, 0x00FF, "Latin-1 Supplement", "Latin"),
        (0x0100, 0x017F, "Latin Extended-A", "Latin"),
        (0x0180, 0x024F, "Latin Extended-B", "Latin"),
        (0x0250, 0x02AF, "IPA Extensions", "IPA"),
        (0x02B0, 0x02FF, "Spacing Modifier Letters", "Latin"),
        (0x0300, 0x036F, "Combining Diacritical Marks", "Latin"),
        (0x0370, 0x03FF, "Greek and Coptic", "Greek"),
        (0x0400, 0x04FF, "Cyrillic", "Cyrillic"),
        (0x0500, 0x052F, "Cyrillic Supplement", "Cyrillic"),
        (0x0530, 0x058F, "Armenian", "Armenian"),
        (0x0590, 0x05FF, "Hebrew", "Hebrew"),
        (0x0600, 0x06FF, "Arabic", "Arabic"),
        (0x0700, 0x074F, "Syriac", "Syriac"),
        (0x0750, 0x077F, "Arabic Supplement", "Arabic"),
        (0x0780, 0x07BF, "Thaana", "Thaana"),
        (0x0900, 0x097F, "Devanagari", "Devanagari"),
        (0x0980, 0x09FF, "Bengali", "Bengali"),
        (0x0A00, 0x0A7F, "Gurmukhi", "Gurmukhi"),
        (0x0A80, 0x0AFF, "Gujarati", "Gujarati"),
        (0x0B00, 0x0B7F, "Oriya", "Oriya"),
        (0x0B80, 0x0BFF, "Tamil", "Tamil"),
        (0x0C00, 0x0C7F, "Telugu", "Telugu"),
        (0x0C80, 0x0CFF, "Kannada", "Kannada"),
        (0x0D00, 0x0D7F, "Malayalam", "Malayalam"),
        (0x0E00, 0x0E7F, "Thai", "Thai"),
        (0x0E80, 0x0EFF, "Lao", "Lao"),
        (0x0F00, 0x0FFF, "Tibetan", "Tibetan"),
        (0x1000, 0x109F, "Myanmar", "Myanmar"),
        (0x10A0, 0x10FF, "Georgian", "Georgian"),
        (0x1100, 0x11FF, "Hangul Jamo", "Hangul"),
        (0x1200, 0x137F, "Ethiopic", "Ethiopic"),
        (0x13A0, 0x13FF, "Cherokee", "Cherokee"),
        (0x1680, 0x169F, "Ogham", "Ogham"),
        (0x1700, 0x171F, "Tagalog", "Tagalog"),
        (0x1780, 0x17FF, "Khmer", "Khmer"),
        (0x1800, 0x18AF, "Mongolian", "Mongolian"),
        (0x1E00, 0x1EFF, "Latin Extended Additional", "Latin"),
        (0x1F00, 0x1FFF, "Greek Extended", "Greek"),
        (0x2000, 0x206F, "General Punctuation", "Common"),
        (0x2070, 0x209F, "Superscripts and Subscripts", "Common"),
        (0x20A0, 0x20CF, "Currency Symbols", "Common"),
        (0x20D0, 0x20FF, "Combining Diacritical Marks for Symbols", "Common"),
        (0x2100, 0x214F, "Letterlike Symbols", "Common"),
        (0x2150, 0x218F, "Number Forms", "Common"),
        (0x2190, 0x21FF, "Arrows", "Common"),
        (0x2200, 0x22FF, "Mathematical Operators", "Common"),
        (0x2300, 0x23FF, "Miscellaneous Technical", "Common"),
        (0x2400, 0x243F, "Control Pictures", "Common"),
        (0x2440, 0x245F, "Optical Character Recognition", "Common"),
        (0x2460, 0x24FF, "Enclosed Alphanumerics", "Common"),
        (0x2500, 0x257F, "Box Drawing", "Common"),
        (0x2580, 0x259F, "Block Elements", "Common"),
        (0x25A0, 0x25FF, "Geometric Shapes", "Common"),
        (0x2600, 0x26FF, "Miscellaneous Symbols", "Common"),
        (0x2700, 0x27BF, "Dingbats", "Common"),
        (0x2E80, 0x2EFF, "CJK Radicals Supplement", "Han"),
        (0x3000, 0x303F, "CJK Symbols and Punctuation", "Han"),
        (0x3040, 0x309F, "Hiragana", "Hiragana"),
        (0x30A0, 0x30FF, "Katakana", "Katakana"),
        (0x3100, 0x312F, "Bopomofo", "Bopomofo"),
        (0x3130, 0x318F, "Hangul Compatibility Jamo", "Hangul"),
        (0x31A0, 0x31BF, "Bopomofo Extended", "Bopomofo"),
        (0x31F0, 0x31FF, "Katakana Phonetic Extensions", "Katakana"),
        (0x3200, 0x32FF, "Enclosed CJK Letters and Months", "Han"),
        (0x3300, 0x33FF, "CJK Compatibility", "Han"),
        (0x3400, 0x4DBF, "CJK Unified Ideographs Extension A", "Han"),
        (0x4E00, 0x9FFF, "CJK Unified Ideographs", "Han"),
        (0xA000, 0xA48F, "Yi Syllables", "Yi"),
        (0xAC00, 0xD7AF, "Hangul Syllables", "Hangul"),
        (0xD800, 0xDFFF, "Surrogates", "Common"),
        (0xE000, 0xF8FF, "Private Use Area", "Common"),
        (0xF900, 0xFAFF, "CJK Compatibility Ideographs", "Han"),
        (0xFB00, 0xFB4F, "Alphabetic Presentation Forms", "Common"),
        (0xFB50, 0xFDFF, "Arabic Presentation Forms-A", "Arabic"),
        (0xFE00, 0xFE0F, "Variation Selectors", "Common"),
        (0xFE10, 0xFE1F, "Vertical Forms", "Common"),
        (0xFE30, 0xFE4F, "CJK Compatibility Forms", "Han"),
        (0xFE50, 0xFE6F, "Small Form Variants", "Common"),
        (0xFE70, 0xFEFF, "Arabic Presentation Forms-B", "Arabic"),
        (0xFF00, 0xFFEF, "Halfwidth and Fullwidth Forms", "Common"),
        (0xFFF0, 0xFFFF, "Specials", "Common"),
        (0x1F000, 0x1F02F, "Mahjong Tiles", "Common"),
        (0x1F300, 0x1F5FF, "Miscellaneous Symbols and Pictographs", "Common"),
        (0x1F600, 0x1F64F, "Emoticons", "Common"),
        (0x1F680, 0x1F6FF, "Transport and Map Symbols", "Common"),
        (0x1F900, 0x1F9FF, "Supplemental Symbols and Pictographs", "Common"),
        (0x20000, 0x2A6DF, "CJK Unified Ideographs Extension B", "Han"),
        (0x2F800, 0x2FA1F, "CJK Compatibility Ideographs Supplement", "Han"),
    )

    @classmethod
    def _block_to_script(cls, block_name: str) -> str:
        # The block_name we pass is the character NAME's first comma segment,
        # not a block. Fall back to "Latin" for ASCII, "Common" otherwise.
        lowered = block_name.lower()
        if not lowered or lowered == "unknown":
            return "Unknown"
        return "Common"

    @staticmethod
    def _codeblock(cp: int) -> tuple[str, str]:
        """Return (block_name, script) for a codepoint via range lookup."""
        for start, end, block, script in ToolboxService._BLOCK_RANGES:
            if start <= cp <= end:
                return block, script
        return "Other", "Other"

    @staticmethod
    def unicode_inspect(text: str) -> dict[str, Any]:
        import unicodedata

        characters: list[dict[str, Any]] = []
        scripts: set[str] = set()
        categories: set[str] = set()

        for ch in text:
            cp_value = ord(ch)
            cp = f"U+{cp_value:04X}"
            try:
                name = unicodedata.name(ch, "UNKNOWN")
            except ValueError:
                name = "UNKNOWN"
            cat_code = unicodedata.category(ch)
            cat_name = {
                "Lu": "Letter, uppercase", "Ll": "Letter, lowercase",
                "Lt": "Letter, titlecase", "Lm": "Letter, modifier",
                "Lo": "Letter, other", "Mn": "Mark, nonspacing",
                "Mc": "Mark, spacing", "Me": "Mark, enclosing",
                "Nd": "Number, decimal digit", "Nl": "Number, letter",
                "No": "Number, other", "Pc": "Punctuation, connector",
                "Pd": "Punctuation, dash", "Ps": "Punctuation, open",
                "Pe": "Punctuation, close", "Pi": "Punctuation, initial quote",
                "Pf": "Punctuation, final quote", "Po": "Punctuation, other",
                "Sm": "Symbol, math", "Sc": "Symbol, currency",
                "Sk": "Symbol, modifier", "So": "Symbol, other",
                "Zs": "Separator, space", "Zl": "Separator, line",
                "Zp": "Separator, paragraph", "Cc": "Control",
                "Cf": "Format", "Cs": "Surrogate", "Co": "Private use",
                "Cn": "Unassigned",
            }.get(cat_code, cat_code)

            try:
                bidi = unicodedata.bidirectional(ch)
            except (AttributeError, ValueError):
                bidi = "Unknown"

            block, script = ToolboxService._codeblock(cp_value)

            decimal_val = None
            try:
                decimal_val = unicodedata.decimal(ch)
            except (ValueError, TypeError):
                pass

            characters.append({
                "char": ch,
                "codepoint": cp,
                "name": name,
                "category": cat_code,
                "category_name": cat_name,
                "script": script,
                "block": block,
                "bidirectional": bidi,
                "is_alphabetic": unicodedata.category(ch).startswith("L"),
                "is_numeric": unicodedata.category(ch).startswith("N"),
                "is_whitespace": unicodedata.category(ch).startswith("Z") or ch in (" ", "\t", "\n", "\r"),
                "is_control": unicodedata.category(ch).startswith("C"),
                "decimal_value": decimal_val,
            })
            scripts.add(script)
            categories.add(cat_code)

        return {
            "input": text,
            "length": len(text),
            "total_codepoints": len(text),
            "scripts": sorted(scripts),
            "categories": sorted(categories),
            "characters": characters,
        }
