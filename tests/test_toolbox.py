from __future__ import annotations

from app.services.toolbox_service import ToolboxService


def test_jwt_inspector_does_not_verify_signature() -> None:
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjQxMDI0NDQ4MDB9.fake"
    result = ToolboxService.inspect_jwt(token)
    assert result["is_valid"] is True
    assert result["algorithm"] == "HS256"
    assert result["subject"] == "123"


def test_hash_generation() -> None:
    result = ToolboxService.hash_generate("hello", "sha256", "utf-8")
    assert result["digest_hex"] == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_hash_identifier_is_heuristic() -> None:
    result = ToolboxService.hash_identify("a" * 64)
    assert any(item["algorithm"] == "sha256" for item in result["candidates"])


def test_uuid_and_ulid() -> None:
    import uuid
    u = ToolboxService.uuid_generate(4, None, None)
    assert uuid.UUID(str(u)).version == 4
    ulid = ToolboxService.ulid_generate(1)[0]
    assert ToolboxService.ulid_validate(ulid)["is_valid"] is True


def test_json_and_regex() -> None:
    assert ToolboxService.json_tool('{"a": 1}', "minify")["value"] == '{"a":1}'
    result = ToolboxService.regex_tool(r"(foo)(?P<num>\d+)", "foo42", "")
    assert result["valid"] is True
    assert result["matches"][0]["named_groups"]["num"] == "42"


def test_http_header_analysis() -> None:
    result = ToolboxService.analyze_headers(
        {
            "Content-Security-Policy": "default-src 'self'",
            "Cache-Control": "max-age=60",
        }
    )
    assert result["security"]["CSP"] == "default-src 'self'"
    assert result["caching"]["has_cache_control"] is True


def test_email_header_analysis() -> None:
    raw = (
        "From: sender@example.com\nTo: receiver@example.com\nSubject: Hello\n"
        "Message-ID: <x@example.com>\n"
        "Authentication-Results: mx.example; spf=pass dkim=pass dmarc=pass\n"
        "Received: from host.example by mx.example; Tue, 1 Sep 2026 10:00:00 +0000\n\n"
    )
    result = ToolboxService.parse_email_headers(raw)
    assert result["from_address"] == "sender@example.com"
    assert result["spf"] == "pass"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "pass"
