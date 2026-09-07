"""Deterministic tests for the design-system normalizer and browser policy."""
from __future__ import annotations

from app.core.config import Settings
from app.providers.web.ssrf import SSRFGuard
from app.services.design_system_service import DesignSystemService


def test_normalizer_extracts_runtime_tokens(fake_dns) -> None:
    service = DesignSystemService.__new__(DesignSystemService)
    service._settings = Settings(app_env="test", cache_enabled=False)
    service._guard = SSRFGuard(fake_dns)
    snap = {
        "variables": {"--color-primary": "#2563eb", "--radius-md": "10px"},
        "runtimeStyles": [".btn { background-color: #2563eb; padding: 8px 16px; }"] ,
        "rules": ["@media (min-width: 768px) { .grid { display:grid; } }"] ,
        "fonts": [{"family": "Inter", "weight": "600", "status": "loaded"}],
        "fontFaces": ["@font-face { font-family: 'Inter'; font-weight: 400; src: url(x); }"] ,
        "frameworkSignals": {"tailwind": True, "react": True},
        "iconSignals": {"svg": 2, "use": 1, "iconClass": 0},
        "elements": [
            {"tag":"button","role":"button","cls":["btn","primary"],"props":{
                "color":"#fff","background-color":"#2563eb","border-color":"#2563eb","border-width":"1px","border-style":"solid",
                "border-radius":"10px","box-shadow":"none","font-family":"Inter","font-size":"16px","font-weight":"600","line-height":"24px",
                "letter-spacing":"normal","text-transform":"none","margin":"0px",
                "padding":"8px 16px","padding-left":"16px",
                "gap":"0px","row-gap":"0px","column-gap":"0px",
                "width":"100px","height":"40px","max-width":"none","min-width":"0px","display":"inline-flex","position":"relative"},"rect":{"width":100,"height":40},"text":"Buy"},
            {"tag":"p","role":None,"cls":[],"props":{
                "color":"#111827","background-color":"rgba(0,0,0,0)","border-color":"rgb(0,0,0)","border-width":"0px","border-style":"none",
                "border-radius":"0px","box-shadow":"none","font-family":"Inter","font-size":"16px","font-weight":"400","line-height":"24px",
                "letter-spacing":"normal","text-transform":"none","margin":"0px 0px 16px",
                "padding":"0px","padding-left":"0px","gap":"0px","row-gap":"0px","column-gap":"0px",
                "width":"500px","height":"24px","max-width":"800px","min-width":"0px","display":"block","position":"static"},"rect":{"width":500,"height":24},"text":"Hello"},
        ],
    }
    tokens = service._normalize([snap])
    assert "--color-primary" in tokens.custom_properties
    assert any(v.value == "#2563EB" for v in tokens.colors.values())
    assert "button" in tokens.components
    assert any(f.family == "Inter" for f in tokens.fonts)
    assert "768px" in tokens.breakpoints


def test_color_normalization() -> None:
    assert DesignSystemService._normalize_color("#abc") == "#AABBCC"
    assert DesignSystemService._normalize_color("#abcd") == "#AABBCCDD"
    assert DesignSystemService._is_color("rgb(1, 2, 3)")
