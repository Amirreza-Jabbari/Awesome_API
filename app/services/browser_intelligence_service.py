"""Shared browser-based intelligence services.

All analyzers use the Design System Extractor's BrowserManager. No analyzer
creates its own Playwright process or bypasses the browser network guard.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.config import Settings
from app.core.exceptions import (
    AuthenticationRequiredError,
    BrowserCapacityError,
    InvalidSelectorError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ResourceLimitError,
)
from app.core.logging import get_logger
from app.providers.web.ssrf import SSRFGuard
from app.schemas.browser_intelligence import (
    AccessibilityIssue,
    AccessibilityResponse,
    AccessibilitySummary,
    AuditWCAG,
    BrowserAnalysisMeta,
    DiscoveredEndpoint,
    DiscoveryResponse,
    MetricValue,
    PerformanceBottleneck,
    ScreenshotResponseMeta,
    WebVitalsResponse,
    WebVitalsViewport,
)
from app.services.design_system_service import BrowserManager
from app.utils.url import normalize_url

logger = get_logger(__name__)

ACCESS_VERSION = "1.0.0"


def _cache_key(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"browser-intelligence:{kind}:{ACCESS_VERSION}:{digest}"


def _cache_enabled(cache: Any | None, settings: Settings) -> bool:
    return cache is not None and settings.cache_enabled and settings.design_system_cache_ttl > 0

_WCAG: dict[str, AuditWCAG] = {
    "1.1.1": AuditWCAG(criterion="1.1.1", level="A", name="Non-text Content"),
    "1.3.1": AuditWCAG(criterion="1.3.1", level="A", name="Info and Relationships"),
    "1.3.2": AuditWCAG(criterion="1.3.2", level="A", name="Meaningful Sequence"),
    "1.3.5": AuditWCAG(criterion="1.3.5", level="AA", name="Identify Input Purpose"),
    "1.4.3": AuditWCAG(criterion="1.4.3", level="AA", name="Contrast (Minimum)"),
    "1.4.11": AuditWCAG(criterion="1.4.11", level="AA", name="Non-text Contrast"),
    "2.1.1": AuditWCAG(criterion="2.1.1", level="A", name="Keyboard"),
    "2.4.1": AuditWCAG(criterion="2.4.1", level="A", name="Bypass Blocks"),
    "2.4.2": AuditWCAG(criterion="2.4.2", level="A", name="Page Titled"),
    "2.4.3": AuditWCAG(criterion="2.4.3", level="A", name="Focus Order"),
    "2.4.4": AuditWCAG(criterion="2.4.4", level="A", name="Link Purpose"),
    "2.4.6": AuditWCAG(criterion="2.4.6", level="AA", name="Headings and Labels"),
    "2.4.7": AuditWCAG(criterion="2.4.7", level="A", name="Focus Visible"),
    "2.4.11": AuditWCAG(criterion="2.4.11", level="AA", name="Focus Not Obscured"),
    "3.1.1": AuditWCAG(criterion="3.1.1", level="A", name="Language of Page"),
    "3.3.2": AuditWCAG(criterion="3.3.2", level="A", name="Labels or Instructions"),
    "4.1.2": AuditWCAG(criterion="4.1.2", level="A", name="Name, Role, Value"),
    "4.1.3": AuditWCAG(criterion="4.1.3", level="AA", name="Status Messages"),
}


def _wcag(*criteria: str) -> list[AuditWCAG]:
    return [_WCAG[c] for c in criteria if c in _WCAG]


def _selector(el: dict[str, Any]) -> str | None:
    tag = str(el.get("tag", "div")).lower()
    ident = str(el.get("id", "")).strip()
    if ident and re.fullmatch(r"[A-Za-z][A-Za-z0-9_:\-.]*", ident):
        return f"{tag}#{ident}"
    classes = [str(x) for x in el.get("classes", []) if re.fullmatch(r"[A-Za-z0-9_:\-.]+", str(x))]
    return tag + ("." + ".".join(classes[:2]) if classes else "")


async def _open_page(browser: BrowserManager, *, viewport: dict[str, int] | None = None, device_scale_factor: float = 1.0) -> tuple[Any, Any]:
    managed = await browser.context(viewport=viewport, device_scale_factor=device_scale_factor)
    try:
        page = await managed.context.new_page()
        await managed.install_network_policy()
        return managed, page
    except Exception:
        with suppress(Exception):
            await managed.close()
        raise


async def _navigate(page: Any, url: str, settings: Settings) -> Any:
    try:
        response = await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=settings.design_system_navigation_timeout_ms,
        )
    except Exception as exc:
        name = type(exc).__name__.lower()
        if "timeout" in name:
            raise ProviderTimeoutError("Website navigation timed out.") from exc
        raise ProviderUnavailableError("Website navigation failed.") from exc
    if response is not None and response.status in {401, 403}:
        # 403 is not necessarily authentication, but 401 is deterministic.
        if response.status == 401:
            raise AuthenticationRequiredError()
    return response


async def _settle(page: Any, settings: Settings) -> None:
    await page.wait_for_timeout(settings.design_system_render_wait_ms)


class AccessibilityAuditService:
    def __init__(self, browser: BrowserManager, guard: SSRFGuard, settings: Settings, cache: Any | None = None) -> None:
        self._browser, self._guard, self._settings, self._cache = browser, guard, settings, cache

    async def audit(self, raw_url: str) -> AccessibilityResponse:
        if not self._settings.accessibility_audit_enabled:
            raise ProviderUnavailableError("Accessibility audit is disabled.")
        url = normalize_url(raw_url)
        await self._guard.resolve_and_check(urlparse(url).hostname or "")
        cache_key = _cache_key("accessibility", f"{url}|{self._settings.accessibility_audit_max_elements}")
        if _cache_enabled(self._cache, self._settings):
            cached = await self._cache.get(cache_key)
            if isinstance(cached, dict):
                with suppress(Exception):
                    return AccessibilityResponse.model_validate(cached)
        started = time.perf_counter()
        managed, page = await _open_page(self._browser)
        warnings: list[str] = []
        try:
            response = await _navigate(page, url, self._settings)
            await _settle(page, self._settings)
            viewport = await page.evaluate("({width: innerWidth, height: innerHeight})")
            payload = await page.evaluate(_ACCESSIBILITY_JS, self._settings.accessibility_audit_max_elements)
            issues = self._issues(payload)
            summary = AccessibilitySummary(
                errors=sum(i.severity == "error" for i in issues),
                warnings=sum(i.severity == "warning" for i in issues),
                notices=sum(i.severity == "notice" for i in issues),
                passed=max(0, int(payload.get("checks", 0)) - len(issues)),
            )
            final_url = page.url or (response.url if response is not None else url)
            result = AccessibilityResponse(
                url=url, final_url=final_url, fetched_at=datetime.now(timezone.utc),
                analysis=BrowserAnalysisMeta(duration_ms=int((time.perf_counter() - started) * 1000), resources_analyzed=managed.request_count, bytes_downloaded=managed.bytes_downloaded, partial=bool(managed.warnings)),
                viewport={"width": int(viewport["width"]), "height": int(viewport["height"])},
                elements_analyzed=int(payload.get("elements", 0)), summary=summary, issues=issues,
                warnings=[w.message for w in managed.warnings] + warnings,
            )
            if _cache_enabled(self._cache, self._settings):
                with suppress(Exception): await self._cache.set(cache_key, result.model_dump(mode="json"), self._settings.design_system_cache_ttl)
            return result
        finally:
            with suppress(Exception):
                await page.close()
            await managed.close()

    @staticmethod
    def _issues(payload: dict[str, Any]) -> list[AccessibilityIssue]:
        result: list[AccessibilityIssue] = []
        for item in payload.get("issues", []):
            if not isinstance(item, dict):
                continue
            result.append(
                AccessibilityIssue(
                    element=str(item.get("element", "unknown")),
                    selector=item.get("selector"),
                    issue=str(item.get("issue", "UNKNOWN")),
                    severity=item.get("severity", "warning"),
                    message=str(item.get("message", "Accessibility concern detected.")),
                    wcag=_wcag(*(item.get("wcag") or [])),
                    confidence=max(0.0, min(1.0, float(item.get("confidence", 0.8)))),
                )
            )
        return result


_ACCESSIBILITY_JS = r"""
(maxElements) => {
  const issues=[]; const seenIds=new Set(); const duplicateIds=new Set();
  const all=[...document.querySelectorAll('*')];
  const els=all.slice(0, Math.max(1, Number(maxElements)));
  const esc=s=>{try{return CSS.escape(s)}catch{return ''}};
  const selector=e=>e.id?`${e.tagName.toLowerCase()}#${esc(e.id)}`:e.tagName.toLowerCase()+([...e.classList].slice(0,2).map(c=>'.'+esc(c)).join(''));
  const name=e=>(e.getAttribute('aria-label')||'').trim() || (()=>{const r=e.getAttribute('aria-labelledby'); if(!r)return ''; return r.split(/\s+/).map(id=>document.getElementById(id)?.innerText||'').join(' ').trim()})() || (e.innerText||'').trim() || (e.getAttribute('title')||'').trim();
  const add=(e,issue,severity,message,wcag,confidence)=>issues.push({element:e.tagName.toLowerCase(),selector:selector(e),issue,severity,message,wcag,confidence});
  for(const e of els){
    if(e.id){ if(seenIds.has(e.id)) duplicateIds.add(e.id); else seenIds.add(e.id); }
    const tag=e.tagName.toLowerCase(), role=(e.getAttribute('role')||'').toLowerCase();
    const validRoles=new Set(['alert','alertdialog','button','checkbox','combobox','dialog','document','feed','grid','gridcell','heading','img','link','list','listbox','listitem','log','main','menu','menubar','menuitem','navigation','none','option','presentation','progressbar','radio','radiogroup','region','row','rowgroup','search','slider','spinbutton','status','switch','tab','tablist','tabpanel','textbox','timer','toolbar','tooltip','tree','treeitem']);
    if(role && !validRoles.has(role)) add(e,'INVALID_ARIA_ROLE','error',`Unknown or unsupported ARIA role: ${role}.`,['4.1.2'],.96);
    for(const attr of e.getAttributeNames().filter(a=>a.startsWith('aria-'))){ if(!/^aria-(atomic|busy|checked|colcount|colindex|colspan|controls|current|describedby|description|details|disabled|dropeffect|errormessage|expanded|flowto|haspopup|hidden|invalid|keyshortcuts|label|labelledby|level|live|modal|multiline|multiselectable|orientation|owns|placeholder|posinset|pressed|readonly|relevant|required|roledescription|rowcount|rowindex|rowspan|selected|setsize|sort|valuemax|valuemin|valuenow|valuetext|autocomplete|braillelabel|brailleroledescription|colindextext|rowindextext)$/.test(attr)) add(e,'INVALID_ARIA_ATTRIBUTE','warning',`Unrecognized ARIA attribute: ${attr}.`,['4.1.2'],.9); }
    if(tag==='img'){
      if(!e.hasAttribute('alt')) add(e,'MISSING_ALT','error','Image has no alt attribute.',['1.1.1'],.99);
      else if(e.getAttribute('alt')==='' && (e.closest('a,button')||e.getAttribute('role'))) add(e,'EMPTY_ALT_INTERACTIVE','warning','Interactive image has empty alternative text.',['1.1.1','4.1.2'],.95);
      else if(/^(image|photo|picture|img|graphic)$/i.test((e.getAttribute('alt')||'').trim()) || /\.(png|jpe?g|gif|webp|svg)$/i.test((e.getAttribute('alt')||'').trim())) add(e,'SUSPICIOUS_ALT','warning','Alternative text appears generic or filename-like; verify that it describes the image purpose.',['1.1.1'],.84);
    }
    const interactive=tag==='button'||tag==='a'||['button','link','checkbox','radio','tab','menuitem','switch','textbox','combobox'].includes(role)||e.hasAttribute('onclick');
    if(interactive && !name(e)) add(e,'MISSING_ACCESSIBLE_NAME','error','Interactive element has no detectable accessible name.',['4.1.2','2.4.4'],.97);
    if((tag==='div'||tag==='span') && e.hasAttribute('onclick') && !['button','link'].includes(role)) add(e,'CLICKABLE_NONINTERACTIVE','warning','Clickable non-interactive element has no explicit interactive role.',['2.1.1','4.1.2'],.88);
    const ti=e.getAttribute('tabindex');
    if(ti!==null && Number(ti)>0) add(e,'POSITIVE_TABINDEX','warning','Positive tabindex can create an unpredictable focus order.',['2.4.3'],.99);
    if(interactive && ti!==null && Number(ti)<0 && !e.hasAttribute('disabled') && e.getAttribute('aria-hidden')!=='true') add(e,'INTERACTIVE_NOT_FOCUSABLE','warning','Interactive element is removed from sequential keyboard focus.',['2.1.1'],.92);
    if(e.getAttribute('aria-hidden')==='true' && (interactive || e.matches('input,select,textarea,button,a[href]'))) add(e,'HIDDEN_INTERACTIVE','error','Interactive content is aria-hidden.',['4.1.2','2.1.1'],.98);
    const refs=(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).concat((e.getAttribute('aria-describedby')||'').split(/\s+/).filter(Boolean));
    for(const id of refs) if(!document.getElementById(id)) add(e,'BROKEN_ARIA_REFERENCE','error',`ARIA reference does not resolve: ${id}.`,['4.1.2'],.99);
    const required=e.getAttribute('aria-required')==='true'; if(required && e.matches('input,select,textarea') && !e.required) add(e,'ARIA_REQUIRED_MISMATCH','warning','aria-required and native required state disagree.',['4.1.2'],.9);
    if(tag==='input'||tag==='textarea'||tag==='select'){
      const label=e.labels?.length>0 || !!name(e); if(!label) add(e,'MISSING_FORM_LABEL','error','Form control has no detectable accessible name or label.',['3.3.2','4.1.2'],.98);
      if(e.placeholder && !e.labels?.length && !e.getAttribute('aria-label') && !e.getAttribute('aria-labelledby')) add(e,'PLACEHOLDER_ONLY_LABEL','warning','Placeholder appears to be the only visible labeling mechanism.',['3.3.2'],.9);
    }
    if(tag==='a' && !e.getAttribute('href') && !e.hasAttribute('role')) add(e,'EMPTY_LINK','warning','Anchor has no href and no explicit role.',['2.4.4'],.9);
    if((tag==='a'||tag==='button') && !name(e)) add(e,'EMPTY_CONTROL','error','Control has no detectable accessible name.',['4.1.2'],.98);
  }
  for(const id of duplicateIds) add(document.getElementById(id)||document.body,'DUPLICATE_ID','warning',`Duplicate id detected: ${id}.`,['4.1.2'],.99);
  const html=document.documentElement; if(!(html.getAttribute('lang')||'').trim()) add(html,'MISSING_LANG','error','Document does not declare a language.',['3.1.1'],.99);
  if(!document.title.trim()) add(document.head,'MISSING_TITLE','error','Document has no non-empty title.',['2.4.2'],.99);
  const headings=[...document.querySelectorAll('h1,h2,h3,h4,h5,h6')]; if(headings.length){ let prev=0; for(const h of headings){const n=Number(h.tagName.substring(1)); if(prev && n>prev+1) add(h,'HEADING_LEVEL_SKIP','warning',`Heading level jumps from h${prev} to h${n}.`,['1.3.1','2.4.6'],.95); prev=n;} } else add(document.body,'NO_HEADINGS','notice','No native headings were detected; verify document structure manually.',['1.3.1'],.7);
  const parseRGB=v=>{const m=v.match(/rgba?\(\s*([\d.]+)[, ]+\s*([\d.]+)[, ]+\s*([\d.]+)/i);if(m)return[+m[1],+m[2],+m[3]];if(/^#[0-9a-f]{3,8}$/i.test(v)){let h=v.slice(1);if(h.length===3)h=h.split('').map(x=>x+x).join('');return[parseInt(h.slice(0,2),16),parseInt(h.slice(2,4),16),parseInt(h.slice(4,6),16)]}return null};
  const lum=c=>{const q=c.map(x=>{x/=255;return x<=.04045?x/12.92:Math.pow((x+.055)/1.055,2.4)});return .2126*q[0]+.7152*q[1]+.0722*q[2]};
  for(const e of els.filter(x=>/^(p|span|a|button|label|h1|h2|h3|h4|h5|h6|li|td|th)$/.test(x.tagName.toLowerCase()) && (x.innerText||'').trim())){const cs=getComputedStyle(e);const fg=parseRGB(cs.color);let bg=e;let bgc=null;while(bg&&bgc===null){const c=getComputedStyle(bg).backgroundColor;if(c && c!=='transparent' && !c.endsWith(', 0)')) bgc=parseRGB(c);bg=bg.parentElement}if(fg&&bgc){const ratio=(Math.max(lum(fg),lum(bgc))+.05)/(Math.min(lum(fg),lum(bgc))+.05);const large=parseFloat(cs.fontSize)>=24 || (parseFloat(cs.fontSize)>=18.66 && Number(cs.fontWeight)>=700);if(ratio<(large?3:4.5)) add(e,'LOW_TEXT_CONTRAST','error',`Computed text contrast is ${ratio.toFixed(2)}:1.`,['1.4.3'],.93)}}
  const h1=document.querySelectorAll('h1'); if(h1.length>1) add(h1[1],'MULTIPLE_H1','notice','Multiple h1 elements detected; verify that they represent the intended document structure.',['1.3.1'],.85);
  if(!document.querySelector('main,[role="main"]')) add(document.body,'MISSING_MAIN_LANDMARK','notice','No main landmark was detected.',['1.3.1'],.9);
  const skip=[...document.querySelectorAll('a[href]')].some(a=>/^#/.test(a.getAttribute('href')||'') && /skip|content|main/i.test(a.innerText||'')); if(!skip) add(document.body,'NO_SKIP_LINK_DETECTED','notice','No conventional skip link was detected.',['2.4.1'],.72);
  let checks=all.length+12; return {issues,elements:els.length,checks};
}
"""


def _contrast_channel(v: float) -> float:
    v /= 255.0
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def contrast_ratio(fg: str, bg: str) -> float | None:
    def rgb(value: str) -> tuple[float, float, float] | None:
        m = re.fullmatch(r"rgba?\(\s*([\d.]+)[, ]+\s*([\d.]+)[, ]+\s*([\d.]+)(?:\s*[,/]\s*[\d.]+)?\s*\)", value.lower())
        if m:
            return tuple(float(m.group(i)) for i in range(1, 4))  # type: ignore[return-value]
        h = value.lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        if len(h) in {6, 8} and re.fullmatch(r"[0-9a-fA-F]+", h):
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
        return None
    a,b=rgb(fg),rgb(bg)
    if not a or not b: return None
    la=.2126*_contrast_channel(a[0])+.7152*_contrast_channel(a[1])+.0722*_contrast_channel(a[2])
    lb=.2126*_contrast_channel(b[0])+.7152*_contrast_channel(b[1])+.0722*_contrast_channel(b[2])
    return (max(la,lb)+.05)/(min(la,lb)+.05)


class CoreWebVitalsService:
    def __init__(self, browser: BrowserManager, guard: SSRFGuard, settings: Settings, cache: Any | None = None) -> None:
        self._browser, self._guard, self._settings, self._cache = browser, guard, settings, cache

    async def measure(self, raw_url: str) -> WebVitalsResponse:
        if not self._settings.web_vitals_enabled:
            raise ProviderUnavailableError("Core Web Vitals measurement is disabled.")
        url=normalize_url(raw_url); await self._guard.resolve_and_check(urlparse(url).hostname or "")
        cache_key = _cache_key("web-vitals", f"{url}|{self._settings.web_vitals_measurement_ms}|{self._settings.design_system_viewports[:2]}")
        if _cache_enabled(self._cache, self._settings):
            cached = await self._cache.get(cache_key)
            if isinstance(cached, dict):
                with suppress(Exception): return WebVitalsResponse.model_validate(cached)
        started=time.perf_counter(); managed,page=await _open_page(self._browser); warnings=[]; rows=[]
        try:
            await _navigate(page,url,self._settings)
            await _settle(page,self._settings)
            for i, vp in enumerate(self._settings.design_system_viewports[:2]):
                if i: await page.set_viewport_size(vp); await _navigate(page,url,self._settings); await _settle(page,self._settings)
                duration=self._settings.web_vitals_measurement_ms
                await page.wait_for_timeout(duration)
                raw=await page.evaluate(_VITALS_JS)
                rows.append(self._normalize_vitals(raw,vp))
            final=page.url or url
            result=WebVitalsResponse(url=url,final_url=final,fetched_at=datetime.now(timezone.utc),analysis=BrowserAnalysisMeta(duration_ms=int((time.perf_counter()-started)*1000),resources_analyzed=managed.request_count,bytes_downloaded=managed.bytes_downloaded,partial=bool(managed.warnings)),measurement_duration_ms=self._settings.web_vitals_measurement_ms,viewports=rows,warnings=[w.message for w in managed.warnings]+warnings)
            if _cache_enabled(self._cache, self._settings):
                with suppress(Exception): await self._cache.set(cache_key,result.model_dump(mode="json"),self._settings.design_system_cache_ttl)
            return result
        finally:
            with suppress(Exception): await page.close()
            await managed.close()

    @staticmethod
    def _metric_ms(value: Any, thresholds: tuple[float,float], reason: str|None=None) -> MetricValue:
        if value is None: return MetricValue(status="not_available",source="unavailable",reason=reason or "browser API did not provide the metric")
        v=float(value); status="good" if v<=thresholds[0] else "needs_improvement" if v<=thresholds[1] else "poor"
        return MetricValue(value_ms=v,status=status,source="browser")

    @staticmethod
    def _normalize_vitals(raw: dict[str,Any], vp: dict[str,int]) -> WebVitalsViewport:
        fcp=CoreWebVitalsService._metric_ms(raw.get('fcp'),(1800,3000)); lcp=CoreWebVitalsService._metric_ms(raw.get('lcp'),(2500,4000))
        cls_v=raw.get('cls'); cls=MetricValue(value=float(cls_v),status='good' if cls_v is not None and cls_v<=.1 else 'needs_improvement' if cls_v is not None and cls_v<=.25 else 'poor' if cls_v is not None else 'not_available',source='browser' if cls_v is not None else 'unavailable')
        inp_v=raw.get('inp'); inp=CoreWebVitalsService._metric_ms(inp_v,(200,500));
        ttfb=CoreWebVitalsService._metric_ms(raw.get('ttfb'),(800,1800))
        bottlenecks=[]
        if raw.get('jsBytes',0)>500_000: bottlenecks.append(PerformanceBottleneck(type='large_javascript',severity='warning',details='JavaScript transfer exceeded 500 KB.'))
        if raw.get('cssBytes',0)>200_000: bottlenecks.append(PerformanceBottleneck(type='large_css',severity='warning',details='CSS transfer exceeded 200 KB.'))
        if raw.get('imageBytes',0)>1_500_000: bottlenecks.append(PerformanceBottleneck(type='large_images',severity='warning',details='Image transfer exceeded 1.5 MB.'))
        if raw.get('longTasks',0)>5: bottlenecks.append(PerformanceBottleneck(type='long_tasks',severity='warning',details='Multiple long tasks were observed.'))
        if cls_v is not None and cls_v>.1: bottlenecks.append(PerformanceBottleneck(type='layout_instability',severity='warning',details='Cumulative layout shift exceeded the good threshold.'))
        return WebVitalsViewport(viewport=vp,fcp=fcp,lcp=lcp,cls=cls,inp=inp,ttfb=ttfb,dom_content_loaded_ms=raw.get('domContentLoaded'),load_event_ms=raw.get('loadEvent'),resource_count=int(raw.get('resourceCount',0)),transfer_bytes=int(raw.get('transferBytes',0)),js_transfer_bytes=int(raw.get('jsBytes',0)),css_transfer_bytes=int(raw.get('cssBytes',0)),image_transfer_bytes=int(raw.get('imageBytes',0)),long_tasks=int(raw.get('longTasks',0)),total_blocking_time_ms=float(raw.get('tbt',0)),bottlenecks=bottlenecks)


_VITALS_JS=r"""
() => new Promise(resolve => {
 const state={fcp:null,lcp:null,cls:0,inp:null,ttfb:null,domContentLoaded:null,loadEvent:null,resourceCount:0,transferBytes:0,jsBytes:0,cssBytes:0,imageBytes:0,longTasks:0,tbt:0};
 try{const p=performance.getEntriesByType('paint').find(x=>x.name==='first-contentful-paint');if(p)state.fcp=p.startTime;}catch{}
 try{const nav=performance.getEntriesByType('navigation')[0];if(nav){state.ttfb=nav.responseStart;state.domContentLoaded=nav.domContentLoadedEventEnd;state.loadEvent=nav.loadEventEnd;}}catch{}
 try{for(const r of performance.getEntriesByType('resource')){const s=Number(r.transferSize||0);state.transferBytes+=s;state.resourceCount++;const i=String(r.initiatorType||'').toLowerCase();if(i==='script')state.jsBytes+=s;if(i==='link'||i==='css')state.cssBytes+=s;if(i==='img'||i==='image')state.imageBytes+=s;}}catch{}
 const finish=()=>resolve(state);
 try{new PerformanceObserver(list=>{for(const e of list.getEntries()){if(e.entryType==='largest-contentful-paint')state.lcp=e.startTime;else if(e.entryType==='layout-shift'&&!e.hadRecentInput)state.cls+=e.value;else if(e.entryType==='event'&&e.interactionId){const d=e.duration;if(state.inp===null||d>state.inp)state.inp=d;}}}).observe({type:'largest-contentful-paint',buffered:true});}catch{}
 try{new PerformanceObserver(list=>{for(const e of list.getEntries()){if(e.entryType==='layout-shift'&&!e.hadRecentInput)state.cls+=e.value;}}).observe({type:'layout-shift',buffered:true});}catch{}
 try{new PerformanceObserver(list=>{for(const e of list.getEntries()){if(e.entryType==='event'&&e.interactionId){state.inp=Math.max(state.inp||0,e.duration||0);}}}).observe({type:'event',buffered:true,durationThreshold:40});}catch{}
 try{new PerformanceObserver(list=>{for(const e of list.getEntries()){if(e.duration>50){state.longTasks++;state.tbt+=Math.max(0,e.duration-50);}}}).observe({type:'longtask',buffered:true});}catch{}
 setTimeout(finish,50);
});
"""


class ScreenshotService:
    def __init__(
        self, browser: BrowserManager, guard: SSRFGuard, settings: Settings, cache: Any | None = None
    ) -> None:
        self._browser = browser
        self._guard = guard
        self._settings = settings
        self._cache = cache
        self._sem = asyncio.Semaphore(settings.screenshot_max_concurrent)
    async def capture(self,raw_url:str,selector:str|None,width:int|None,height:int|None,full_page:bool,fmt:str,quality:int|None,dpr:float)->tuple[bytes,ScreenshotResponseMeta]:
        if not self._settings.screenshot_enabled:
            raise ProviderUnavailableError("Screenshot API is disabled.")
        url=normalize_url(raw_url); await self._guard.resolve_and_check(urlparse(url).hostname or "")
        if width is None: width=self._settings.screenshot_default_width
        if height is None: height=self._settings.screenshot_default_height
        if not 1 <= width <= self._settings.screenshot_max_width or not 1 <= height <= self._settings.screenshot_max_height:
            raise ResourceLimitError("Screenshot dimensions exceed the configured limit.")
        if full_page and self._settings.screenshot_max_full_page_height <= 0:
            raise ResourceLimitError("Full-page screenshots are disabled.")
        cache_key = _cache_key("screenshot", f"{url}|{selector}|{width}|{height}|{full_page}|{fmt}|{quality}|{dpr}")
        if _cache_enabled(self._cache, self._settings):
            cached = await self._cache.get(cache_key)
            if isinstance(cached, dict) and isinstance(cached.get("data"), str) and isinstance(cached.get("meta"), dict):
                with suppress(Exception): return base64.b64decode(cached["data"]), ScreenshotResponseMeta.model_validate(cached["meta"])
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=self._settings.design_system_queue_timeout_ms/1000)
        except TimeoutError as exc:
            raise BrowserCapacityError() from exc
        try:
            managed,page=await _open_page(self._browser, viewport={'width':width,'height':height}, device_scale_factor=dpr)
        except Exception:
            self._sem.release()
            raise
        try:
            await _navigate(page,url,self._settings); await _settle(page,self._settings)
            if full_page:
                page_height=await page.evaluate('Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)')
                if int(page_height)>self._settings.screenshot_max_full_page_height: raise ResourceLimitError('Page height exceeds the configured screenshot limit.')
            if selector:
                try: count=await page.locator(selector).count()
                except Exception as exc: raise InvalidSelectorError() from exc
                if count==0: from app.core.exceptions import ElementNotFoundError; raise ElementNotFoundError()
                if count>1: from app.core.exceptions import MultipleElementsError; raise MultipleElementsError()
                element=page.locator(selector); await element.scroll_into_view_if_needed()
                data=await element.screenshot(type=fmt,quality=quality,animations='disabled',timeout=self._settings.screenshot_timeout_ms)
                box=await element.bounding_box(); out_w=int(round((box or {}).get('width',width)*dpr)); out_h=int(round((box or {}).get('height',height)*dpr))
            else:
                data=await page.screenshot(type=fmt,quality=quality,full_page=full_page,animations='disabled',timeout=self._settings.screenshot_timeout_ms)
                dims=await page.evaluate('({w: innerWidth, h: innerHeight, full: Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)})')
                out_w=int(dims['w']*dpr); out_h=int(dims['full'] if full_page else dims['h'])*int(dpr)
            if len(data)>self._settings.screenshot_max_bytes: raise ResourceLimitError('Screenshot exceeds the configured size limit.')
            meta=ScreenshotResponseMeta(url=url,final_url=page.url or url,fetched_at=datetime.now(timezone.utc),width=max(1,out_w),height=max(1,out_h),format=fmt,bytes=len(data),full_page=full_page,selector=selector,partial=bool(managed.warnings))
            if _cache_enabled(self._cache, self._settings):
                with suppress(Exception):
                    await self._cache.set(cache_key, {"data": base64.b64encode(data).decode("ascii"), "meta": meta.model_dump(mode="json")}, self._settings.design_system_cache_ttl)
            return data,meta
        except BrowserCapacityError: raise
        except ResourceLimitError: raise
        finally:
            with suppress(Exception): await page.close()
            await managed.close()
            self._sem.release()


class APIDiscoveryService:
    def __init__(self,browser:BrowserManager,guard:SSRFGuard,settings:Settings,cache:Any|None=None)->None:self._browser,self._guard,self._settings,self._cache=browser,guard,settings,cache
    async def discover(self,raw_url:str)->DiscoveryResponse:
        if not self._settings.api_discovery_enabled:
            raise ProviderUnavailableError("API discovery is disabled.")
        url=normalize_url(raw_url); parsed=urlparse(url); await self._guard.resolve_and_check(parsed.hostname or '')
        cache_key = _cache_key("api-discovery", f"{url}|{self._settings.api_discovery_max_endpoints}|{self._settings.api_discovery_max_probes}|{self._settings.api_discovery_max_requests}")
        if _cache_enabled(self._cache, self._settings):
            cached = await self._cache.get(cache_key)
            if isinstance(cached, dict):
                with suppress(Exception): return DiscoveryResponse.model_validate(cached)
        started=time.perf_counter(); managed,page=await _open_page(self._browser); endpoints:dict[tuple[str,str],DiscoveredEndpoint]={}; warnings=[]; observed=[]
        def origin(u:str)->str: return 'first_party' if urlparse(u).hostname==parsed.hostname else 'third_party'
        def add(u:str,method:str,typ:str,source:str,ct:str|None=None,status:int|None=None,conf:float=.8)->None:
            if urlparse(u).scheme not in {'http','https','ws','wss'}:
                return
            key=(method.upper(),u.rstrip('/') or u)
            old=endpoints.get(key)
            if old is None:
                if len(endpoints)>=self._settings.api_discovery_max_endpoints:
                    return
            elif not (
                conf > old.confidence
                or (ct is not None and old.content_type is None)
                or (status is not None and old.status is None)
            ):
                return
            endpoints[key]=DiscoveredEndpoint(
                url=u,method=method.upper(),type=typ,origin_type=origin(u),
                content_type=ct,status=status,source=source,confidence=conf,
            )
        def on_request(req:Any)->None:
            observed.append(req.url)
            if len(observed)>self._settings.api_discovery_max_requests:return
            rt=str(getattr(req,'resource_type','')).lower(); method=str(req.method).upper()
            if rt in {'xhr','fetch'} and method in {'GET','HEAD'}: add(req.url,method,'rest','browser_network',conf=.88)
            if str(req.url).startswith(('ws://','wss://')): add(req.url,method,'websocket','browser_network',conf=.94)
        def on_response(resp:Any)->None:
            try:
                req=resp.request; ct=str(resp.headers.get('content-type','')).lower(); url2=resp.url
                if 'application/json' in ct or 'application/problem+json' in ct:
                    add(url2,req.method,'json_api','browser_network',ct,resp.status,.94)
            except Exception: pass
        page.on('request',on_request); page.on('response',on_response)
        try:
            await _navigate(page,url,self._settings); await _settle(page,self._settings)
            doc=await page.evaluate(_DISCOVERY_JS,self._settings.api_discovery_max_endpoints)
            for x in doc.get('candidates',[]):
                if isinstance(x,dict) and x.get('url'): add(urljoin(page.url,x['url']),x.get('method','GET'),x.get('type','rest'),x.get('source','document'),conf=float(x.get('confidence',.75)))
            # Probe only a tiny allowlisted set; browser navigation remains guarded.
            base=f'{urlparse(page.url).scheme}://{urlparse(page.url).netloc}'
            for path in self._settings.api_discovery_well_known_paths[:self._settings.api_discovery_max_probes]:
                target=urljoin(base,path)
                try:
                    await self._guard.resolve_and_check(urlparse(target).hostname or '')
                    probe=await page.evaluate("""async (u) => { try { const r=await fetch(u,{method:'GET',credentials:'omit',redirect:'follow'}); const t=(await r.text()).slice(0,2000); return {ok:true,status:r.status,contentType:r.headers.get('content-type')||'',text:t}; } catch(e) { return {ok:false}; } }""", target)
                    if probe.get('ok') and int(probe.get('status',599)) < 400:
                        ct=str(probe.get('contentType','')); text=str(probe.get('text',''))
                        if 'json' in ct.lower() or path.endswith(('.json','.yaml','.yml')):
                            typ='openapi' if any(k in text.lower() for k in ('openapi','swagger')) or 'openapi' in path or 'swagger' in path else 'rest'
                            add(target,'GET',typ,'well_known',ct,int(probe.get('status',200)),.97 if typ=='openapi' else .82)
                except Exception: continue
            final=page.url or url
            result=DiscoveryResponse(url=url,final_url=final,fetched_at=datetime.now(timezone.utc),analysis=BrowserAnalysisMeta(duration_ms=int((time.perf_counter()-started)*1000),resources_analyzed=managed.request_count,bytes_downloaded=managed.bytes_downloaded,partial=bool(managed.warnings) or len(observed)>self._settings.api_discovery_max_requests),requests_observed=min(len(observed),self._settings.api_discovery_max_requests),endpoints_discovered=len(endpoints),openapi_documents=sum(x.type=='openapi' for x in endpoints.values()),graphql_endpoints=sum(x.type=='graphql' for x in endpoints.values()),websockets=sum(x.type=='websocket' for x in endpoints.values()),endpoints=list(endpoints.values()),partial=bool(managed.warnings) or len(observed)>self._settings.api_discovery_max_requests,warnings=[w.message for w in managed.warnings]+warnings)
            if _cache_enabled(self._cache, self._settings):
                with suppress(Exception): await self._cache.set(cache_key,result.model_dump(mode="json"),self._settings.design_system_cache_ttl)
            return result
        finally:
            with suppress(Exception): await page.close()
            await managed.close()

_DISCOVERY_JS=r"""
(maxItems)=>{const out=[];const push=(u,type,source,confidence=.75)=>{if(!u||out.length>=maxItems)return;try{const x=new URL(u,location.href);if(['http:','https:'].includes(x.protocol))out.push({url:x.href,type,source,confidence})}catch{}};
 document.querySelectorAll('a[href],link[href],script[src],form[action]').forEach(e=>{const a=e.getAttribute('href')||e.getAttribute('src')||e.getAttribute('action');if(!a)return;const s=a.toLowerCase();if(/openapi|swagger|api-docs/.test(s))push(a,'openapi','document',.9);else if(/graphql/.test(s))push(a,'graphql','document',.9);else if(e.tagName.toLowerCase()==='form')push(a,'form','form',.65)});
 const html=document.documentElement.innerHTML.slice(0,500000); for(const m of html.matchAll(/(?:https?:\/\/[^\s"'<>]+|\/api\/[A-Za-z0-9_./?=&-]+)/g)){const s=m[0];if(/graphql/i.test(s))push(s,'graphql','document',.82);else if(/openapi|swagger/i.test(s))push(s,'openapi','document',.82);else push(s,'rest','document',.6)} return {candidates:out};}
"""
