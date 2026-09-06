"""Local color-model conversion and WCAG contrast helpers.

Pure arithmetic (no external services). Supports hex, rgb()/rgba(), hsl()/hsla()
and hsv()/hsva() input, and reports all representations plus WCAG relative
luminance/contrast and a best-effort CSS colour name.
"""
from __future__ import annotations

import math
import re
from typing import Any

from app.core.exceptions import ValidationError

_NAMED_COLORS: dict[str, tuple[int, int, int]] = {
    "aliceblue": (240, 248, 255), "antiquewhite": (250, 235, 215),
    "aqua": (0, 255, 255), "aquamarine": (127, 255, 212),
    "azure": (240, 255, 255), "beige": (245, 245, 220),
    "bisque": (255, 228, 196), "black": (0, 0, 0),
    "blanchedalmond": (255, 235, 205), "blue": (0, 0, 255),
    "blueviolet": (138, 43, 226), "brown": (165, 42, 42),
    "burlywood": (222, 184, 135), "cadetblue": (95, 158, 160),
    "chartreuse": (127, 255, 0), "chocolate": (210, 105, 30),
    "coral": (255, 127, 80), "cornflowerblue": (100, 149, 237),
    "cornsilk": (255, 248, 220), "crimson": (220, 20, 60),
    "cyan": (0, 255, 255), "darkblue": (0, 0, 139),
    "darkcyan": (0, 139, 139), "darkgoldenrod": (184, 134, 11),
    "darkgray": (169, 169, 169), "darkgreen": (0, 100, 0),
    "darkkhaki": (189, 183, 107), "darkmagenta": (139, 0, 139),
    "darkolivegreen": (85, 107, 47), "darkorange": (255, 140, 0),
    "darkorchid": (153, 50, 204), "darkred": (139, 0, 0),
    "darksalmon": (233, 150, 122), "darkseagreen": (143, 188, 143),
    "darkslateblue": (72, 61, 139), "darkslategray": (47, 79, 79),
    "darkturquoise": (0, 206, 209), "darkviolet": (148, 0, 211),
    "deeppink": (255, 20, 147), "deepskyblue": (0, 191, 255),
    "dimgray": (105, 105, 105), "dodgerblue": (30, 144, 255),
    "firebrick": (178, 34, 34), "floralwhite": (255, 250, 240),
    "forestgreen": (34, 139, 34), "fuchsia": (255, 0, 255),
    "gainsboro": (220, 220, 220), "ghostwhite": (248, 248, 255),
    "gold": (255, 215, 0), "goldenrod": (218, 165, 32),
    "gray": (128, 128, 128), "green": (0, 128, 0),
    "greenyellow": (173, 255, 47), "honeydew": (240, 255, 240),
    "hotpink": (255, 105, 180), "indianred": (205, 92, 92),
    "indigo": (75, 0, 130), "ivory": (255, 255, 240),
    "khaki": (240, 230, 140), "lavender": (230, 230, 250),
    "lavenderblush": (255, 240, 245), "lawngreen": (124, 252, 0),
    "lemonchiffon": (255, 250, 205), "lightblue": (173, 216, 230),
    "lightcoral": (240, 128, 128), "lightcyan": (224, 255, 255),
    "lightgoldenrodyellow": (250, 250, 210), "lightgray": (211, 211, 211),
    "lightgreen": (144, 238, 144), "lightpink": (255, 182, 193),
    "lightsalmon": (255, 160, 122), "lightseagreen": (32, 178, 170),
    "lightskyblue": (135, 206, 250), "lightslategray": (119, 136, 153),
    "lightsteelblue": (176, 196, 222), "lightyellow": (255, 255, 224),
    "lime": (0, 255, 0), "limegreen": (50, 205, 50),
    "linen": (250, 240, 230), "magenta": (255, 0, 255),
    "maroon": (128, 0, 0), "mediumaquamarine": (102, 205, 170),
    "mediumblue": (0, 0, 205), "mediumorchid": (186, 85, 211),
    "mediumpurple": (147, 112, 219), "mediumseagreen": (60, 179, 113),
    "mediumslateblue": (123, 104, 238), "mediumspringgreen": (0, 250, 154),
    "mediumturquoise": (72, 209, 204), "mediumvioletred": (199, 21, 133),
    "midnightblue": (25, 25, 112), "mintcream": (245, 255, 250),
    "mistyrose": (255, 228, 225), "moccasin": (255, 228, 181),
    "navajowhite": (255, 222, 173), "navy": (0, 0, 128),
    "oldlace": (253, 245, 230), "olive": (128, 128, 0),
    "olivedrab": (107, 142, 35), "orange": (255, 165, 0),
    "orangered": (255, 69, 0), "orchid": (218, 112, 214),
    "palegoldenrod": (238, 232, 170), "palegreen": (152, 251, 152),
    "paleturquoise": (175, 238, 238), "palevioletred": (219, 112, 147),
    "papayawhip": (255, 239, 213), "peachpuff": (255, 218, 185),
    "peru": (205, 133, 63), "pink": (255, 192, 203),
    "plum": (221, 160, 221), "powderblue": (176, 224, 230),
    "purple": (128, 0, 128), "rebeccapurple": (102, 51, 153),
    "red": (255, 0, 0), "rosybrown": (188, 143, 143),
    "royalblue": (65, 105, 225), "saddlebrown": (139, 69, 19),
    "salmon": (250, 128, 114), "sandybrown": (244, 164, 96),
    "seagreen": (46, 139, 87), "seashell": (255, 245, 238),
    "sienna": (160, 82, 45), "silver": (192, 192, 192),
    "skyblue": (135, 206, 235), "slateblue": (106, 90, 205),
    "slategray": (112, 128, 144), "snow": (255, 250, 250),
    "springgreen": (0, 255, 127), "steelblue": (70, 130, 180),
    "tan": (210, 180, 140), "teal": (0, 128, 128),
    "thistle": (216, 191, 216), "tomato": (255, 99, 71),
    "turquoise": (64, 224, 208), "violet": (238, 130, 238),
    "wheat": (245, 222, 179), "white": (255, 255, 255),
    "whitesmoke": (245, 245, 245), "yellow": (255, 255, 0),
    "yellowgreen": (154, 205, 50),
}

_FUNC_RE = re.compile(r"^([a-z]+)\s*\(([^)]*)\)$", re.IGNORECASE)


def _clamp255(value: float) -> int:
    return int(max(0, min(255, round(value))))


def _hex_to_rgb(hexstr: str) -> tuple[int, int, int, float] | None:
    h = hexstr.lstrip("#")
    if len(h) in (3, 4):
        h = "".join(c * 2 for c in h)
    if len(h) == 6:
        try:
            return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0
        except ValueError:
            return None
    if len(h) == 8:
        try:
            alpha = int(h[6:8], 16) / 255.0
            return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), alpha
        except ValueError:
            return None
    return None


def _rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02x}{g:02x}{b:02x}"


def _rgb_to_hsl(r: int, g: int, b: int) -> tuple[float, float, float]:
    rf, gf, bf = r / 255.0, g / 255.0, b / 255.0
    cmax = max(rf, gf, bf)
    cmin = min(rf, gf, bf)
    delta = cmax - cmin
    lightness = (cmax + cmin) / 2.0
    if delta == 0:
        return 0.0, 0.0, round(lightness * 100, 2)
    saturation = delta / (1 - abs(2 * lightness - 1))
    if cmax == rf:
        hue = 60 * (((gf - bf) / delta) % 6)
    elif cmax == gf:
        hue = 60 * ((bf - rf) / delta + 2)
    else:
        hue = 60 * ((rf - gf) / delta + 4)
    if hue < 0:
        hue += 360
    return round(hue, 2), round(saturation * 100, 2), round(lightness * 100, 2)


def _rgb_to_hsv(r: int, g: int, b: int) -> tuple[float, float, float]:
    rf, gf, bf = r / 255.0, g / 255.0, b / 255.0
    cmax = max(rf, gf, bf)
    cmin = min(rf, gf, bf)
    delta = cmax - cmin
    if cmax == 0:
        return 0.0, 0.0, 0.0
    saturation = delta / cmax
    if delta == 0:
        return 0.0, 0.0, round(cmax * 100, 2)
    if cmax == rf:
        hue = 60 * (((gf - bf) / delta) % 6)
    elif cmax == gf:
        hue = 60 * ((bf - rf) / delta + 2)
    else:
        hue = 60 * ((rf - gf) / delta + 4)
    if hue < 0:
        hue += 360
    return round(hue, 2), round(saturation * 100, 2), round(cmax * 100, 2)


def _hsl_to_rgb(hue: float, sat: float, light: float) -> tuple[int, int, int]:
    s = sat / 100.0
    light_val = light / 100.0
    c = (1 - abs(2 * light_val - 1)) * s
    hh = hue / 60.0
    x = c * (1 - abs(hh % 2 - 1))
    m = light_val - c / 2.0
    r: float
    g: float
    b: float
    if hh < 1:
        r, g, b = c, x, 0
    elif hh < 2:
        r, g, b = x, c, 0
    elif hh < 3:
        r, g, b = 0, c, x
    elif hh < 4:
        r, g, b = 0, x, c
    elif hh < 5:
        r, g, b = x, 0, c
    else:
        r, g, b = c, 0, x
    return _clamp255((r + m) * 255), _clamp255((g + m) * 255), _clamp255((b + m) * 255)


def _hsv_to_rgb(hue: float, sat: float, value: float) -> tuple[int, int, int]:
    s = sat / 100.0
    v = value / 100.0
    hh = hue / 60.0
    c = v * s
    x = c * (1 - abs(hh % 2 - 1))
    m = v - c
    r: float
    g: float
    b: float
    if hh < 1:
        r, g, b = c, x, 0
    elif hh < 2:
        r, g, b = x, c, 0
    elif hh < 3:
        r, g, b = 0, c, x
    elif hh < 4:
        r, g, b = 0, x, c
    elif hh < 5:
        r, g, b = x, 0, c
    else:
        r, g, b = c, 0, x
    return _clamp255((r + m) * 255), _clamp255((g + m) * 255), _clamp255((b + m) * 255)


def _relative_luminance(r: int, g: int, b: int) -> float:
    def channel(c: float) -> float:
        c /= 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _contrast_ratio(r1: int, g1: int, b1: int, r2: int, g2: int, b2: int) -> float:
    l1 = _relative_luminance(r1, g1, b1)
    l2 = _relative_luminance(r2, g2, b2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return round((lighter + 0.05) / (darker + 0.05), 4)


def _nearest_name(r: int, g: int, b: int) -> str | None:
    best: tuple[float, str] | None = None
    for name, (nr, ng, nb) in _NAMED_COLORS.items():
        dist = math.sqrt((r - nr) ** 2 + (g - ng) ** 2 + (b - nb) ** 2)
        if best is None or dist < best[0]:
            best = (dist, name)
    if best and best[0] < 12.0:
        return best[1]
    return None


def _normalize_output(hue: float) -> float:
    return round(hue % 360, 2)


def _parse_hsl_parts(text: str) -> tuple[int, int, int, float] | None:
    m = _FUNC_RE.match(text.strip())
    if not m:
        return None
    name = m.group(1).lower()
    if name not in ("hsl", "hsla", "hsv", "hsva", "rgb", "rgba"):
        return None
    nums = [p.strip() for p in m.group(2).split(",")]
    try:
        if name.startswith("hsl") or name.startswith("hsv"):
            if len(nums) < 3:
                return None
            hue = float(nums[0].replace("deg", ""))
            sat = float(nums[1].replace("%", ""))
            third = float(nums[2].replace("%", ""))
            alpha = float(nums[3]) if name.startswith("hsla") and len(nums) == 4 else 1.0
            if not (0 <= hue <= 360 and 0 <= sat <= 100 and 0 <= third <= 100):
                return None
            if name.startswith("hsl"):
                r, g, b = _hsl_to_rgb(hue, sat, third)
            else:
                r, g, b = _hsv_to_rgb(hue, sat, third)
            return r, g, b, min(1.0, max(0.0, alpha))
        if len(nums) < 3 or len(nums) > 4:
            return None
        r, g, b = int(nums[0]), int(nums[1]), int(nums[2])
        if not (0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255):
            return None
        alpha = float(nums[3]) if len(nums) == 4 else 1.0
        return r, g, b, min(1.0, max(0.0, alpha))
    except ValueError:
        return None


def _parse_color(text: str, hint: str) -> tuple[int, int, int, float, str] | None:
    t = text.strip().lower()
    parsed = _hex_to_rgb(t)
    if parsed is not None:
        return parsed[0], parsed[1], parsed[2], parsed[3], "hex"
    named = _NAMED_COLORS.get(t)
    if named is not None:
        return named[0], named[1], named[2], 1.0, "name"
    if "(" in t and ")" in t:
        m = _FUNC_RE.match(t)
        if m:
            func = m.group(1).lower()
            if hint in ("auto",) or hint == func:
                parsed_func = _parse_hsl_parts(t)
                if parsed_func:
                    return parsed_func[0], parsed_func[1], parsed_func[2], parsed_func[3], func
    if hint not in ("auto", "hex") and _FUNC_RE.match(t) is None:
        pass
    return None


def color_convert(color: str, from_format: str, background: str | None) -> dict[str, Any]:
    hint = "hex" if from_format == "hex" else (
        from_format if from_format != "auto" else "auto"
    )
    parsed = _parse_color(color, hint)
    if parsed is None:
        raise ValidationError(
            "Unrecognized color format. Use hex (#rgb/#rrggbb/#rrggbbaa), "
            "rgb()/rgba(), hsl()/hsla(), hsv()/hsva() or a CSS named colour."
        )
    r, g, b, alpha, source = parsed
    hue, sat_pct, light_pct = _rgb_to_hsl(r, g, b)
    hue_v, sat_v, val_v = _rgb_to_hsv(r, g, b)
    hex_str = _rgb_to_hex(r, g, b)

    css: dict[str, str] = {
        "hex": hex_str,
        "rgb": f"rgb({r}, {g}, {b})",
        "rgba": f"rgba({r}, {g}, {b}, {alpha:.2f})",
        "hsl": f"hsl({hue:.2f}deg, {sat_pct:.2f}%, {light_pct:.2f}%)",
        "hsla": f"hsla({hue:.2f}deg, {sat_pct:.2f}%, {light_pct:.2f}%, {alpha:.2f})",
        "hsv": f"hsv({hue_v:.2f}, {sat_v:.2f}%, {val_v:.2f}%)",
    }
    result: dict[str, Any] = {
        "valid": True,
        "error": None,
        "from_format": source,
        "hex": hex_str,
        "rgb": {"r": r, "g": g, "b": b},
        "rgba": {"r": r, "g": g, "b": b, "a": alpha},
        "hsl": {"h": hue, "s": sat_pct, "lightness": light_pct},
        "hsv": {"h": hue_v, "s": sat_v, "v": val_v},
        "css": css,
        "luminance": round(_relative_luminance(r, g, b), 6),
        "contrast": None,
        "notes": [],
    }
    if background:
        bg = _parse_color(background, "auto")
        if bg is None:
            raise ValidationError("Background color is not a recognized color format.")
        result["contrast"] = _contrast_ratio(r, g, b, bg[0], bg[1], bg[2])
        result["notes"].append(
            "WCAG AA (>= 4.5) / large-text AA (>= 3.0): %s"
            % ("passes" if result["contrast"] >= 4.5 else (
                "large text only" if result["contrast"] >= 3.0 else "fails"
            ))
        )
    name = _nearest_name(r, g, b)
    if name:
        result["notes"].append(f"Approximate CSS color name: {name}")
    return result
