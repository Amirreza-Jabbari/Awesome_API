"""Hosting-provider detection helpers.

Mapping an ASN org name to a recognizable hosting brand is heuristic. This
module returns the raw ASN/org string when no confident mapping exists rather
than inventing a provider.
"""

from __future__ import annotations

# Known hosting / cloud brands and substrings typically seen in ASN org names.
_HOSTING_KEYWORDS = (
    "amazon",
    "aws",
    "google cloud",
    "google llc",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "linode",
    "ovh",
    "hetzner",
    "vultr",
    "scaleway",
    "cloudflare",
    "akamai",
    "fastly",
    "godaddy",
    "hostinger",
    "dreamhost",
    "bluehost",
    "namecheap",
    "rackspace",
    "softlayer",
    "ibm cloud",
    "oracle cloud",
    "alibaba",
    "tencent cloud",
    "heroku",
    "render",
    "fly.io",
    "vercel",
    "netlify",
    "cloudsigma",
    "contabo",
    "iwebfusion",
)


def detect_hosting_provider_from_asn(asn_name: str | None) -> str | None:
    """Return a human-friendly hosting brand for an ASN name, if recognizable."""
    if not asn_name:
        return None
    text = asn_name.lower().replace("_", " ")
    for keyword in _HOSTING_KEYWORDS:
        if keyword in text:
            # Map a few well-known brand names to their public name.
            mapping = {
                "amazon": "Amazon Web Services",
                "aws": "Amazon Web Services",
                "google cloud": "Google Cloud",
                "google llc": "Google",
                "google": "Google",
                "microsoft": "Microsoft Azure",
                "azure": "Microsoft Azure",
            }
            for k, v in mapping.items():
                if keyword == k:
                    return v
            return keyword.title()
    return asn_name
