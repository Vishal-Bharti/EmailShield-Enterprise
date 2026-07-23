"""
URL redirect chain analyzer.

Attackers commonly hide the real destination of a phishing link behind
a URL shortener or an open-redirect chain (bit.ly -> tracking domain
-> the actual phishing site). A link that *looks* like bit.ly/xyz
gives no visibility into where it actually leads without following
it. This module follows each redirect hop (HEAD request, GET
fallback) up to a safety cap and reports the final destination plus
every intermediate hop.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse

import requests

MAX_REDIRECTS = 8
REQUEST_TIMEOUT = 5

# A request per URL is expensive (network round trip), so this
# analyzer is capped to avoid an email with dozens of links turning
# into a slow, hammering burst of outbound requests.
MAX_URLS_TO_CHECK = 15

KNOWN_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "s.id", "v.gd", "shorte.st", "adf.ly", "bl.ink",
    "lnkd.in", "youtu.be",
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}


def is_shortener_domain(domain):

    domain = (domain or "").lower()

    return domain in KNOWN_SHORTENER_DOMAINS or any(
        domain.endswith("." + short) for short in KNOWN_SHORTENER_DOMAINS
    )


def _is_private_or_local(hostname):
    """Refuse to follow a redirect into a private/internal address.

    Without this check, a malicious redirect chain could point at
    169.254.169.254 (cloud metadata endpoints), localhost, or an
    internal network address - turning this feature into a
    server-side request forgery (SSRF) vector. Any hop that resolves
    to a private/loopback/link-local address stops the chain here.
    """

    try:
        # Strip a port if present (e.g. "example.com:8080")
        host = hostname.split(":")[0]
        addr_info = socket.getaddrinfo(host, None)

        for info in addr_info:
            ip = ipaddress.ip_address(info[4][0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
            ):
                return True

        return False

    except Exception:
        # If resolution fails, don't block the check on that alone -
        # the request itself will simply fail and be handled below.
        return False


def trace_redirect_chain(url):
    """Follow a URL's redirect chain manually (not requests' built-in
    auto-follow) so every intermediate hop can be recorded and each
    hop's target can be checked against private/internal addresses
    before it's requested.

    Returns a dict:
        {
            "original_url": str,
            "final_url": str,
            "hops": [str, ...],       # each URL in the chain, in order
            "hop_count": int,
            "status": "ok" | "error" | "blocked_private_address" | "too_many_redirects",
            "error": str | None,
        }
    """

    hops = [url]
    current_url = url

    for _ in range(MAX_REDIRECTS):

        parsed = urlparse(current_url)

        if not parsed.scheme or not parsed.netloc:
            return {
                "original_url": url,
                "final_url": current_url,
                "hops": hops,
                "hop_count": len(hops) - 1,
                "status": "error",
                "error": "Malformed URL",
            }

        if _is_private_or_local(parsed.netloc):
            return {
                "original_url": url,
                "final_url": current_url,
                "hops": hops,
                "hop_count": len(hops) - 1,
                "status": "blocked_private_address",
                "error": f"Redirect target resolves to a private/internal address: {parsed.netloc}",
            }

        try:

            response = requests.head(
                current_url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )

            # Some servers don't support HEAD properly (405, or return
            # a generic 200 without the real redirect) - fall back to
            # GET without downloading the body.
            if response.status_code in (405, 501) or (
                response.status_code == 200 and "location" not in response.headers
            ):
                response = requests.get(
                    current_url,
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                    stream=True,
                )
                response.close()

        except requests.exceptions.RequestException as e:
            return {
                "original_url": url,
                "final_url": current_url,
                "hops": hops,
                "hop_count": len(hops) - 1,
                "status": "error",
                "error": str(e),
            }

        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):

            location = response.headers.get("Location")

            if not location:
                break

            # Resolve relative redirects (e.g. Location: /login)
            if location.startswith("/"):
                location = f"{parsed.scheme}://{parsed.netloc}{location}"

            if location == current_url:
                # Redirect loop to itself - stop rather than spin.
                break

            current_url = location
            hops.append(current_url)
            continue

        # Not a redirect - this is the final destination.
        return {
            "original_url": url,
            "final_url": current_url,
            "hops": hops,
            "hop_count": len(hops) - 1,
            "status": "ok",
            "error": None,
        }

    return {
        "original_url": url,
        "final_url": current_url,
        "hops": hops,
        "hop_count": len(hops) - 1,
        "status": "too_many_redirects",
        "error": f"Exceeded {MAX_REDIRECTS} redirect hops",
    }


def analyze_url_redirects(urls):
    """Trace redirect chains for a list of URLs found in an email.

    Returns a list of trace results (see trace_redirect_chain), capped
    at MAX_URLS_TO_CHECK to bound total request volume, with each
    result additionally tagged with risk indicators:
        - starts_as_shortener: bool
        - domain_changed: bool     (final domain differs from original)
        - excessive_hops: bool     (hop_count >= 4)
    """

    results = []

    for url in urls[:MAX_URLS_TO_CHECK]:

        trace = trace_redirect_chain(url)

        original_domain = urlparse(trace["original_url"]).netloc.lower()
        final_domain = urlparse(trace["final_url"]).netloc.lower()

        trace["starts_as_shortener"] = is_shortener_domain(original_domain)
        trace["domain_changed"] = bool(
            original_domain and final_domain and original_domain != final_domain
        )
        trace["excessive_hops"] = trace["hop_count"] >= 4

        results.append(trace)

    return results
