"""
URL redirect chain tracer. Follows redirects manually to reveal final destination.
Never renders page content. Network calls only via requests HEAD/GET with short timeout.
All string outputs are sanitized against prompt injection.
URLs themselves are never modified — only inspected for injection triggers.
Cloaking detection: same URL is traced with desktop, mobile, and bot User-Agents.
Divergent final destinations across agents indicate conditional-redirect cloaking.
Does NOT render pages or execute JavaScript — header-only inspection only.
"""

import socket
import requests
from urllib.parse import urljoin, urlparse, unquote_plus

from utils.cache import cache
from utils.logger import get_logger
from utils.validators import is_safe_host_to_fetch
from core.reasoning.injection_guard import INJECTION_TRIGGERS

logger = get_logger(__name__)

# Three distinct User-Agent strings used for cloaking detection.
# Keys: "desktop", "mobile", "bot". Do not reorder — order is referenced by name only.
USER_AGENTS = {
    "desktop": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "bot": "python-requests/2.31.0",
}


def detect_injection_in_url(url: str) -> bool:
    """
    Check whether the URL path or query parameters contain injection trigger keywords.

    URLs are NEVER modified or truncated — this function is read-only inspection only.
    Returns True if an injection attempt is detected, False otherwise.
    Never raises.
    """
    try:
        parsed = urlparse(url)
        # Decode percent-encoding and '+'-as-space before checking triggers
        inspectable = unquote_plus(f"{parsed.path} {parsed.query}").lower()
        for trigger in INJECTION_TRIGGERS:
            if trigger in inspectable:
                logger.warning(
                    "Injection trigger detected in URL path/query",
                    extra={"trigger_found": trigger, "url": url[:120]},
                )
                return True
        return False
    except Exception as exc:
        logger.warning(
            "detect_injection_in_url raised unexpectedly; defaulting to False.",
            extra={"error": str(exc)},
        )
        return False


def _follow_redirects(url: str, user_agent: str) -> dict:
    """
    Follow the redirect chain for a single URL using the supplied User-Agent string.

    Private — only called by get_url_trail. Never import or call from outside this module.
    Returns a dict with keys: hops, final_url, final_ip.
    On any failure or timeout, returns the sentinel: {"hops": [], "final_url": "timeout", "final_ip": ""}.
    Does NOT check the cache. Does NOT sanitize for injection — callers handle that.
    """
    _MAX_HOPS = 10
    _TIMEOUT_SEC = 5

    hops = [url]
    current_url = url

    try:
        for _ in range(_MAX_HOPS):
            # ── SSRF guard: validate scheme and host on EVERY hop ──────────────
            parsed_check = urlparse(current_url)
            if parsed_check.scheme not in ("http", "https"):
                logger.warning(
                    "Blocked non-http(s) scheme during redirect trace",
                    extra={"scheme": parsed_check.scheme, "url": current_url[:120]},
                )
                return {"hops": hops, "final_url": "blocked_invalid_scheme", "final_ip": ""}

            hostname_check = parsed_check.hostname
            if not hostname_check or not is_safe_host_to_fetch(hostname_check):
                logger.warning(
                    "Blocked SSRF attempt — private/reserved/invalid host",
                    extra={"host": hostname_check, "url": current_url[:120]},
                )
                return {"hops": hops, "final_url": "blocked_private_ip", "final_ip": ""}
            # ──────────────────────────────────────────────────────────────────

            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=_TIMEOUT_SEC,
                stream=True,
                headers={"User-Agent": user_agent},
            )
            # CRITICAL: drop body immediately — never buffer potentially malicious content
            response.close()

            if response.status_code in (301, 302, 303, 307, 308) and "Location" in response.headers:
                next_url = urljoin(current_url, response.headers["Location"])
                hops.append(next_url)
                current_url = next_url
            else:
                break

        # Resolve final IP
        final_ip = ""
        domain = urlparse(current_url).hostname
        if domain:
            try:
                final_ip = socket.gethostbyname(domain)
            except socket.error as dns_exc:
                logger.warning(
                    "DNS resolution failed in _follow_redirects",
                    extra={"domain": domain, "error": str(dns_exc)},
                )

        return {"hops": hops, "final_url": current_url, "final_ip": final_ip}

    except requests.exceptions.Timeout:
        logger.warning(
            "_follow_redirects timed out",
            extra={"url": url[:120], "user_agent": user_agent[:60]},
        )
        return {"hops": [], "final_url": "timeout", "final_ip": ""}
    except Exception as exc:
        logger.error(
            "_follow_redirects raised unexpectedly",
            extra={"url": url[:120], "error": str(exc)},
        )
        return {"hops": [], "final_url": "timeout", "final_ip": ""}


def get_url_trail(url: str) -> dict:
    """
    Trace the redirect chain of a URL using three User-Agents to detect cloaking.

    Returns the canonical osint_bundle url_trail shape, extended with:
      - cloaking_detected: bool — True if final_url differs across agents
      - alternate_destinations: list[str] — unique final URLs seen
      - agent_results: dict — per-agent final_url strings
    Primary trail (hops, final_url, final_ip) is always the desktop agent result.
    On total failure, falls back to primary trail with cloaking_detected=False.
    Result is cached before returning. Cache is always checked first.
    """
    cache_key = f"url_trail:{url}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        desktop = _follow_redirects(url, USER_AGENTS["desktop"])
        mobile = _follow_redirects(url, USER_AGENTS["mobile"])
        bot = _follow_redirects(url, USER_AGENTS["bot"])

        # Collect non-timeout final URLs for cloaking comparison
        final_urls = {
            agent: result["final_url"]
            for agent, result in [("desktop", desktop), ("mobile", mobile), ("bot", bot)]
            if result["final_url"] != "timeout"
        }

        unique_destinations = set(final_urls.values())
        cloaking_detected = len(unique_destinations) > 1

        if cloaking_detected:
            logger.warning(
                "Cloaking detected — divergent final URLs across User-Agents",
                extra={"url": url[:120], "destinations": list(unique_destinations)},
            )

        result = {
            # Primary trail from desktop agent (canonical for downstream modules)
            "hops": desktop["hops"],
            "final_url": desktop["final_url"],
            "final_ip": desktop["final_ip"],
            "injection_in_url": detect_injection_in_url(desktop["final_url"]),
            # Cloaking fields
            "cloaking_detected": cloaking_detected,
            "alternate_destinations": list(unique_destinations),
            "agent_results": {
                "desktop": desktop["final_url"],
                "mobile": mobile["final_url"],
                "bot": bot["final_url"],
            },
        }

        cache.set(cache_key, result)
        return result

    except Exception as exc:
        logger.error(
            "get_url_trail failed entirely; returning safe fallback",
            extra={"url": url[:120], "error": str(exc)},
        )
        return {
            "hops": [],
            "final_url": url,
            "final_ip": "",
            "injection_in_url": detect_injection_in_url(url),
            "cloaking_detected": False,
            "alternate_destinations": [],
            "agent_results": {"desktop": url, "mobile": "timeout", "bot": "timeout"},
        }


# Alias for backward compatibility / testing
trace_url = get_url_trail

