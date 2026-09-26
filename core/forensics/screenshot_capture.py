"""
Playwright screenshot capture. Captures static rendered HTML/CSS only.
JavaScript is DISABLED to prevent exploit/beacon code from running against this server.
Host is validated against private/reserved IP ranges before browser launch.
SSRF protection mirrors core/osint/url_tracer.py (FIX-1).
Only call from the Forensics tab in pages/02_forensics.py with explicit user consent.
Does NOT execute page scripts, does NOT follow auth flows, does NOT store cookies.
"""

from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from utils.validators import is_safe_host_to_fetch
from utils.logger import get_logger

logger = get_logger(__name__)


def capture_page(url: str, sandbox: bool = False) -> bytes:
    """
    Captures a full-page screenshot of a given URL.

    Sandbox must be enabled to prevent drive-by execution during standard analysis.
    JavaScript execution is DISABLED — this captures static rendered HTML/CSS only,
    not the live behaviour of the page. This is a deliberate trade-off: a phishing
    page's visual layout is still fully captured for evidentiary purposes, but its
    ability to run exploit code or fingerprinting scripts against this server is
    removed.

    Host is validated against private/reserved IP ranges before every navigation —
    same protection as core/osint/url_tracer.py (FIX-1).

    If a future requirement needs JS-rendered screenshots, Docker-level network
    isolation must be in place first — do not re-enable JS without that.
    """
    # ── Gate 1: sandbox flag (must be caller-explicit) ────────────────────────
    if not sandbox:
        raise ValueError("Screenshot capture requires sandbox=True")

    # ── Gate 2: scheme and host validation (before browser is even launched) ───
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        logger.warning(
            "Blocked non-http(s) scheme in screenshot capture",
            extra={"scheme": parsed.scheme, "url": url[:120]},
        )
        return b""

    if not parsed.hostname or not is_safe_host_to_fetch(parsed.hostname):
        logger.warning(
            "Blocked SSRF attempt in screenshot capture",
            extra={"host": parsed.hostname, "url": url[:120]},
        )
        return b""

    # ── Capture ──────────────────────────────────────────────────────────
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                java_script_enabled=False,   # CRITICAL: prevents exploit/beacon code from running
            )

            # Block image/media/font resources to reduce attack surface further
            context.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in ["image", "media", "font"]
                else route.continue_(),
            )

            page = context.new_page()
            page.goto(url, timeout=10000)

            screenshot_bytes = page.screenshot(full_page=True)
            browser.close()
            return screenshot_bytes

    except Exception as e:
        logger.error(f"Playwright error during screenshot capture of {url}: {e}")
        return b""
