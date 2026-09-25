"""
Playwright screenshot capture. Requires sandbox=True to prevent accidental live URL rendering.
Only call from the Forensics tab in pages/02_forensics.py with explicit user consent.
"""

from playwright.sync_api import sync_playwright
from utils.logger import get_logger

logger = get_logger(__name__)


def capture_page(url: str, sandbox: bool = False) -> bytes:
    """
    Captures a full-page screenshot of a given URL.
    Sandbox must be enabled to prevent drive-by execution during standard analysis.
    """
    if not sandbox:
        raise ValueError("Screenshot capture requires sandbox=True")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            
            # Block potentially malicious media, fonts, and images (load DOM only)
            context.route("**/*", lambda route: route.abort() 
                if route.request.resource_type in ["image", "media", "font"] 
                else route.continue_())
                
            page = context.new_page()
            # 10 second timeout max
            page.goto(url, timeout=10000)
            
            # Retrieve bytes directly
            screenshot_bytes = page.screenshot(full_page=True)
            
            browser.close()
            return screenshot_bytes
            
    except Exception as e:
        logger.error(f"Playwright error during screenshot capture of {url}: {e}")
        return b""
