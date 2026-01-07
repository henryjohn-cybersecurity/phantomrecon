import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; PhantomRecon/1.0; +https://example.com)"
}

def fingerprint_tech_stack(domain):
    url = f"https://{domain}"
    result = {
        "server": None,
        "backend": [],
        "frontend": [],
        "cdn_waf": [],
        "cms": None,
        "analytics": [],
        "third_party": [],
        "security_headers": {},
        "confidence": "low"
    }

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
    except Exception:
        return result

    headers = r.headers
    html = r.text.lower()

    # --------------------
    # SERVER / CDN
    # --------------------
    server = headers.get("Server", "").lower()
    if "cloudflare" in server:
        result["cdn_waf"].append("Cloudflare")
    if "nginx" in server:
        result["server"] = "nginx"
    if "apache" in server:
        result["server"] = "apache"

    # --------------------
    # SECURITY HEADERS
    # --------------------
    result["security_headers"] = {
        "hsts": "strict-transport-security" in headers,
        "csp": "content-security-policy" in headers,
        "x_frame_options": "x-frame-options" in headers,
        "x_content_type": "x-content-type-options" in headers
    }

    # --------------------
    # BACKEND HINTS
    # --------------------
    if "x-powered-by" in headers:
        powered = headers["x-powered-by"].lower()
        if "express" in powered:
            result["backend"].append("Node.js (Express)")
        if "php" in powered:
            result["backend"].append("PHP")
        if "asp.net" in powered:
            result["backend"].append("ASP.NET")

    # --------------------
    # CMS DETECTION
    # --------------------
    if "wp-content" in html:
        result["cms"] = "WordPress"

    # --------------------
    # HTML & JS ANALYSIS
    # --------------------
    soup = BeautifulSoup(r.text, "html.parser")
    scripts = soup.find_all("script", src=True)

    for s in scripts:
        src = s["src"].lower()

        if "react" in src:
            result["frontend"].append("React")
        if "vue" in src:
            result["frontend"].append("Vue.js")
        if "next" in src:
            result["frontend"].append("Next.js")

        if "googletagmanager" in src or "google-analytics" in src:
            result["analytics"].append("Google Analytics")

        if "stripe" in src:
            result["third_party"].append("Stripe")
        if "firebase" in src:
            result["third_party"].append("Firebase")
        if "sentry" in src:
            result["third_party"].append("Sentry")

    # --------------------
    # CONFIDENCE SCORING
    # --------------------
    signals = sum([
        bool(result["backend"]),
        bool(result["frontend"]),
        bool(result["cdn_waf"]),
        bool(result["cms"]),
        bool(result["third_party"])
    ])

    if signals >= 4:
        result["confidence"] = "high"
    elif signals >= 2:
        result["confidence"] = "medium"

    # Deduplicate
    for k in ["backend", "frontend", "analytics", "third_party", "cdn_waf"]:
        result[k] = list(set(result[k]))

    return result
