import requests
import re

HEADERS = {
    "User-Agent": "PhantomRecon/1.0 (OSINT Research)"
}

COMMON_PATHS = [
    "/admin",
    "/login",
    "/wp-admin",
    "/cpanel",
    "/dashboard"
]

TECH_SIGNS = {
    "WordPress": "wp-content",
    "Joomla": "joomla",
    "Drupal": "drupal",
    "Laravel": "laravel",
    "Django": "csrfmiddlewaretoken",
    "React": "react",
    "Vue": "vue",
    "Angular": "angular"
}


def fingerprint_tech(domain):
    url = f"https://{domain}"
    result = {
        "server": None,
        "technologies": [],
        "security_headers": {},
        "admin_panels": [],
        "risk": "LOW"
    }

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
    except Exception:
        return result

    # Server header
    result["server"] = r.headers.get("Server")

    # Security headers
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]

    missing = 0
    for h in security_headers:
        if h in r.headers:
            result["security_headers"][h] = "Present"
        else:
            result["security_headers"][h] = "Missing"
            missing += 1

    # Tech detection via HTML
    html = r.text.lower()
    for tech, sig in TECH_SIGNS.items():
        if sig in html:
            result["technologies"].append(tech)

    # Admin panel discovery
    for path in COMMON_PATHS:
        try:
            p = requests.get(url + path, headers=HEADERS, timeout=5)
            if p.status_code in [200, 401, 403]:
                result["admin_panels"].append(path)
        except Exception:
            pass

    # Risk scoring
    if missing >= 3 or result["admin_panels"]:
        result["risk"] = "MEDIUM"
    if "WordPress" in result["technologies"] and missing >= 3:
        result["risk"] = "HIGH"

    return result
