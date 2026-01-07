import re
import requests

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Firebase URL": r"https://[a-z0-9\-]+\.firebaseio\.com",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
}


def scan_js_for_secrets(js_urls):
    findings = []

    for url in js_urls:
        try:
            r = requests.get(url, timeout=7)
            content = r.text
        except Exception:
            continue

        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "source": url,
                    "type": name,
                    "matches": list(set(matches)),
                    "risk": "HIGH"
                })

    return findings
