import re
import requests

SECRET_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-_\.]+",
    "Password Assignment": r"(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']+[\"']",
    "Client Secret": r"(client_secret|secret_key)\s*[:=]\s*[\"'][^\"']+[\"']",
    "Admin Endpoint": r"/admin|/dashboard|/internal",
    "API Endpoint": r"/api/v[0-9]+/[A-Za-z0-9/_-]+"
}

def scan_js_for_secrets(js_urls):
    findings = []

    for url in js_urls:
        try:
            r = requests.get(url, timeout=8)
            content = r.text
        except Exception:
            continue

        for label, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "type": label,
                    "source": url,
                    "matches": list(set(matches)),
                    "risk": "HIGH" if "Key" in label or "Secret" in label else "MEDIUM"
                })

    return findings
