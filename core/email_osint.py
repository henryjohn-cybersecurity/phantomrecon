import re
import requests
from urllib.parse import urljoin

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

COMMON_PATHS = [
    "/contact",
    "/about",
    "/support",
    "/legal",
    "/privacy",
    "/security",
    "/.well-known/security.txt"
]

COMMON_ALIASES = [
    "info@", "contact@", "support@", "security@", "abuse@", "admin@"
]


def extract_emails(text):
    return set(re.findall(EMAIL_REGEX, text))


def fetch(url):
    try:
        r = requests.get(url, timeout=10, headers={
            "User-Agent": "PhantomRecon OSINT Scanner"
        })
        return r.text if r.status_code == 200 else ""
    except Exception:
        return ""


def discover_emails(domain):
    emails = []
    findings = set()
    security_txt_found = False

    bases = [f"https://{domain}", f"https://www.{domain}"]

    # 1️⃣ Crawl pages + security.txt
    for base in bases:
        for path in COMMON_PATHS:
            url = urljoin(base, path)
            content = fetch(url)
            if not content:
                continue

            if "security.txt" in path:
                security_txt_found = True

            found = extract_emails(content)
            for email in found:
                findings.add(email)

    # 2️⃣ Header-based discovery
    try:
        r = requests.head(bases[0], timeout=5)
        header_text = " ".join(r.headers.values())
        findings.update(extract_emails(header_text))
    except Exception:
        pass

    # 3️⃣ Alias guessing (low confidence)
    for alias in COMMON_ALIASES:
        findings.add(f"{alias}{domain}")

    # Build structured output
    for email in findings:
        confidence = "low"
        source = "guessed"

        if email.endswith(domain):
            confidence = "medium"
            source = "on-site"

        if "security@" in email:
            confidence = "high"
            source = "security"

        emails.append({
            "email": email,
            "type": "organizational",
            "source": source,
            "confidence": confidence
        })

    return {
        "emails": emails,
        "security_txt_found": security_txt_found
    }
