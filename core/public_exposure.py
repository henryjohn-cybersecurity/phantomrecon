import requests
from urllib.parse import urljoin

COMMON_EXPOSED_FILES = [
    ".env",
    ".git/config",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "database.sql",
    "config.php",
    "settings.py",
    "robots.txt",
    ".DS_Store"
]

HEADERS = {
    "User-Agent": "PhantomRecon/1.0 (OSINT Research)"
}


def check_file(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=8)
        if r.status_code == 200 and len(r.text) > 0:
            return True
    except Exception:
        pass
    return False


def discover_public_exposures(domain):
    base_urls = [
        f"https://{domain}/",
        f"https://www.{domain}/"
    ]

    exposed = []
    evidence = []

    for base in base_urls:
        for file in COMMON_EXPOSED_FILES:
            full_url = urljoin(base, file)
            if check_file(full_url):
                exposed.append(full_url)
                evidence.append(f"Publicly accessible file: {file}")

    risk = "LOW"
    if any(".env" in e or ".git" in e for e in exposed):
        risk = "HIGH"
    elif exposed:
        risk = "MEDIUM"

    return {
        "exposed_files": exposed,
        "risk": risk,
        "evidence": evidence
    }
