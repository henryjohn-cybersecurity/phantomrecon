import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


SOCIAL_DOMAINS = {
    "Twitter": "twitter.com",
    "LinkedIn": "linkedin.com",
    "Facebook": "facebook.com",
    "Instagram": "instagram.com",
    "GitHub": "github.com"
}


def extract_social_links(html, base_domain):
    soup = BeautifulSoup(html, "html.parser")
    discovered = []

    for link in soup.find_all("a", href=True):
        href = link["href"]

        for platform, domain in SOCIAL_DOMAINS.items():
            if domain in href:
                confidence = "medium"

                # Increase confidence if domain appears in link text or nearby
                if base_domain in href:
                    confidence = "high"

                discovered.append({
                    "platform": platform,
                    "profile_url": href,
                    "discovered_via": "website_html",
                    "confidence": confidence
                })

    return discovered


def discover_social_presence(domain):
    url = f"http://{domain}"
    results = []

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            html = response.text
            results = extract_social_links(html, domain)
    except Exception:
        pass

    return results
