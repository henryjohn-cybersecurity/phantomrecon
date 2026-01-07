import requests

# Known CDN / cloud providers (keyword-based)
CDN_KEYWORDS = [
    "cloudflare", "akamai", "fastly",
    "cloudfront", "incapsula",
    "stackpath", "azure", "google",
    "amazon", "aws", "gcp"
]


def is_cdn(org_name: str) -> bool:
    if not org_name:
        return False
    org = org_name.lower()
    return any(keyword in org for keyword in CDN_KEYWORDS)


def lookup_ip(ip):
    """
    Enrich IP with geo, ASN, org info
    Uses ip-api (free, no key)
    """
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as",
            timeout=8
        )
        data = r.json()
        if data.get("status") != "success":
            return None

        return {
            "ip": ip,
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as")
        }
    except Exception:
        return None


def fetch_http_headers(ip):
    """
    Safely fetch HTTP headers from IP (no exploitation)
    """
    try:
        url = f"http://{ip}"
        r = requests.head(url, timeout=6, allow_redirects=True)
        return dict(r.headers)
    except Exception:
        return {}


def classify_ip(ip_info, dns_data):
    """
    Decide if IP is CDN or possible origin
    """
    score = 0
    evidence = []

    org = (ip_info.get("org") or "").lower()

    # CDN detection
    if is_cdn(org):
        evidence.append("IP belongs to known CDN provider")
    else:
        score += 3
        evidence.append("IP organization not linked to known CDN")

    # DNS signals
    if dns_data.get("CNAME"):
        evidence.append("CNAME record detected (likely CDN in front)")
    else:
        score += 2
        evidence.append("No CNAME record detected")

    # Header signals
    headers = ip_info.get("headers", {})
    header_str = " ".join(headers.keys()).lower()

    if any(h in header_str for h in ["cf-ray", "x-cache", "via", "akamai"]):
        evidence.append("CDN-related HTTP headers detected")
    else:
        score += 2
        evidence.append("No CDN headers detected in HTTP response")

    # Final classification
    if score >= 6:
        classification = "LIKELY_ORIGIN"
        risk = "HIGH"
    elif score >= 3:
        classification = "POSSIBLE_ORIGIN"
        risk = "MEDIUM"
    else:
        classification = "CDN_EDGE"
        risk = "LOW"

    return classification, risk, evidence


def bulk_ip_lookup(ips, dns_data):
    """
    Full IP intelligence + origin exposure analysis
    """
    results = []

    for ip in ips:
        ip_info = lookup_ip(ip)
        if not ip_info:
            continue

        headers = fetch_http_headers(ip)
        ip_info["headers"] = headers

        classification, risk, evidence = classify_ip(ip_info, dns_data)

        ip_info.update({
            "classification": classification,
            "risk": risk,
            "evidence": evidence
        })

        results.append(ip_info)

    return results
