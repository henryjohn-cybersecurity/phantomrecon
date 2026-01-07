import dns.resolver
import requests

TAKEOVER_SIGNATURES = {
    "AWS_S3": "NoSuchBucket",
    "GitHub_Pages": "There isn't a GitHub Pages site here",
    "Heroku": "no such app",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Zendesk": "Help Center Closed",
    "Fastly": "Fastly error"
}


def check_takeover(subdomains):
    findings = []

    for sub in subdomains:
        result = {
            "subdomain": sub,
            "cname": None,
            "service": None,
            "takeover_possible": False,
            "evidence": None
        }

        try:
            answers = dns.resolver.resolve(sub, "CNAME")
            cname = answers[0].target.to_text().lower()
            result["cname"] = cname
        except Exception:
            continue

        try:
            r = requests.get(f"http://{sub}", timeout=7)
            body = r.text.lower()
        except Exception:
            continue

        for service, signature in TAKEOVER_SIGNATURES.items():
            if signature.lower() in body:
                result["service"] = service
                result["takeover_possible"] = True
                result["evidence"] = signature
                break

        if result["takeover_possible"]:
            findings.append(result)

    return findings
