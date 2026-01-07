import whois
import dns.resolver


def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers or []
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def get_dns_records(domain):
    records = {}
    resolver = dns.resolver.Resolver()

    for record_type in ["A", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(r).strip() for r in answers]
        except Exception:
            records[record_type] = []

    return records


def analyze_dns_exposure(dns_data):
    findings = []

    # Mail exposure
    if dns_data.get("MX"):
        findings.append("Mail servers exposed (MX records present)")

    # SPF
    spf = [r for r in dns_data.get("TXT", []) if r.lower().startswith("v=spf1")]
    if spf:
        findings.append("SPF record detected")
    else:
        findings.append("No SPF record detected")

    # DMARC
    dmarc = [r for r in dns_data.get("TXT", []) if "v=dmarc" in r.lower()]
    if dmarc:
        findings.append("DMARC policy detected")
        if "p=none" in dmarc[0].lower():
            findings.append("Weak DMARC policy (monitoring only)")
    else:
        findings.append("No DMARC policy detected")

    # CNAME exposure
    if dns_data.get("CNAME"):
        findings.append("CNAME record detected (possible CDN or SaaS exposure)")

    # Cloud hints
    ns_joined = " ".join(dns_data.get("NS", [])).lower()
    if "awsdns" in ns_joined:
        findings.append("AWS DNS infrastructure detected")
    if "cloudflare" in ns_joined:
        findings.append("Cloudflare DNS infrastructure detected")
    if "azure" in ns_joined:
        findings.append("Azure DNS infrastructure detected")

    return findings


def domain_intel(domain):
    whois_data = get_whois_info(domain)
    dns_data = get_dns_records(domain)
    dns_plus = analyze_dns_exposure(dns_data)

    return {
        "whois": whois_data,
        "dns": dns_data,
        "dns_plus": dns_plus
    }
