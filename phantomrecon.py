from core.whois_dns import domain_intel
from core.ip_intel import bulk_ip_lookup
from core.social_osint import discover_social_presence
from core.email_osint import discover_emails
from core.exposure_scoring import calculate_exposure_score
from reporting.html_report import generate_html_report
from reporting.report_generator import save_json_report
from core.tech_stack import fingerprint_tech_stack
from core.subdomain_enum import enumerate_subdomains
from core.cloud_intel import detect_cloud
from core.tech_fingerprint import fingerprint_tech
from core.public_exposure import discover_public_exposures
from core.subdomain_takeover import check_takeover
from core.js_intel import extract_js_files
from core.js_secrets import scan_js_for_secrets
from core.mitre_mapper import map_to_mitre
from reporting.pdf_export import export_html_to_pdf



import time
import random

STEALTH_MODE = True


def stealth_delay():
    if STEALTH_MODE:
        time.sleep(random.uniform(1.5, 3.5))


def print_section(title):
    print(f"\n[ {title.upper()} ]")


def print_list(label, items):
    print(f"• {label}:")
    if not items:
        print("   - None")
    else:
        for item in items:
            print(f"   - {item}")


def main():
    html_path = None
    target = "example.com"

    # ================== BASE RECON ==================
    intel = domain_intel(target)
    stealth_delay()

    whois_data = intel.get("whois", {})
    dns_data = intel.get("dns", {})
    ips = dns_data.get("A", [])

    ip_data = bulk_ip_lookup(ips, dns_data) if ips else []

    tech_stack = fingerprint_tech_stack(target)
    tech_fingerprint = fingerprint_tech(target)

    subdomains = enumerate_subdomains(target)
    stealth_delay()

    cloud = detect_cloud(ip_data, dns_data)

    public_exposure = discover_public_exposures(target)
    stealth_delay()

    takeovers = check_takeover(subdomains)
    stealth_delay()

    socials = discover_social_presence(target)
    stealth_delay()

    email_result = discover_emails(target)
    emails = email_result.get("emails", [])
    security_txt_found = email_result.get("security_txt_found", False)

    js_files = extract_js_files(target)
    leaks = scan_js_for_secrets(js_files)

    # ================== DNS+ ANALYSIS ==================
    dns_plus_findings = []

    if dns_data.get("MX"):
        dns_plus_findings.append("Mail servers exposed (MX records present)")

    for txt in dns_data.get("TXT", []):
        txt_l = txt.lower()
        if "spf" in txt_l:
            dns_plus_findings.append("SPF record detected")
        if "dkim" in txt_l:
            dns_plus_findings.append("DKIM record detected")
        if "dmarc" in txt_l:
            dns_plus_findings.append("DMARC policy present")

    if len(ips) > 5:
        dns_plus_findings.append("Multiple IPs detected (CDN or load balancing)")

    # ================== SOCIAL+ ANALYSIS ==================
    social_plus = {
        "count": len(socials),
        "risk": "LOW"
    }

    if len(socials) >= 3:
        social_plus["risk"] = "MEDIUM"
    if len(socials) >= 6:
        social_plus["risk"] = "HIGH"
    

    # ================== EXPOSURE SCORE ==================
    exposure = calculate_exposure_score(
        emails=emails,
        socials=socials,
        ip_data=ip_data,
        dns_data=dns_data,
        security_txt_found=security_txt_found
    )

    # ================== MITRE MAPPING ==================
    findings = {
        "emails": emails,
        "socials": socials,
        "dns": dns_data,
        "ips": ip_data,
        "js_secrets": leaks,
        "cloud": cloud
    }

    mitre_attack_surface = map_to_mitre(findings)
    

    # ================== FINAL RESULT ==================
    full_result = {
        "target": target,
        "whois": whois_data,
        "dns": dns_data,
        "ip_intel": ip_data,
        "socials": socials,
        "emails": emails,
        "exposure": exposure,
        "dns_plus": dns_plus_findings,
        "social_plus": social_plus,
        "tech_stack": tech_stack,
        "subdomains": subdomains,
        "cloud": cloud,
        "technology_fingerprint": tech_fingerprint,
        "public_exposure": public_exposure,
        "subdomain_takeovers": takeovers,
        "leaks": leaks,
        "mitre_attack_surface": mitre_attack_surface,
        "summary": {
            "overall_risk": exposure["risk_level"],
            "email_count": len(emails),
            "social_count": len(socials),
            "ip_count": len(ip_data)
        }
    }



    # ================== OUTPUT ==================
    print("\n=== PHANTOMRECON REPORT ===")

    print_section("WHOIS Information")
    print(f"• Domain Name     : {whois_data.get('domain')}")
    print(f"• Registrar       : {whois_data.get('registrar')}")
    print(f"• Creation Date   : {whois_data.get('creation_date')}")
    print(f"• Expiration Date : {whois_data.get('expiration_date')}")
    print_list("Name Servers", whois_data.get("name_servers", []))

    print_section("DNS Records")
    for rtype, records in dns_data.items():
        print_list(f"{rtype} Records", records)

    print_section("DNS+ Intelligence")
    for f in dns_plus_findings:
        print(f"• {f}")

    print_section("IP Intelligence")
    for ip in ip_data:
        print(f"• {ip.get('ip')} — {ip.get('country')} / {ip.get('isp')}")

    print_section("Social Media Presence")
    for s in socials:
        print(f"• {s['platform']} → {s['profile_url']}")

    print_section("Exposure Assessment")
    print(f"Risk Level : {exposure['risk_level']}")
    print(f"Score      : {exposure['score']}")

    report_path = save_json_report(full_result, target)
    html_path = generate_html_report(full_result, target)

    print(f"\n[+] JSON report saved to: {report_path}")
    print(f"[+] HTML report saved to: {html_path}")
    if html_path:
        choice = input("\nExport report to PDF? (y/n): ").lower().strip()
    if choice == "y":
        try:
            pdf_path = export_html_to_pdf(html_path)
            print(f"[+] PDF report exported: {pdf_path}")
        except Exception as e:
            print(f"[!] PDF export failed: {e}")




if __name__ == "__main__":
    main()
