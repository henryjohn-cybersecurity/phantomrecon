import json
import datetime
import html
import os

def save_json_report(data, target):
    """Save JSON report to file"""
    filename = f"{target.replace('.', '_')}_report.json"
    os.makedirs("output", exist_ok=True)
    path = os.path.join("output", filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[+] JSON report saved to: {path}")
    return path

def generate_html_report(report, output_file=None):
    """Generate a fully formatted HTML report"""
    if not output_file:
        output_file = f"reports/{report.get('target', 'report').replace('.', '_')}_report.html"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    now = datetime.datetime.now()
    def esc(x): return html.escape(str(x)) if x is not None else "N/A"

    html_content = f"""

    
<html>
<head>
    <title>PhantomRecon Report - {esc(report.get('target'))}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0f0f0f; color: #eee; padding: 20px; }}
        h1,h2,h3 {{ color: #00ffcc; }}
        .section {{ margin-bottom: 25px; padding: 15px; background: #1a1a1a; border-radius: 8px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
        th {{ background: #222; }}
        .risk-high {{ color: #ff4c4c; }}
        .risk-medium {{ color: #ffcc00; }}
        .risk-low {{ color: #00ff88; }}
        .footer {{ font-size: 12px; color: #aaa; margin-top: 20px; }}
    </style>
</head>
<body>

<h1>🕵️ PhantomRecon Intelligence Report</h1>
<p><b>Target:</b> {esc(report.get('target'))}</p>
<p><b>Generated:</b> {now}</p>
"""

    # Exposure Summary
    exposure = report.get("exposure", {})
    html_content += f"""
<div class="section">
<h2>Exposure Summary</h2>
<p><b>Risk Level:</b> <span class="risk-high">{esc(exposure.get('risk_level'))}</span></p>
<p><b>Score:</b> {esc(exposure.get('score'))}</p>
</div>
"""

    # WHOIS
    whois = report.get("whois", {})
    html_content += f"""
<div class="section">
<h2>WHOIS Information</h2>
<p><b>Domain:</b> {esc(whois.get('domain'))}</p>
<p><b>Registrar:</b> {esc(whois.get('registrar'))}</p>
<p><b>Creation Date:</b> {esc(whois.get('creation_date'))}</p>
<p><b>Expiration Date:</b> {esc(whois.get('expiration_date'))}</p>
<ul>
"""
    for ns in whois.get("name_servers", []):
        html_content += f"<li>{esc(ns)}</li>"
    html_content += "</ul></div>"

    # DNS
    dns = report.get("dns", {})
    html_content += "<div class='section'><h2>DNS Records</h2>"
    for rtype, values in dns.items():
        html_content += f"<h3>{rtype}</h3><ul>"
        for v in values:
            html_content += f"<li>{esc(v)}</li>"
        html_content += "</ul>"
    html_content += "</div>"

    # DNS+
    dns_plus = report.get("dns_plus", [])
    if dns_plus:
        html_content += "<div class='section'><h2>DNS+ Findings</h2><ul>"
        for f in dns_plus:
            html_content += f"<li>{esc(f)}</li>"
        html_content += "</ul></div>"

    # IP Intelligence
    ip_intel = report.get("ip_intel", [])
    html_content += "<div class='section'><h2>IP Intelligence</h2><table><tr><th>IP</th><th>Location</th><th>ISP / Org</th><th>ASN</th><th>Classification</th><th>Risk</th><th>Evidence</th></tr>"
    for ip in ip_intel:
        evidence = "<br>".join(ip.get("evidence", []))
        html_content += f"<tr><td>{esc(ip.get('ip'))}</td><td>{esc(ip.get('country'))} / {esc(ip.get('city'))}</td>"
        html_content += f"<td>{esc(ip.get('isp'))} ({esc(ip.get('org'))})</td><td>{esc(ip.get('asn'))}</td>"
        html_content += f"<td>{esc(ip.get('classification'))}</td><td class='risk-high'>{esc(ip.get('risk'))}</td><td>{esc(evidence)}</td></tr>"
    html_content += "</table></div>"

    # Socials
    socials = report.get("socials", [])
    unique_socials = {(s["platform"], s["profile_url"]): s for s in socials}.values()
    html_content += "<div class='section'><h2>Social Media Presence</h2><ul>"
    for s in unique_socials:
        html_content += f"<li>{esc(s['platform'])}: <a href='{esc(s['profile_url'])}'>{esc(s['profile_url'])}</a> (Confidence: {esc(s['confidence'])})</li>"
    html_content += "</ul></div>"

    # Emails
    emails = report.get("emails", [])
    html_content += "<div class='section'><h2>Email Intelligence</h2><ul>"
    for e in emails:
        html_content += f"<li>{esc(e['email'])} — {esc(e['type'])} ({esc(e['source'])})</li>"
    html_content += "</ul></div>"

    # Exposure Findings
    findings = exposure.get("findings", [])
    html_content += "<div class='section'><h2>Exposure Findings</h2><ul>"
    for f in findings:
        html_content += f"<li>{esc(f)}</li>"
    html_content += "</ul></div>"

    # Summary
    summary = report.get("summary", {})
    html_content += f"""
<div class='section'>
<h2>Summary</h2>
<p><b>Overall Risk:</b> {esc(summary.get('overall_risk'))}</p>
<p><b>Emails Found:</b> {esc(summary.get('email_count'))}</p>
<p><b>Social Profiles:</b> {esc(summary.get('social_count'))}</p>
<p><b>IP Addresses:</b> {esc(summary.get('ip_count'))}</p>
</div>
"""
    # Footer
    html_content += "<div class='footer'>Generated by PhantomRecon • Ethical OSINT Framework</div></body></html>"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] HTML report saved to: {output_file}")

    # Also return path
    return output_file
