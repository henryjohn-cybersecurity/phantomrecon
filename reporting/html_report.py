import json
import os
from datetime import datetime
from typing import Final


def generate_html_report(data: dict, target: str) -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    filename = f"{target}_report_{timestamp}.html"
    filepath: Final[str] = os.path.join(output_dir, filename)

    

    def badge(level):
        colors = {
            "LOW": "#2ecc71",
            "MEDIUM": "#f1c40f",
            "HIGH": "#e74c3c"
        }
        return f"<span class='badge' style='background:{colors.get(level,'#777')}'>{level}</span>"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhantomRecon Report – {target}</title>
<style>
body {{
    margin: 0;
    font-family: 'Segoe UI', Roboto, Arial, sans-serif;
    background: #0f172a;
    color: #e5e7eb;
}}

h1, h2, h3 {{
    color: #f8fafc;
}}

.container {{
    max-width: 1200px;
    margin: auto;
    padding: 30px;
}}

.header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #1e293b;
    padding-bottom: 15px;
}}

.risk {{
    font-size: 18px;
}}

.section {{
    margin-top: 35px;
}}

.card {{
    background: #020617;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 20px;
    margin-top: 15px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 15px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    padding: 10px;
    border-bottom: 1px solid #1e293b;
    text-align: left;
}}

th {{
    color: #93c5fd;
}}

.badge {{
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: bold;
    color: #000;
}}

ul {{
    padding-left: 20px;
}}

.footer {{
    margin-top: 60px;
    text-align: center;
    font-size: 12px;
    color: #64748b;
}}
</style>
</head>

<body>
<div class="container">

<div class="header">
  <h1>PhantomRecon Intelligence Report</h1>
  <div class="risk">Overall Risk: {badge(data['summary']['overall_risk'])}</div>
</div>
<!-- SUMMARY -->
<div class="section">
<h2>Executive Summary</h2>
<div class="grid">
<div class="card">Target<br><strong>{target}</strong></div>
<div class="card">Emails Found<br><strong>{data['summary']['email_count']}</strong></div>
<div class="card">Social Profiles<br><strong>{data['summary']['social_count']}</strong></div>
<div class="card">IP Addresses<br><strong>{data['summary']['ip_count']}</strong></div>
</div>
</div>


<div style="opacity:0.6;font-size:13px;">
Tip: Use PhantomRecon’s PDF export option to generate a shareable report.
</div>


<!-- WHOIS -->
<div class="section">
<h2>WHOIS Information</h2>
<div class="card">
<table>
<tr><th>Registrar</th><td>{data['whois'].get('registrar')}</td></tr>
<tr><th>Created</th><td>{data['whois'].get('creation_date')}</td></tr>
<tr><th>Expires</th><td>{data['whois'].get('expiration_date')}</td></tr>
<tr><th>Name Servers</th><td>{"<br>".join(data['whois'].get('name_servers', []))}</td></tr>
</table>
</div>
</div>

<!-- DNS -->
<div class="section">
<h2>DNS Records</h2>
<div class="card">
{''.join(f"<h3>{k}</h3><ul>" + ''.join(f"<li>{v}</li>" for v in vals) + "</ul>" for k, vals in data['dns'].items())}
</div>
</div>

<!-- IP INTEL -->
<div class="section">
<h2>IP Intelligence</h2>
<div class="grid">
{''.join(f"""
<div class="card">
<strong>{ip['ip']}</strong><br>
{ip['country']} – {ip['city']}<br>
ISP: {ip['isp']}<br>
ASN: {ip['asn']}<br>
Classification: <strong>{ip['classification']}</strong><br>
Risk: {badge(ip['risk'])}
<hr>
<b>Evidence</b>
<ul>{''.join(f"<li>{e}</li>" for e in ip.get('evidence', []))}</ul>
<b>HTTP Headers</b>
<ul>{''.join(f"<li>{k}: {v}</li>" for k,v in ip.get('headers', {}).items())}</ul>
</div>
""" for ip in data.get('ip_intel', []))}
</div>
</div>

<!-- SOCIAL -->
<div class="section">
<h2>Social Media Exposure</h2>
<div class="card">
<table>
<tr><th>Platform</th><th>URL</th><th>Confidence</th></tr>
{''.join(f"<tr><td>{s['platform']}</td><td><a href='{s['profile_url']}' target='_blank'>{s['profile_url']}</a></td><td>{s['confidence']}</td></tr>" for s in data['socials'])}
</table>
</div>
</div>

<!-- EMAIL -->
<div class="section">
<h2>Email Exposure</h2>
<div class="card">
<table>
<tr><th>Email</th><th>Type</th><th>Source</th><th>Confidence</th></tr>
{''.join(f"<tr><td>{e['email']}</td><td>{e['type']}</td><td>{e['source']}</td><td>{e['confidence']}</td></tr>" for e in data['emails'])}
</table>
</div>
</div>


<!-- TECH STACK -->
<div class="section">
<h2>Technology Stack</h2>
<div class="card">
<table>
<tr><th>Server</th><td>{data['tech_stack'].get('server')}</td></tr>
<tr><th>CDN / WAF</th><td>{", ".join(data['tech_stack'].get('cdn_waf', []))}</td></tr>
<tr><th>Analytics</th><td>{", ".join(data['tech_stack'].get('analytics', []))}</td></tr>
<tr><th>Confidence</th><td>{data['tech_stack'].get('confidence')}</td></tr>
</table>

<h3>Security Headers</h3>
<ul>
{''.join(f"<li>{k}: {'✔' if v else '✖'}</li>" for k,v in data['tech_stack']['security_headers'].items())}
</ul>
</div>
</div>

<!-- SUBDOMAINS -->
<div class="section">
<h2>Subdomain Enumeration</h2>
<div class="card">

<h3>Discovered Subdomains</h3>
<ul>{''.join(f"<li>{s}</li>" for s in data['subdomains']['discovered'])}</ul>

<h3>Services by Subdomain</h3>
<ul>
{''.join(f"<li><strong>{k}</strong>: {', '.join(v)}</li>" for k,v in data['subdomains']['services'].items())}
</ul>

<h3>Security Evidence</h3>
<ul>
{''.join(f"<li>{e}</li>" for e in data['subdomains'].get('evidence', []))}
</ul>

<h3>Security Evidence</h3>
<ul>
{''.join(f"<li>{e}</li>" for e in data['subdomains'].get('evidence', []))}
</ul>

Risk: {badge(data['subdomains']['risk'])}
</div>
</div>


<!-- CLOUD -->
<div class="section">
<h2>Cloud Intelligence</h2>
<div class="card">
Providers: {", ".join(data['cloud']['provider']) or "Unknown"}<br>
Services: {", ".join(data['cloud']['services']) or "Unknown"}<br>
S3 Detected: {data['cloud']['storage_exposure']['s3_detected']}<br>

<h3>Evidence</h3>
<ul>{''.join(f"<li>{e}</li>" for e in data['cloud'].get('evidence', []))}</ul>

Risk: {badge(data['cloud']['risk'])}
</div>
</div>


<!-- TECH FINGERPRINT -->
<div class="section">
<h2>Technology Fingerprinting</h2>
<div class="card">
Server: {data['technology_fingerprint']['server']}<br>

<h3>Security Headers</h3>
<ul>
{''.join(f"<li>{k}: {v}</li>" for k,v in data['technology_fingerprint']['security_headers'].items())}
</ul>

<h3>Admin Panels Discovered</h3>
<ul>
{''.join(f"<li>{p}</li>" for p in data['technology_fingerprint'].get('admin_panels', []))}
</ul>
Risk: {badge(data['technology_fingerprint']['risk'])}
</div>
</div>



<!-- PUBLIC EXPOSURE -->
<div class="section">
<h2>Public Exposure</h2>
<div class="card">
<ul>
{''.join(f"<li>{e}</li>" for e in data['public_exposure']['evidence'])}
</ul>
Risk: {badge(data['public_exposure']['risk'])}
</div>
</div>

<!-- JS LEAKS -->
<div class="section">
<h2>JavaScript Secrets & Leaks</h2>
<div class="grid">
{''.join(f"""
<div class="card">
<strong>{l['type']}</strong><br>
Source: <a href="{l['source']}" target="_blank">JS File</a><br>
Matches: {', '.join(l['matches'])}<br>
Risk: {badge(l['risk'])}
</div>
""" for l in data['leaks'])}
</div>
</div>

<!-- MITRE -->
<div class="section">
<h2>MITRE ATT&CK Mapping</h2>
{''.join(f"""
<div class="card">
<h3>{stage}</h3>
<ul>
{''.join(f"<li><strong>{t['technique']}</strong> ({t['technique_id']}) — {badge(t['severity'])}<br>{t['evidence']}</li>" for t in techniques)}
</ul>
</div>
""" for stage, techniques in data['mitre_attack_surface'].items())}
</div>

<div class="footer">
Generated by PhantomRecon • {datetime.utcnow().isoformat()} UTC
</div>

</div>
</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath
    
