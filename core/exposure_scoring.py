def calculate_exposure_score(
    emails=None,
    socials=None,
    ip_data=None,
    dns_data=None,
    security_txt_found=False
):
    """
    Calculate exposure score based on OSINT findings.
    This module DOES NOT collect data.
    It only scores what other modules already discovered.
    """

    score = 0
    findings = []

    emails = emails or []
    socials = socials or []
    ip_data = ip_data or []
    dns_data = dns_data or {}

    # --- EMAIL EXPOSURE ---
    for e in emails:
        if e.get("type") == "organizational":
            score += 15
            findings.append(f"Public email exposed: {e.get('email')}")

        if e.get("type") == "security":
            score += 10
            findings.append(f"Security email exposed: {e.get('email')}")

    # --- SOCIAL MEDIA EXPOSURE ---
    if socials:
        for s in socials:
            score += 5
            findings.append(f"Social profile discovered: {s}")

    # --- IP EXPOSURE ---
    if len(ip_data) > 1:
        score += 10
        findings.append("Multiple IP addresses detected")

    for ip in ip_data:
        if ip.get("country") and ip.get("org"):
            score += 5

    # --- DNS EXPOSURE ---
    if dns_data.get("mx"):
        score += 10
        findings.append("Mail servers publicly exposed (MX records)")

    if dns_data.get("txt"):
        score += 5

    # --- SECURITY.TXT ---
    if not security_txt_found:
        score += 15
        findings.append("Missing security.txt")

    # --- FINAL RISK LEVEL ---
    if score <= 20:
        level = "LOW"
    elif score <= 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": score,
        "risk_level": level,
        "findings": findings
    }
