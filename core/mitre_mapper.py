def map_to_mitre(findings):
    """
    Build MITRE ATT&CK-style exposure mapping from PhantomRecon findings
    """

    mitre = {
        "Reconnaissance": [],
        "Initial Access": [],
        "Credential Access": [],
        "Command and Control": []
    }

    # === EMAILS → Reconnaissance ===
    email_count = len(findings.get("emails", []))
    if email_count > 0:
        mitre["Reconnaissance"].append({
            "technique": "Gather Victim Identity Information",
            "technique_id": "T1589",
            "evidence": f"{email_count} public organizational emails discovered",
            "severity": "HIGH" if email_count >= 5 else "MEDIUM"
        })

    # === SOCIALS → Reconnaissance ===
    social_count = len(findings.get("socials", []))
    if social_count > 0:
        mitre["Reconnaissance"].append({
            "technique": "Gather Victim Organization Information",
            "technique_id": "T1591",
            "evidence": f"{social_count} official social media profiles discovered",
            "severity": "MEDIUM"
        })

    # === DNS / MX → Initial Access ===
    dns = findings.get("dns", {})
    if dns.get("MX"):
        mitre["Initial Access"].append({
            "technique": "Phishing",
            "technique_id": "T1566",
            "evidence": "Mail servers exposed via MX records",
            "severity": "MEDIUM"
        })

    # === JS / SECRETS → Credential Access ===
    leaks = findings.get("js_secrets", [])
    if leaks:
        mitre["Credential Access"].append({
            "technique": "Unsecured Credentials",
            "technique_id": "T1552",
            "evidence": f"{len(leaks)} potential secrets found in JavaScript",
            "severity": "HIGH"
        })

    # === CLOUD → Command & Control ===
    cloud = findings.get("cloud", {})
    if cloud.get("provider"):
        mitre["Command and Control"].append({
            "technique": "Cloud Services",
            "technique_id": "T1071.001",
            "evidence": f"Infrastructure hosted on {cloud['provider']}",
            "severity": "LOW"
        })

    # Remove empty tactics
    mitre = {k: v for k, v in mitre.items() if v}

    return mitre
