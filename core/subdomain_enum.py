import socket

COMMON_SUBDOMAINS = [
    "www", "api", "admin", "portal", "dashboard",
    "dev", "staging", "test", "beta",
    "mail", "webmail", "smtp", "vpn",
    "cdn", "assets", "static"
]


def resolve_subdomain(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return True
    except Exception:
        return False


def enumerate_subdomains(domain):
    discovered = []
    evidence = []
    services = {}

    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        if resolve_subdomain(fqdn):
            discovered.append(fqdn)

            if sub in ["mail", "smtp", "webmail"]:
                services[fqdn] = ["SMTP"]
            elif sub in ["api", "admin", "portal", "dashboard"]:
                services[fqdn] = ["HTTPS"]
                evidence.append(f"Sensitive subdomain discovered: {fqdn}")
            else:
                services[fqdn] = ["HTTP/HTTPS"]

    risk = "LOW"
    if any("admin" in d or "dev" in d for d in discovered):
        risk = "HIGH"
    elif discovered:
        risk = "MEDIUM"

    return {
        "discovered": discovered,
        "services": services,
        "risk": risk,
        "evidence": evidence
    }
