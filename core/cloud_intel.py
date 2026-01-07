import re

AWS_KEYWORDS = ["amazon", "aws", "cloudfront", "global accelerator"]
AZURE_KEYWORDS = ["microsoft", "azure"]
GCP_KEYWORDS = ["google", "gcp"]

AWS_REGIONS = [
    "us-east-1", "us-west-1", "us-west-2",
    "eu-west-1", "eu-central-1"
]


def detect_cloud(ip_data, dns_data):
    providers = set()
    services = set()
    regions = set()
    evidence = []

    # --- IP-based detection ---
    for ip in ip_data:
        org = (ip.get("org") or "").lower()
        asn = (ip.get("asn") or "").lower()

        if any(k in org or k in asn for k in AWS_KEYWORDS):
            providers.add("AWS")
            evidence.append(f"ASN {ip.get('asn')} (Amazon)")

        if any(k in org for k in AZURE_KEYWORDS):
            providers.add("Azure")
            evidence.append("Azure IP ownership detected")

        if any(k in org for k in GCP_KEYWORDS):
            providers.add("GCP")
            evidence.append("Google Cloud IP ownership detected")

        if "global accelerator" in org:
            services.add("Global Accelerator")

    # --- DNS-based service hints ---
    for cname in dns_data.get("CNAME", []):
        cname_l = cname.lower()
        if "cloudfront" in cname_l:
            services.add("CloudFront")
            providers.add("AWS")
            evidence.append("CloudFront CNAME detected")

    # --- Region inference (weak but useful) ---
    for txt in dns_data.get("TXT", []):
        for r in AWS_REGIONS:
            if r in txt:
                regions.add(r)

    # --- Storage exposure hint ---
    s3_detected = False
    for txt in dns_data.get("TXT", []):
        if "s3" in txt.lower():
            s3_detected = True
            evidence.append("S3 reference found in DNS TXT")

    risk = "LOW"
    if "AWS" in providers and len(services) >= 2:
        risk = "MEDIUM"
    if s3_detected:
        risk = "HIGH"

    return {
        "provider": list(providers),
        "services": list(services),
        "regions": list(regions),
        "storage_exposure": {
            "s3_detected": s3_detected,
            "public_bucket_hint": False
        },
        "risk": risk,
        "evidence": list(set(evidence))
    }
