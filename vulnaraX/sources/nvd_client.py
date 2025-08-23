# NVD API / local mirror
import requests
import os

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # optional, rate-limit is higher with key

def query_nvd(package_name: str, version: str):
    """
    Query NVD for vulnerabilities matching a package and version.
    Returns a list of normalized vulnerability dicts.
    """
    params = {
        "keywordSearch": f"{package_name} {version}",
        "resultsPerPage": 10
    }
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] NVD query failed for {package_name} {version}: {e}")
        return []

    vulns = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")
        descs = cve_data.get("descriptions", [])
        description = descs[0]["value"] if descs else ""

        severity = "UNKNOWN"
        fixed_version = None
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")

        # Normalize
        vulns.append({
            "id": cve_id,
            "package": package_name,
            "version": version,
            "severity": severity,
            "description": description,
            "fixed_version": fixed_version,  # unknown, unless parsing vendor advisories
            "instructions": f"apt-get install --only-upgrade {package_name}"
        })

    return vulns