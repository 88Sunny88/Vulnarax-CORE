import requests

OSV_API_URL = "https://api.osv.dev/v1/query"


def query_osv(package_name: str, version: str):
    """
    Query OSV API for a package+version. Returns list of vulnerabilities.
    """
    payload = {
        "package": {"name": package_name},
        "version": version
    }
    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return []

    vulns = []
    for v in data.get("vulns", []):
        fixed_version = None
        affected = v.get("affected", [])
        if affected:
            events = affected[0].get("ranges", [])
            for ev in events:
                for event in ev.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]

        vulns.append({
            "id": v.get("id"),
            "severity": v.get("severity", "UNKNOWN"),
            "summary": v.get("summary", ""),
            "fixed_version": fixed_version
        })
    return vulns