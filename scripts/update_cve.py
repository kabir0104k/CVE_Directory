import requests
import json
from datetime import datetime, timedelta

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

params = {
    "resultsPerPage": 1000,
    "pubStartDate": (datetime.utcnow() - timedelta(days=2)).strftime('%Y-%m-%dT00:00:00.000Z')
}

response = requests.get(NVD_API, params=params)
cve_items = []

if response.status_code == 200:
    for item in response.json().get("vulnerabilities", []):
        cve_id = item["cve"]["id"]
        summary = item["cve"]["descriptions"][0]["value"]
        cvss = item["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
        published = item["cve"]["published"]
        url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        cve_items.append({
            "id": cve_id,
            "summary": summary,
            "cvss": str(cvss),
            "published": published,
            "url": url
        })

    with open("data/latest.json", "w") as f:
        json.dump(cve_items, f, indent=2)
else:
    print("NVD API error:", response.status_code, response.text)
