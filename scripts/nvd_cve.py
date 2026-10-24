#!/usr/bin/env python3

import sys
import os
import json
import argparse
from datetime import datetime, timedelta, timezone
import urllib.request
import urllib.parse

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MOCK_DATA = [
    {
        "cve_id": "CVE-2024-4577",
        "title": "PHP Windows CGI Argument Injection Vulnerability",
        "description": "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may bypass character escape sequences.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "categories": ["php", "nvd", "cgi", "rce"],
        "is_exploited": False,
        "pocs": [],
        "source": "nvd",
        "published_at": "2024-06-09T19:15:00Z",
        "raw_data": {
            "cweId": "CWE-78",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
    },
    {
        "cve_id": "CVE-2024-38077",
        "title": "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability (MadLicense)",
        "description": "Windows Remote Desktop Licensing Service contains an unspecified vulnerability leading to unauthenticated remote code execution.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "categories": ["windows", "nvd", "rce"],
        "is_exploited": True,
        "pocs": [],
        "source": "nvd",
        "published_at": "2024-07-09T17:15:00Z",
        "raw_data": {
            "cweId": "CWE-94",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
    }
]

def log(msg: str):
    sys.stderr.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [nvd_cve] {msg}\n")
    sys.stderr.flush()

def fetch_nvd_cves(limit: int = 20) -> list:
    log("querying NVD REST API 2.0 for recent critical vulnerabilities")
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=120)
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(limit, 50),
        "cvssV3Severity": "CRITICAL"
    }
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
    
    headers = {
        "User-Agent": "Raven-Threat-Collector/1.0",
        "Accept": "application/json"
    }
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vuln_items = data.get("vulnerabilities", [])
            log(f"retrieved {len(vuln_items)} CVE records from NVD")

            results = []
            for item in vuln_items:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id", "").strip().upper()
                if not cve_id:
                    continue

                descriptions = cve_obj.get("descriptions", [])
                desc_text = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_text = d.get("value", "")
                        break

                metrics = cve_obj.get("metrics", {})
                severity = "UNKNOWN"
                cvss_score = None
                
                v31_list = metrics.get("cvssMetricV31", [])
                if v31_list:
                    primary_v31 = v31_list[0].get("cvssData", {})
                    severity = primary_v31.get("baseSeverity", "UNKNOWN")
                    cvss_score = primary_v31.get("baseScore")

                categories = ["nvd"]
                lower_desc = desc_text.lower()
                for lang_kw in ["java", "spring", "golang", "php", "python", "c", "cpp", "windows", "linux"]:
                    if lang_kw in lower_desc:
                        categories.append(lang_kw)

                results.append({
                    "cve_id": cve_id,
                    "title": desc_text[:120] + "..." if len(desc_text) > 120 else desc_text or f"Vulnerability {cve_id}",
                    "description": desc_text,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "categories": list(set(categories)),
                    "is_exploited": False,
                    "pocs": [],
                    "source": "nvd",
                    "published_at": cve_obj.get("published"),
                    "raw_data": {
                        "sourceIdentifier": cve_obj.get("sourceIdentifier"),
                        "vulnStatus": cve_obj.get("vulnStatus")
                    }
                })
            return results
    except Exception as e:
        log(f"NVD API request failed: {e}. Falling back to curated mock dataset.")
        return MOCK_DATA

def main():
    parser = argparse.ArgumentParser(description="NVD Metadata Sync")
    parser.add_argument("--mock", action="store_true", help="output mock test dataset")
    parser.add_argument("--limit", type=int, default=15, help="maximum items to fetch")
    parser.add_argument("--categories", type=str, default="", help="filter categories")
    args = parser.parse_args()

    if args.mock:
        log("running in mock mode, returning curated NVD dataset")
        results = MOCK_DATA
    else:
        results = fetch_nvd_cves(limit=args.limit)

    sys.stdout.write(json.dumps(results, indent=2, ensure_ascii=False))
    sys.stdout.flush()

if __name__ == "__main__":
    main()
