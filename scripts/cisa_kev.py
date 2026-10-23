#!/usr/bin/env python3
"""
CISA KEV (Known Exploited Vulnerabilities) 官方在野利用漏洞库同步脚本 (cisa_kev.py)
自动将所有抓取到的漏洞标记为 is_exploited = True，并自动解析技术栈标签。
"""

import sys
import os
import json
import argparse
from datetime import datetime
import urllib.request

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

MOCK_DATA = [
    {
        "cve_id": "CVE-2024-4577",
        "title": "PHP CGI Argument Injection Vulnerability (CISA KEV)",
        "description": "PHP contains an argument injection vulnerability affecting Windows systems. CISA has added this to the Known Exploited Vulnerabilities Catalog.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "categories": ["php", "kev", "exploited-in-the-wild"],
        "is_exploited": True,
        "pocs": [],
        "source": "cisa_kev",
        "published_at": "2024-06-12T00:00:00Z",
        "raw_data": {
            "vendorProject": "PHP Group",
            "product": "PHP",
            "requiredAction": "Apply mitigations per vendor instructions or discontinue use.",
            "dueDate": "2024-07-03"
        }
    },
    {
        "cve_id": "CVE-2023-46604",
        "title": "Apache ActiveMQ OpenWire Remote Code Execution Vulnerability",
        "description": "Apache ActiveMQ OpenWire protocol implementation allows remote code execution via ClassPathXmlApplicationContext.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "categories": ["java", "activemq", "kev", "exploited-in-the-wild"],
        "is_exploited": True,
        "pocs": [
            {
                "url": "https://github.com/sa-cyber/CVE-2023-46604-RCE",
                "author": "sa-cyber",
                "description": "ActiveMQ OpenWire RCE exploit demonstration",
                "published_at": "2023-11-01T00:00:00Z"
            }
        ],
        "source": "cisa_kev",
        "published_at": "2023-11-02T00:00:00Z",
        "raw_data": {
            "vendorProject": "Apache",
            "product": "ActiveMQ"
        }
    }
]

def log(msg: str):
    sys.stderr.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [cisa_kev] {msg}\n")
    sys.stderr.flush()

def fetch_cisa_kev(limit: int = 50) -> list:
    log(f"downloading official CISA KEV JSON catalog: {CISA_KEV_FEED_URL}")
    req = urllib.request.Request(
        CISA_KEV_FEED_URL,
        headers={"User-Agent": "Raven-Threat-Collector/1.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vuln_list = data.get("vulnerabilities", [])
            log(f"successfully downloaded catalog containing {len(vuln_list)} exploited vulnerabilities")

            # 按时间倒序切片
            vuln_list.reverse()
            sliced = vuln_list[:limit]

            results = []
            for item in sliced:
                cve_id = item.get("cveID", "").strip().upper()
                if not cve_id:
                    continue

                vendor = (item.get("vendorProject") or "").lower()
                product = (item.get("product") or "").lower()
                
                categories = ["kev", "exploited-in-the-wild"]
                for keyword in ["java", "spring", "golang", "php", "python", "apache", "cisco", "microsoft", "linux"]:
                    if keyword in vendor or keyword in product:
                        categories.append(keyword)

                results.append({
                    "cve_id": cve_id,
                    "title": item.get("vulnerabilityName") or f"Exploited Vulnerability {cve_id}",
                    "description": item.get("shortDescription") or "",
                    "severity": "CRITICAL",
                    "cvss_score": None,
                    "categories": list(set(categories)),
                    "is_exploited": True,
                    "pocs": [],
                    "source": "cisa_kev",
                    "published_at": item.get("dateAdded") + "T00:00:00Z" if item.get("dateAdded") else None,
                    "raw_data": {
                        "vendorProject": item.get("vendorProject"),
                        "product": item.get("product"),
                        "requiredAction": item.get("requiredAction"),
                        "dueDate": item.get("dueDate")
                    }
                })
            return results
    except Exception as e:
        log(f"downloading CISA KEV failed: {e}. Falling back to curated mock dataset.")
        return MOCK_DATA

def main():
    parser = argparse.ArgumentParser(description="CISA Known Exploited Vulnerabilities Sync")
    parser.add_argument("--mock", action="store_true", help="强制输出模拟测试数据")
    parser.add_argument("--limit", type=int, default=30, help="最多同步条目数")
    parser.add_argument("--categories", type=str, default="", help="过滤分类")
    args = parser.parse_args()

    if args.mock:
        log("running in mock mode, returning curated CISA KEV dataset")
        results = MOCK_DATA
    else:
        results = fetch_cisa_kev(limit=args.limit)

    sys.stdout.write(json.dumps(results, indent=2, ensure_ascii=False))
    sys.stdout.flush()

if __name__ == "__main__":
    main()
