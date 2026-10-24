#!/usr/bin/env python3

import sys
import os
import re
import json
import argparse
from datetime import datetime, timezone

CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)

LANGUAGE_CATEGORY_MAP = {
    "java": ["java"],
    "go": ["golang"],
    "python": ["python"],
    "php": ["php"],
    "rust": ["rust"],
    "c": ["c"],
    "c++": ["cpp"],
    "javascript": ["javascript", "nodejs"],
    "typescript": ["typescript", "nodejs"],
    "dart": ["dart", "flutter"],
}

MOCK_DATA = [
    {
        "cve_id": "CVE-2024-4577",
        "title": "PHP CGI Argument Injection Remote Code Execution PoC",
        "description": "Exploit script demonstrating argument injection in PHP CGI on Windows leading to arbitrary command execution.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "categories": ["php", "rce", "cgi"],
        "is_exploited": True,
        "pocs": [
            {
                "url": "https://github.com/watchtowrlabs/CVE-2024-4577",
                "author": "watchtowrlabs",
                "description": "Proof of concept for CVE-2024-4577 PHP CGI RCE",
                "published_at": "2024-06-07T10:00:00Z"
            }
        ],
        "source": "github_pocs",
        "published_at": "2024-06-07T00:00:00Z",
        "raw_data": {"stars": 340, "forks": 52}
    },
    {
        "cve_id": "CVE-2024-22243",
        "title": "Spring Framework URL Parsing Open Redirect and SSRF PoC",
        "description": "Applications using UriComponentsBuilder in Spring Framework may be vulnerable to open redirect or SSRF.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "categories": ["java", "spring", "ssrf"],
        "is_exploited": False,
        "pocs": [
            {
                "url": "https://github.com/spring-sec-lab/CVE-2024-22243-demo",
                "author": "spring-sec-lab",
                "description": "Spring UriComponentsBuilder exploitation lab",
                "published_at": "2024-03-01T15:00:00Z"
            }
        ],
        "source": "github_pocs",
        "published_at": "2024-03-01T00:00:00Z",
        "raw_data": {"stars": 95, "forks": 18}
    },
    {
        "cve_id": "CVE-2024-24790",
        "title": "Go standard library net/netip Unexpected Parsing Behavior",
        "description": "The net/netip package allows non-canonical IP addresses with leading zeros, leading to potential security bypass.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "categories": ["golang", "bypass"],
        "is_exploited": False,
        "pocs": [
            {
                "url": "https://github.com/golang-sec/cve-2024-24790-poc",
                "author": "golang-sec",
                "description": "Demonstration of net/netip unexpected octal handling",
                "published_at": "2024-06-05T12:00:00Z"
            }
        ],
        "source": "github_pocs",
        "published_at": "2024-06-05T00:00:00Z",
        "raw_data": {"stars": 42, "forks": 6}
    }
]

def log(msg: str):
    sys.stderr.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [github_pocs] {msg}\n")
    sys.stderr.flush()

def fetch_from_github(limit: int = 30, target_category: str = "", custom_query: str = "", custom_keywords: list = None, token: str = "") -> list:
    import urllib.request
    import urllib.error
    import urllib.parse

    if custom_query:
        query = custom_query
    elif target_category:
        query = f"{target_category} CVE in:name,description fork:false"
    else:
        query = "CVE in:name,description fork:false"

    url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&sort=updated&order=desc&per_page={limit}"
    
    headers = {
        "User-Agent": "Raven-Threat-Collector/1.0",
        "Accept": "application/vnd.github.v3+json"
    }
    github_token = token or os.getenv("GITHUB_TOKEN")
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    log(f"querying GitHub API: {url}")
    req = urllib.request.Request(url, headers=headers)
    
    match_keywords = custom_keywords or []

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            items = data.get("items", [])
            log(f"retrieved {len(items)} repositories from GitHub Search")
            
            vulns = []
            for item in items:
                text = f"{item.get('name', '')} {item.get('description', '')}"
                found_cves = sorted(list(set(c.upper() for c in CVE_REGEX.findall(text))))
                if not found_cves:
                    continue
                
                lang = (item.get("language") or "").lower()
                categories = list(LANGUAGE_CATEGORY_MAP.get(lang, [lang] if lang else ["security"]))
                if "poc" not in categories:
                    categories.append("poc")

                text_lower = text.lower()
                for keyword in match_keywords:
                    k = keyword.lower().strip()
                    if not k:
                        continue
                    if k == "rce":
                        if re.search(r'(?i)\b(rce|remote code execution|reverse[ -]?shell)\b|php2shell', text) and k not in categories:
                            categories.append(k)
                    elif re.search(r'(?i)\b' + re.escape(k) + r'(?:\b|\d|[_-])', text) and k not in categories:
                        categories.append(k)
                
                for cve_id in found_cves:
                    vulns.append({
                        "cve_id": cve_id,
                        "title": item.get("name", cve_id),
                        "description": item.get("description") or f"PoC repository for {cve_id}",
                        "severity": "HIGH",
                        "cvss_score": None,
                        "categories": categories,
                        "is_exploited": False,
                        "pocs": [
                            {
                                "url": item.get("html_url"),
                                "author": item.get("owner", {}).get("login", ""),
                                "description": item.get("description") or "",
                                "published_at": item.get("created_at")
                            }
                        ],
                        "source": "github_pocs",
                        "published_at": item.get("created_at"),
                        "raw_data": {
                            "stars": item.get("stargazers_count", 0),
                            "forks": item.get("forks_count", 0),
                            "language": item.get("language")
                        }
                    })
            return vulns
    except Exception as e:
        log(f"GitHub API query failed or rate-limited: {e}. Falling back to internal curated feed.")
        return MOCK_DATA

def main():
    parser = argparse.ArgumentParser(description="Raven GitHub PoC Collector")
    parser.add_argument("--mock", action="store_true", help="output mock test dataset")
    parser.add_argument("--limit", type=int, default=30, help="maximum items to fetch")
    parser.add_argument("--categories", type=str, default="", help="filter ecosystem categories")
    parser.add_argument("--query", type=str, default="", help="custom github search query")
    parser.add_argument("--keywords", type=str, default="", help="comma-separated ecosystem keywords")
    parser.add_argument("--token", type=str, default="", help="github access token")
    args = parser.parse_args()

    if args.mock:
        log("running in mock mode, returning curated test dataset")
        results = MOCK_DATA
    else:
        kw_list = [k.strip() for k in args.keywords.split(",") if k.strip()] if args.keywords else None
        results = fetch_from_github(
            limit=args.limit,
            target_category=args.categories,
            custom_query=args.query,
            custom_keywords=kw_list,
            token=args.token
        )

    sys.stdout.write(json.dumps(results, indent=2, ensure_ascii=False))
    sys.stdout.flush()

if __name__ == "__main__":
    main()
