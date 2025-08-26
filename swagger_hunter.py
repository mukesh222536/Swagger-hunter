#!/usr/bin/env python3
import argparse
import asyncio
import sys
import httpx
import csv
from pathlib import Path

# Common swagger/openapi endpoints
ENDPOINTS_BASIC = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/openapi.json",
    "/openapi/v1.json",
    "/openapi/v2.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html"
]

# Extra endpoints to try in deep mode
ENDPOINTS_DEEP_EXTRA = [
    "/docs",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/api/swagger.json",
    "/api/openapi.json",
    "/spec",
    "/spec.json"
]

VALID_KEYS = {"swagger", "openapi", "paths", "info"}

SEM = asyncio.Semaphore(100)  # concurrency limiter
OUTPUT_FILE = "swagger_results.csv"


def build_urls_for_domain(domain: str, deep: bool) -> list[str]:
    """Create list of candidate URLs for a domain (always try https, http, and :8080)."""
    urls = []
    endpoints = ENDPOINTS_BASIC[:]
    if deep:
        endpoints += ENDPOINTS_DEEP_EXTRA

    # Always test https, http, and http:8080
    protocols_ports = [
        ("https", None),
        ("http", None),
        ("http", 8080),
    ]

    # Add more ports if deep scan
    if deep:
        protocols_ports += [
            ("http", 80),
            ("http", 8000),
            ("http", 9000),
        ]

    for proto, port in protocols_ports:
        base = f"{proto}://{domain}"
        if port and not (proto == "http" and port == 80) and not (proto == "https" and port == 443):
            base = f"{proto}://{domain}:{port}"

        for ep in endpoints:
            urls.append(base.rstrip("/") + ep)

    # Deduplicate
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def check_endpoint(client, url):
    """Fetch endpoint and validate it's really swagger/openapi"""
    async with SEM:
        try:
            resp = await client.get(url, timeout=7)
            if resp.status_code != 200:
                return None

            # Must be JSON
            content_type = resp.headers.get("Content-Type", "").lower()
            if "json" not in content_type:
                return None

            # Must contain OpenAPI/Swagger keys
            try:
                data = resp.json()
            except Exception:
                return None

            if any(key in data for key in VALID_KEYS):
                return url
            return None
        except Exception:
            return None


async def check_domain(client, domain, idx, total, writer, lock, deep):
    """Check a single domain for swagger/openapi endpoints"""
    urls = build_urls_for_domain(domain, deep)
    tasks = [check_endpoint(client, url) for url in urls]
    found = [res for res in await asyncio.gather(*tasks) if res]

    percent = round((idx / total) * 100, 2)
    sys.stdout.write(f"\r[+] Progress: {idx}/{total} domains scanned ({percent}%)")
    sys.stdout.flush()

    if found:
        print(f"\n\033[91m[!!!] {domain}: Vulnerable endpoints found:\033[0m")
        for url in found:
            print(f"    \033[92m- {url}\033[0m")
            async with lock:
                writer.writerow([domain, url])
    return domain, found


async def run(domains, insecure=False, deep=False):
    lock = asyncio.Lock()

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Endpoint"])  # header row

        async with httpx.AsyncClient(follow_redirects=True, verify=not insecure, timeout=7) as client:
            tasks = [
                check_domain(client, domain.strip(), idx, len(domains), writer, lock, deep)
                for idx, domain in enumerate(domains, start=1)
                if domain.strip()
            ]
            results = await asyncio.gather(*tasks)

    print(f"\n\n[+] Scan complete! Results saved to {OUTPUT_FILE}\n")
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Swagger/OpenAPI endpoint hunter (fast & safe)")
    parser.add_argument("domains", nargs="*", help="List of domains to scan")
    parser.add_argument("--list", "-l", help="File with list of domains (one per line)")
    parser.add_argument("--insecure", action="store_true", help="Ignore SSL errors")
    parser.add_argument("--deep", action="store_true", help="Enable deep scan (extra ports & paths)")
    args = parser.parse_args(argv)

    # Load domains
    domains = []
    if args.list:
        file_path = Path(args.list)
        if not file_path.exists():
            print(f"[!] File not found: {args.list}")
            return 1
        domains = file_path.read_text().splitlines()
    domains.extend(args.domains)

    if not domains:
        print("[!] No domains provided. Use --list <file> or pass domains directly.")
        return 1

    return asyncio.run(run(domains, insecure=args.insecure, deep=args.deep))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
