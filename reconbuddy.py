#!/usr/bin/env python3
"""
ReconBuddy — your friendly, zero-dependency recon companion for ethical bug hunting.

Performs passive subdomain enumeration, HTTP probing, security-header analysis,
and well-known file discovery, then writes a Markdown + HTML report.

    python3 reconbuddy.py example.com --i-have-permission
    python3 reconbuddy.py example.com --i-have-permission --deep

ONLY use this on domains you own or have explicit written permission to test.
"""

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html import escape

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

USER_AGENT = "ReconBuddy/1.0 (ethical bug-hunting; +https://github.com/yourname/reconbuddy)"
REQUEST_TIMEOUT = 10  # seconds
RATE_LIMIT = 0.4  # polite delay between requests
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

COMMON_PORTS = [80, 443, 8080, 8443]  # only used for light probing, not full scans

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "advice": "Add HSTS to enforce HTTPS and prevent downgrade attacks.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "advice": "Add a CSP to mitigate XSS and data-injection attacks.",
    },
    "X-Frame-Options": {
        "severity": "low",
        "advice": "Add X-Frame-Options (DENY/SAMEORIGIN) or CSP frame-ancestors to stop clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "advice": "Set X-Content-Type-Options: nosniff to stop MIME sniffing.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "advice": "Set a Referrer-Policy (e.g. strict-origin-when-cross-origin).",
    },
    "Permissions-Policy": {
        "severity": "low",
        "advice": "Restrict browser features with Permissions-Policy.",
    },
}

WELL_KNOWN_PATHS = {
    "/robots.txt": "Robots.txt may reveal hidden paths or disallowed areas.",
    "/sitemap.xml": "Sitemap can expose URLs and structure.",
    "/.well-known/security.txt": "A security.txt helps researchers report issues responsibly.",
}

DEEP_PATHS = {
    "/.git/HEAD": {
        "severity": "high",
        "advice": "Exposed .git directory can leak source code and secrets. Block it immediately.",
    },
    "/.env": {
        "severity": "high",
        "advice": "Exposed .env file may contain API keys and credentials. Remove it from the web root.",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner():
    print(r"""
    ____                       ____            _     _
   |  _ \ ___  ___ ___  _ __  | __ ) _   _  __| | __| |_   _
   | |_) / _ \/ __/ _ \| '_ \ |  _ \| | | |/ _` |/ _` | | | |
   |  _ <  __/ (_| (_) | | | || |_) | |_| | (_| | (_| | |_| |
   |_| \_\___|\___\___/|_| |_||____/ \__,_|\__,_|\__,_|\__, |
                                                        |___/
    Zero-dependency recon for ethical bug hunters.
    """)


def legal_gate(domain):
    """Require explicit authorization before any network activity."""
    print("\n⚠️  LEGAL & ETHICAL NOTICE")
    print("ReconBuddy must only be used on domains you own or have")
    print("explicit written permission to test (e.g. a bug bounty program scope).")
    print(f"\nTarget: {domain}")
    try:
        answer = input("Type 'I HAVE PERMISSION' to continue: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        sys.exit(1)
    if answer != "I HAVE PERMISSION":
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)


def validate_domain(value):
    """Basic domain/IP sanity check."""
    value = value.strip().lower()
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urllib.parse.urlparse(value)
        value = parsed.hostname or ""
    if not value or len(value) > 253:
        raise ValueError("Invalid domain.")
    if re.search(r"\s", value):
        raise ValueError("Domain must not contain spaces.")
    return value


def fetch(url, timeout=REQUEST_TIMEOUT):
    """Fetch a URL and return (status, headers dict, body text) or None."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            headers = {k: v for k, v in resp.headers.items()}
            return resp.status, headers, body
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ssl.SSLError, OSError):
        return None


# ---------------------------------------------------------------------------
# Recon steps
# ---------------------------------------------------------------------------

def enumerate_subdomains(domain):
    """Passive subdomain discovery via crt.sh certificate transparency logs."""
    print(f"\n[1/4] Passive subdomain enumeration for {domain} …")
    url = CRT_SH_URL.format(domain=urllib.parse.quote(domain))
    data = fetch(url)
    if not data:
        print("      Could not reach crt.sh. Continuing without subdomains.")
        return []

    _, _, body = data
    try:
        entries = json.loads(body)
    except json.JSONDecodeError:
        print("      crt.sh returned non-JSON. Skipping subdomain step.")
        return []

    subs = set()
    for entry in entries:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line.endswith(domain) and line != domain:
                subs.add(line)
    subs = sorted(subs)
    print(f"      Found {len(subs)} unique subdomains.")
    return subs


def probe_http(domain):
    """Probe HTTP/HTTPS and return a dict of findings."""
    print(f"\n[2/4] Probing HTTP/HTTPS for {domain} …")
    result = {
        "url": None,
        "status": None,
        "headers": {},
        "server": None,
        "title": None,
        "error": None,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        time.sleep(RATE_LIMIT)
        data = fetch(url)
        if data:
            status, headers, body = data
            result.update({
                "url": url,
                "status": status,
                "headers": headers,
                "server": headers.get("Server"),
            })
            match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if match:
                result["title"] = match.group(1).strip()[:120]
            print(f"      Live: {url} → {status}")
            return result

    result["error"] = "No HTTP/HTTPS response."
    print("      No HTTP/HTTPS response.")
    return result


def analyze_headers(headers):
    """Check security headers and return findings."""
    print("\n[3/4] Auditing security headers …")
    findings = []
    for name, meta in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append({
                "type": "missing_header",
                "name": name,
                "severity": meta["severity"],
                "advice": meta["advice"],
            })
    if findings:
        print(f"      {len(findings)} header(s) missing.")
    else:
        print("      All recommended security headers present.")
    return findings


def discover_well_known(base_url):
    """Look for robots.txt, sitemap.xml, security.txt."""
    print("\n[4/4] Discovering well-known files …")
    found = []
    for path, note in WELL_KNOWN_PATHS.items():
        url = urllib.parse.urljoin(base_url, path)
        time.sleep(RATE_LIMIT)
        data = fetch(url)
        if data and data[0] == 200:
            found.append({"path": path, "url": url, "note": note})
            print(f"      Found {path}")
    return found


def discover_deep(base_url):
    """Opt-in checks for commonly exposed sensitive files."""
    print("\n[deep] Checking for commonly exposed sensitive files …")
    found = []
    for path, meta in DEEP_PATHS.items():
        url = urllib.parse.urljoin(base_url, path)
        time.sleep(RATE_LIMIT)
        data = fetch(url)
        if data and data[0] == 200:
            found.append({
                "path": path,
                "url": url,
                "severity": meta["severity"],
                "advice": meta["advice"],
            })
            print(f"      ⚠️  POTENTIALLY EXPOSED: {path}")
    return found


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_report(domain, subs, http_info, header_findings, well_known, deep_findings):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    lines.append(f"# ReconBuddy report — `{domain}`")
    lines.append("")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Target:** `{domain}`")
    lines.append("")
    lines.append("> **Authorization reminder:** Only test assets you own or have explicit permission to assess.")
    lines.append("")
    lines.append("---")
    lines.append("")

    total_issues = len(header_findings) + len(deep_findings)
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"- Subdomains discovered: **{len(subs)}**")
    lines.append(f"- HTTP endpoint: **{http_info.get('url') or 'none'}**")
    lines.append(f"- Security-header issues: **{len(header_findings)}**")
    lines.append(f"- Sensitive-file findings: **{len(deep_findings)}**")
    lines.append(f"- Total actionable findings: **{total_issues}**")
    lines.append("")

    lines.append("## Subdomains")
    lines.append("")
    if subs:
        for s in subs:
            lines.append(f"- `{s}`")
    else:
        lines.append("_No subdomains discovered passively._")
    lines.append("")

    lines.append("## HTTP probe")
    lines.append("")
    if http_info.get("url"):
        lines.append(f"- URL: {http_info['url']}")
        lines.append(f"- Status: {http_info['status']}")
        lines.append(f"- Server: {http_info.get('server') or 'unknown'}")
        lines.append(f"- Title: {http_info.get('title') or '—'}")
    else:
        lines.append("_No HTTP/HTTPS response._")
    lines.append("")

    lines.append("## Security headers")
    lines.append("")
    if header_findings:
        for f in header_findings:
            lines.append(f"### Missing: `{f['name']}`")
            lines.append(f"- **Severity:** {f['severity']}")
            lines.append(f"- **Advice:** {f['advice']}")
            lines.append("")
    else:
        lines.append("_All recommended security headers are present._")
        lines.append("")

    lines.append("## Well-known files")
    lines.append("")
    if well_known:
        for item in well_known:
            lines.append(f"- `{item['path']}` — {item['note']}")
    else:
        lines.append("_No well-known files found._")
    lines.append("")

    if deep_findings:
        lines.append("## ⚠️ Sensitive-file findings (deep mode)")
        lines.append("")
        for item in deep_findings:
            lines.append(f"### `{item['path']}`")
            lines.append(f"- **Severity:** {item['severity']}")
            lines.append(f"- **URL:** {item['url']}")
            lines.append(f"- **Advice:** {item['advice']}")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Generated by ReconBuddy. Use responsibly._")
    return "\n".join(lines)


def write_html(markdown, path):
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ReconBuddy report</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; line-height: 1.6; }}
  code {{ background: #f2f2f2; padding: 0.1em 0.3em; border-radius: 4px; }}
  pre {{ background: #f7f7f7; padding: 1rem; overflow-x: auto; }}
  h1, h2, h3 {{ color: #1a1a1a; }}
</style>
</head>
<body>
<pre>{escape(markdown)}</pre>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="ReconBuddy — zero-dependency recon for ethical bug hunters.")
    parser.add_argument("domain", help="Domain to assess (e.g. example.com)")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="Confirm you are authorized to test this domain.")
    parser.add_argument("--deep", action="store_true",
                        help="Enable opt-in checks for commonly exposed sensitive files.")
    parser.add_argument("-o", "--output-dir", default="reconbuddy-reports",
                        help="Directory for reports (default: reconbuddy-reports).")
    args = parser.parse_args()

    try:
        domain = validate_domain(args.domain)
    except ValueError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    if not args.i_have_permission:
        legal_gate(domain)
    else:
        print("\n[✓] Authorization confirmed via --i-have-permission flag.")

    os.makedirs(args.output_dir, exist_ok=True)
    safe_name = domain.replace(".", "_").replace("/", "_")

    subs = enumerate_subdomains(domain)
    http_info = probe_http(domain)

    if not http_info.get("url"):
        print("\n[!] Cannot continue HTTP-based checks without a live endpoint.")
        sys.exit(0)

    header_findings = analyze_headers(http_info["headers"])
    well_known = discover_well_known(http_info["url"])

    deep_findings = []
    if args.deep:
        deep_findings = discover_deep(http_info["url"])

    report_md = build_report(domain, subs, http_info, header_findings, well_known, deep_findings)

    md_path = os.path.join(args.output_dir, f"{safe_name}-report.md")
    html_path = os.path.join(args.output_dir, f"{safe_name}-report.html")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(report_md)
    write_html(report_md, html_path)

    print("\n" + "=" * 60)
    print("ReconBuddy finished.")
    print(f"  Markdown report: {md_path}")
    print(f"  HTML report:     {html_path}")
    print("=" * 60)
    print("\nRemember: only test assets you are authorized to test.")


if __name__ == "__main__":
    main()
