#!/usr/bin/env python3
"""VZ-Tool Devil: offline defensive triage for URLs and saved email headers."""
import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path
from urllib.parse import urlsplit

SUSPICIOUS_TERMS = {"verify", "account", "secure", "login", "signin", "password", "confirm", "wallet", "urgent", "update"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "buff.ly"}

def finding(code, severity, detail, weight):
    return {"id": code, "severity": severity, "detail": detail, "weight": weight}

def report(kind, value, findings):
    score = min(100, sum(item["weight"] for item in findings))
    return {
        "tool": "VZ-Tool Devil", "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_type": kind, "input": value, "risk_score": score,
        "risk_level": "high" if score >= 50 else "medium" if score >= 25 else "low",
        "finding_count": len(findings), "findings": findings,
        "note": "Heuristic triage only. No target was contacted and no reputation lookup was performed."
    }

def scan_url(value):
    raw = value.strip()
    findings = []
    if not raw:
        return report("url", raw, [finding("empty_input", "high", "No URL supplied.", 100)])
    try:
        parts = urlsplit(raw if "://" in raw else "https://" + raw)
        host, port = parts.hostname, parts.port
    except ValueError:
        return report("url", raw, [finding("malformed_url", "high", "Malformed URL authority or port.", 40)])
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        findings.append(finding("unexpected_scheme", "high", "URL scheme is not HTTP or HTTPS.", 25))
    if not host:
        findings.append(finding("missing_host", "high", "No hostname could be parsed.", 40))
        return report("url", raw, findings)
    host = host.lower().rstrip(".")
    if scheme == "http":
        findings.append(finding("http_without_tls", "medium", "HTTP does not protect the connection with TLS.", 10))
    if parts.username is not None or parts.password is not None:
        findings.append(finding("userinfo_present", "high", "Text before @ can disguise the actual destination.", 30))
    if re.fullmatch(r"[0-9.]+", host):
        findings.append(finding("ip_literal_host", "medium", "URL uses an IP literal instead of a domain name.", 20))
    if "xn--" in host:
        findings.append(finding("punycode_host", "medium", "Hostname contains IDN punycode; inspect for lookalikes.", 20))
    if len(host.split(".")) >= 5:
        findings.append(finding("many_subdomains", "low", "Many hostname labels can obscure the registered domain.", 10))
    if host in SHORTENERS:
        findings.append(finding("url_shortener", "medium", "Shortener obscures the final destination.", 15))
    combined = (host + " " + parts.path + " " + parts.query).lower().replace("-", " ")
    matched = sorted(term for term in SUSPICIOUS_TERMS if term in combined)
    if matched:
        findings.append(finding("suspicious_terms", "low", "Account-related terms found: " + ", ".join(matched), 10))
    if port is not None and port not in {80, 443}:
        findings.append(finding("unusual_port", "low", f"Non-standard web port {port}.", 10))
    return report("url", raw, findings)

def domain_of(value):
    value = (value or "").strip()
    if "<" in value and ">" in value:
        value = value.rsplit("<", 1)[1].split(">", 1)[0]
    return value.rsplit("@", 1)[1].strip().strip(">").lower().rstrip(".") if "@" in value else ""

def scan_headers(raw):
    message = Parser().parsestr(raw, headersonly=True)
    findings = []
    from_domain = domain_of(message.get("From", ""))
    reply_domain = domain_of(message.get("Reply-To", ""))
    return_domain = domain_of(message.get("Return-Path", ""))
    if not message.get("From"):
        findings.append(finding("missing_from", "medium", "No From header found.", 15))
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(finding("reply_to_mismatch", "high", f"Reply-To domain {reply_domain} differs from From domain {from_domain}.", 25))
    if return_domain and from_domain and return_domain != from_domain:
        findings.append(finding("return_path_mismatch", "low", "Return-Path differs from From; this can be legitimate.", 8))
    auth = " ".join(message.get_all("Authentication-Results", [])).lower()
    if not auth:
        findings.append(finding("missing_auth_results", "low", "No Authentication-Results header supplied.", 5))
    else:
        for method in ("spf", "dkim", "dmarc"):
            if method + "=fail" in auth or method + "=softfail" in auth:
                findings.append(finding(method + "_failure", "high", f"Supplied headers report {method.upper()} failure.", 20))
    if not message.get("Date"):
        findings.append(finding("missing_date", "low", "No Date header found.", 3))
    return report("email_headers", raw[:1200], findings)

def save_report(items, path, fmt):
    destination = Path(path)
    if fmt == "json":
        payload = items[0] if len(items) == 1 else {"count": len(items), "reports": items}
        destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        fields = ["input_type", "input", "risk_score", "risk_level", "finding_count", "finding_ids", "generated_at"]
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for item in items:
                row = {key: item.get(key, "") for key in fields}
                row["finding_ids"] = ";".join(f["id"] for f in item["findings"])
                writer.writerow(row)

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline URL and email-header triage; never contacts targets.")
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("url", help="analyze a URL string offline")
    one.add_argument("value")
    one.add_argument("--json", dest="json_path")
    batch = sub.add_parser("file", help="analyze URL strings, one per line")
    batch.add_argument("path")
    batch.add_argument("--json", dest="json_path")
    batch.add_argument("--csv", dest="csv_path")
    mail = sub.add_parser("headers", help="analyze saved email headers offline")
    mail.add_argument("path")
    mail.add_argument("--json", dest="json_path")
    mail.add_argument("--csv", dest="csv_path")
    args = parser.parse_args(argv)
    try:
        if args.command == "url":
            items = [scan_url(args.value)]
        elif args.command == "file":
            values = [line.strip() for line in Path(args.path).read_text(encoding="utf-8").splitlines()
                      if line.strip() and not line.lstrip().startswith("#")]
            items = [scan_url(value) for value in values]
        else:
            items = [scan_headers(Path(args.path).read_text(encoding="utf-8"))]
        if args.json_path:
            save_report(items, args.json_path, "json")
            print(f"[VZ-TOOL] Wrote JSON report: {args.json_path}")
        elif args.command != "url" and args.csv_path:
            save_report(items, args.csv_path, "csv")
            print(f"[VZ-TOOL] Wrote CSV report: {args.csv_path}")
        else:
            print(json.dumps(items[0] if len(items) == 1 else {"count": len(items), "reports": items}, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
