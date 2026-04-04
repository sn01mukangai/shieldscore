#!/usr/bin/env python3
"""
ShieldScore — Free Security Scoring API
MVP: scans any domain and returns a 0-100 security score.
"""

import subprocess
import json
import re
import ssl
import socket
import hashlib
import time
import os
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='static', static_url_path='/static')

# ─── API Security Controls ───

def _get_int_env(name, default):
    try:
        return max(1, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def _get_bool_env(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_api_keys():
    raw_keys = os.getenv("API_KEYS", "") or os.getenv("API_KEY", "")
    return {k.strip() for k in raw_keys.split(",") if k.strip()}


AUTH_REQUIRED = _get_bool_env("API_AUTH_REQUIRED", True)
API_KEYS = _load_api_keys()
IP_RATE_LIMIT = _get_int_env("SCAN_RATE_LIMIT_IP", 10)
DOMAIN_RATE_LIMIT = _get_int_env("SCAN_RATE_LIMIT_DOMAIN", 5)
RATE_WINDOW_SECONDS = _get_int_env("SCAN_RATE_WINDOW_SECONDS", 60)
SCAN_TIMEOUT_SECONDS = _get_int_env("SCAN_TIMEOUT_SECONDS", 90)
MAX_CONCURRENT_SCANS = _get_int_env("MAX_CONCURRENT_SCANS", 4)

_rate_lock = threading.Lock()
_ip_hits = defaultdict(deque)
_domain_hits = defaultdict(deque)
_scan_slots = threading.BoundedSemaphore(value=MAX_CONCURRENT_SCANS)
_scan_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)


def _extract_api_token():
    key = request.headers.get("X-API-Key", "").strip()
    if key:
        return key
    auth = request.headers.get("Authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _authorization_error():
    return jsonify({
        "error": "authentication_required",
        "message": "Provide a valid X-API-Key header or Bearer token.",
    }), 401


def _check_rate_limit(bucket, key, limit):
    now = time.time()
    with _rate_lock:
        entries = bucket[key]
        while entries and now - entries[0] >= RATE_WINDOW_SECONDS:
            entries.popleft()
        if len(entries) >= limit:
            retry_after = max(1, int(RATE_WINDOW_SECONDS - (now - entries[0])))
            return retry_after
        entries.append(now)
    return None

# ─── Scanner Engine ───

def check_ssl(domain, port=443):
    """Check SSL/TLS configuration."""
    result = {"score": 0, "max": 25, "details": []}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()
            protocol = s.version()

            # Certificate validity
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.utcnow()).days

            if days_left > 90:
                result["score"] += 10
                result["details"].append({"status": "pass", "text": f"Certificate valid ({days_left} days remaining)"})
            elif days_left > 30:
                result["score"] += 5
                result["details"].append({"status": "warn", "text": f"Certificate expiring soon ({days_left} days)"})
            else:
                result["details"].append({"status": "fail", "text": f"Certificate expiring in {days_left} days"})

            # Protocol version
            if protocol in ('TLSv1.3',):
                result["score"] += 10
                result["details"].append({"status": "pass", "text": f"Protocol: {protocol} (excellent)"})
            elif protocol in ('TLSv1.2',):
                result["score"] += 7
                result["details"].append({"status": "warn", "text": f"Protocol: {protocol} (consider upgrading to TLS 1.3)"})
            else:
                result["details"].append({"status": "fail", "text": f"Protocol: {protocol} (insecure)"})

            # Cipher strength
            cipher = s.cipher()
            if cipher and cipher[2] >= 256:
                result["score"] += 5
                result["details"].append({"status": "pass", "text": f"Strong cipher: {cipher[0]} ({cipher[2]}-bit)"})
            elif cipher and cipher[2] >= 128:
                result["score"] += 3
                result["details"].append({"status": "warn", "text": f"Cipher: {cipher[0]} ({cipher[2]}-bit)"})
            else:
                result["details"].append({"status": "fail", "text": f"Weak cipher: {cipher[0] if cipher else 'unknown'}"})

    except ssl.SSLCertVerificationError as e:
        result["details"].append({"status": "fail", "text": f"Certificate error: {e.verify_message}"})
    except Exception as e:
        result["details"].append({"status": "fail", "text": f"SSL check failed: {str(e)}"})

    return result


def check_headers(domain):
    """Check HTTP security headers."""
    result = {"score": 0, "max": 30, "details": []}

    required_headers = {
        "strict-transport-security": {"points": 6, "name": "HSTS"},
        "content-security-policy": {"points": 6, "name": "CSP"},
        "x-frame-options": {"points": 4, "name": "X-Frame-Options"},
        "x-content-type-options": {"points": 3, "name": "X-Content-Type-Options"},
        "referrer-policy": {"points": 3, "name": "Referrer-Policy"},
        "permissions-policy": {"points": 3, "name": "Permissions-Policy"},
        "x-xss-protection": {"points": 2, "name": "X-XSS-Protection"},
    }

    try:
        proc = subprocess.run(
            ["curl", "-sI", "--connect-timeout", "10", "-L", f"https://www.{domain}"],
            capture_output=True, text=True, timeout=15
        )
        headers_text = proc.stdout.lower()

        for header, info in required_headers.items():
            if header in headers_text:
                result["score"] += info["points"]
                result["details"].append({"status": "pass", "text": f"{info['name']} present"})
            else:
                result["details"].append({"status": "fail", "text": f"{info['name']} missing"})

        # Check for info leakage
        if "server:" in headers_text:
            server = [l for l in proc.stdout.split('\n') if l.lower().startswith('server:')][0] if any(l.lower().startswith('server:') for l in proc.stdout.split('\n')) else ""
            if any(v in server.lower() for v in ['apache', 'nginx', 'iis']):
                result["details"].append({"status": "warn", "text": f"Server version exposed: {server.strip()}"})

    except Exception as e:
        result["details"].append({"status": "fail", "text": f"Headers check failed: {str(e)}"})

    return result


def check_dns(domain):
    """Check DNS records (SPF, DKIM, DMARC)."""
    result = {"score": 0, "max": 15, "details": []}

    checks = [
        {"name": "SPF", "type": "txt", "match": "v=spf1", "points": 5},
        {"name": "DMARC", "type": "txt", "match": "v=DMARC1", "points": 5, "prefix": "_dmarc."},
    ]

    for check in checks:
        prefix = check.get("prefix", "")
        target = f"{prefix}{domain}"
        try:
            proc = subprocess.run(
                ["dig", "+short", "-t", check["type"], target],
                capture_output=True, text=True, timeout=10
            )
            output = proc.stdout.strip()
            if check["match"] in output:
                result["score"] += check["points"]
                result["details"].append({"status": "pass", "text": f"{check['name']} record found"})
            else:
                result["details"].append({"status": "fail", "text": f"{check['name']} record not found"})
        except Exception:
            result["details"].append({"status": "fail", "text": f"{check['name']} check failed"})

    # DNSSEC check
    try:
        proc = subprocess.run(
            ["dig", "+dnssec", "+short", domain],
            capture_output=True, text=True, timeout=10
        )
        if "RRSIG" in proc.stdout:
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "DNSSEC enabled"})
        else:
            result["details"].append({"status": "warn", "text": "DNSSEC not detected"})
    except Exception:
        result["details"].append({"status": "warn", "text": "DNSSEC check failed"})

    return result


def check_subdomains(domain):
    """Quick subdomain enumeration."""
    result = {"score": 0, "max": 15, "details": [], "subdomains": []}

    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
            capture_output=True, text=True, timeout=60
        )
        subs = [s.strip() for s in proc.stdout.strip().split('\n') if s.strip()]
        result["subdomains"] = subs[:20]  # Cap at 20 for display

        count = len(subs)
        if count < 10:
            result["score"] += 15
            result["details"].append({"status": "pass", "text": f"Small attack surface ({count} subdomains)"})
        elif count < 30:
            result["score"] += 10
            result["details"].append({"status": "warn", "text": f"Moderate attack surface ({count} subdomains)"})
        elif count < 100:
            result["score"] += 5
            result["details"].append({"status": "warn", "text": f"Large attack surface ({count} subdomains)"})
        else:
            result["details"].append({"status": "fail", "text": f"Very large attack surface ({count} subdomains)"})

    except FileNotFoundError:
        result["details"].append({"status": "warn", "text": "subfinder not installed — skipping"})
    except Exception as e:
        result["details"].append({"status": "warn", "text": f"Subdomain check failed: {str(e)}"})

    return result


def check_misc(domain):
    """Miscellaneous security checks."""
    result = {"score": 0, "max": 15, "details": []}

    # Check if HTTPS redirects HTTP
    try:
        proc = subprocess.run(
            ["curl", "-sI", "--connect-timeout", "5", f"http://{domain}"],
            capture_output=True, text=True, timeout=10
        )
        if "location:" in proc.stdout.lower() and "https://" in proc.stdout.lower():
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "HTTP → HTTPS redirect enabled"})
        else:
            result["details"].append({"status": "fail", "text": "No HTTP → HTTPS redirect"})
    except Exception:
        result["details"].append({"status": "warn", "text": "HTTP redirect check failed"})

    # Check robots.txt
    try:
        proc = subprocess.run(
            ["curl", "-s", "--connect-timeout", "5", f"https://{domain}/robots.txt"],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0 and "Disallow" in proc.stdout:
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "robots.txt configured"})
        else:
            result["details"].append({"status": "warn", "text": "robots.txt not found or empty"})
    except Exception:
        result["details"].append({"status": "warn", "text": "robots.txt check failed"})

    # Check security.txt
    try:
        proc = subprocess.run(
            ["curl", "-s", "--connect-timeout", "5", f"https://{domain}/.well-known/security.txt"],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0 and "Contact:" in proc.stdout:
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "security.txt present (responsible disclosure)"})
        else:
            result["details"].append({"status": "warn", "text": "security.txt not found — consider adding one"})
    except Exception:
        result["details"].append({"status": "warn", "text": "security.txt check failed"})

    return result


def get_grade(score):
    """Convert numeric score to letter grade."""
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def scan_domain(domain):
    """Run full scan on a domain and return results."""
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    results = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {}
    }

    # Run all checks
    results["checks"]["ssl"] = check_ssl(domain)
    results["checks"]["headers"] = check_headers(domain)
    results["checks"]["dns"] = check_dns(domain)
    results["checks"]["subdomains"] = check_subdomains(domain)
    results["checks"]["misc"] = check_misc(domain)

    # Calculate total score
    total_score = sum(c["score"] for c in results["checks"].values())
    total_max = sum(c["max"] for c in results["checks"].values())
    percentage = round((total_score / total_max) * 100) if total_max > 0 else 0

    results["score"] = percentage
    results["grade"] = get_grade(percentage)
    results["total_points"] = total_score
    results["max_points"] = total_max

    # Count findings
    fails = sum(1 for c in results["checks"].values() for d in c["details"] if d["status"] == "fail")
    warns = sum(1 for c in results["checks"].values() for d in c["details"] if d["status"] == "warn")
    passes = sum(1 for c in results["checks"].values() for d in c["details"] if d["status"] == "pass")

    results["summary"] = {"passed": passes, "warnings": warns, "failures": fails}

    return results


# ─── API Routes ───

@app.route("/")
def index():
    return send_from_directory('static', 'index.html')


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if AUTH_REQUIRED:
        if not API_KEYS:
            return jsonify({
                "error": "auth_misconfigured",
                "message": "API_AUTH_REQUIRED is enabled but no API_KEY/API_KEYS configured.",
            }), 503
        token = _extract_api_token()
        if not token or token not in API_KEYS:
            return _authorization_error()

    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    normalized_domain = domain.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0].lower()

    ip_retry = _check_rate_limit(_ip_hits, ip_address, IP_RATE_LIMIT)
    if ip_retry is not None:
        payload = {
            "error": "rate_limited",
            "scope": "ip",
            "limit": IP_RATE_LIMIT,
            "window_seconds": RATE_WINDOW_SECONDS,
            "retry_after_seconds": ip_retry,
        }
        response = jsonify(payload)
        response.status_code = 429
        response.headers["Retry-After"] = str(ip_retry)
        return response

    domain_retry = _check_rate_limit(_domain_hits, normalized_domain, DOMAIN_RATE_LIMIT)
    if domain_retry is not None:
        payload = {
            "error": "rate_limited",
            "scope": "domain",
            "limit": DOMAIN_RATE_LIMIT,
            "window_seconds": RATE_WINDOW_SECONDS,
            "retry_after_seconds": domain_retry,
        }
        response = jsonify(payload)
        response.status_code = 429
        response.headers["Retry-After"] = str(domain_retry)
        return response

    if not _scan_slots.acquire(blocking=False):
        response = jsonify({
            "error": "scan_capacity_reached",
            "message": "Too many concurrent scans in progress.",
            "max_concurrent_scans": MAX_CONCURRENT_SCANS,
            "retry_after_seconds": 2,
        })
        response.status_code = 429
        response.headers["Retry-After"] = "2"
        return response

    try:
        future = _scan_executor.submit(scan_domain, normalized_domain)
        try:
            results = future.result(timeout=SCAN_TIMEOUT_SECONDS)
            return jsonify(results)
        except FuturesTimeoutError:
            future.cancel()
            return jsonify({
                "error": "scan_timeout",
                "message": "Scan exceeded configured timeout ceiling.",
                "timeout_seconds": SCAN_TIMEOUT_SECONDS,
            }), 504
    finally:
        _scan_slots.release()


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
