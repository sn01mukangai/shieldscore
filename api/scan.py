"""
ShieldScore — Vercel Serverless API
Does security checks using only the requests library — no subprocess needed.
"""

from http.server import BaseHTTPRequestHandler
import json
import ssl
import socket
import re
import os
import time
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError


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


def _extract_token(headers):
    key = (headers.get("X-API-Key") or "").strip()
    if key:
        return key
    auth = (headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _check_rate_limit(bucket, key, limit):
    now = time.time()
    with _rate_lock:
        entries = bucket[key]
        while entries and now - entries[0] >= RATE_WINDOW_SECONDS:
            entries.popleft()
        if len(entries) >= limit:
            return max(1, int(RATE_WINDOW_SECONDS - (now - entries[0])))
        entries.append(now)
    return None

def check_ssl(domain):
    result = {"score": 0, "max": 25, "details": []}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            protocol = s.version()

            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.utcnow()).days

            if days_left > 90:
                result["score"] += 10
                result["details"].append({"status": "pass", "text": f"Certificate valid ({days_left} days left)"})
            elif days_left > 30:
                result["score"] += 5
                result["details"].append({"status": "warn", "text": f"Certificate expiring in {days_left} days"})
            else:
                result["details"].append({"status": "fail", "text": f"Certificate expiring in {days_left} days"})

            if protocol == 'TLSv1.3':
                result["score"] += 10
                result["details"].append({"status": "pass", "text": f"Protocol: {protocol}"})
            elif protocol == 'TLSv1.2':
                result["score"] += 7
                result["details"].append({"status": "warn", "text": f"Protocol: {protocol} (upgrade to TLS 1.3)"})
            else:
                result["details"].append({"status": "fail", "text": f"Protocol: {protocol} (insecure)"})

            cipher = s.cipher()
            if cipher and cipher[2] >= 256:
                result["score"] += 5
                result["details"].append({"status": "pass", "text": f"Cipher: {cipher[0]} ({cipher[2]}-bit)"})
            elif cipher and cipher[2] >= 128:
                result["score"] += 3
                result["details"].append({"status": "warn", "text": f"Cipher: {cipher[0]} ({cipher[2]}-bit)"})
            else:
                result["details"].append({"status": "fail", "text": f"Weak cipher"})
    except Exception as e:
        result["details"].append({"status": "fail", "text": f"SSL error: {str(e)[:100]}"})
    return result


def check_headers(domain):
    result = {"score": 0, "max": 30, "details": []}
    header_map = {
        "strict-transport-security": {"pts": 6, "name": "HSTS"},
        "content-security-policy": {"pts": 6, "name": "CSP"},
        "x-frame-options": {"pts": 4, "name": "X-Frame-Options"},
        "x-content-type-options": {"pts": 3, "name": "X-Content-Type-Options"},
        "referrer-policy": {"pts": 3, "name": "Referrer-Policy"},
        "permissions-policy": {"pts": 3, "name": "Permissions-Policy"},
        "x-xss-protection": {"pts": 2, "name": "X-XSS-Protection"},
    }

    try:
        req = Request(f"https://www.{domain}", headers={"User-Agent": "ShieldScore/1.0"})
        resp = urlopen(req, timeout=10)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, info in header_map.items():
            if header in headers_lower:
                result["score"] += info["pts"]
                result["details"].append({"status": "pass", "text": f"{info['name']} present"})
            else:
                result["details"].append({"status": "fail", "text": f"{info['name']} missing"})

        if "server" in headers_lower:
            result["details"].append({"status": "warn", "text": f"Server: {headers_lower['server']}"})
    except Exception as e:
        result["details"].append({"status": "fail", "text": f"Headers check failed: {str(e)[:80]}"})
    return result


def check_dns(domain):
    result = {"score": 0, "max": 15, "details": []}
    try:
        # DNS-over-HTTPS for SPF
        url = f"https://dns.google/resolve?name={domain}&type=TXT"
        resp = urlopen(Request(url, headers={"Accept": "application/dns-json"}), timeout=10)
        data = json.loads(resp.read())
        answers = data.get("Answer", [])
        txt_records = " ".join(a.get("data", "") for a in answers)

        if "v=spf1" in txt_records:
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "SPF record found"})
        else:
            result["details"].append({"status": "fail", "text": "SPF record not found"})

        # DMARC
        url2 = f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"
        resp2 = urlopen(Request(url2, headers={"Accept": "application/dns-json"}), timeout=10)
        data2 = json.loads(resp2.read())
        answers2 = data2.get("Answer", [])
        dmarc = " ".join(a.get("data", "") for a in answers2)

        if "v=DMARC1" in dmarc:
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "DMARC record found"})
        else:
            result["details"].append({"status": "fail", "text": "DMARC record not found"})

        # DNSSEC
        url3 = f"https://dns.google/resolve?name={domain}&type=A&cd=0"
        resp3 = urlopen(Request(url3, headers={"Accept": "application/dns-json"}), timeout=10)
        data3 = json.loads(resp3.read())
        if data3.get("AD"):
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "DNSSEC enabled"})
        else:
            result["details"].append({"status": "warn", "text": "DNSSEC not detected"})

    except Exception as e:
        result["details"].append({"status": "fail", "text": f"DNS check failed: {str(e)[:80]}"})
    return result


def check_misc(domain):
    result = {"score": 0, "max": 15, "details": []}
    try:
        # HTTP → HTTPS redirect
        try:
            req = Request(f"http://{domain}", headers={"User-Agent": "ShieldScore/1.0"})
            resp = urlopen(req, timeout=5)
            result["details"].append({"status": "fail", "text": "No HTTP → HTTPS redirect"})
        except URLError as e:
            if hasattr(e, 'headers') and 'location' in str(e.headers).lower():
                result["score"] += 5
                result["details"].append({"status": "pass", "text": "HTTP → HTTPS redirect"})
            elif "ssl" in str(e).lower() or "certificate" in str(e).lower() or "redirect" in str(e).lower():
                result["score"] += 5
                result["details"].append({"status": "pass", "text": "HTTP → HTTPS redirect"})
            else:
                result["details"].append({"status": "warn", "text": "HTTP redirect unclear"})
    except Exception as e:
        result["details"].append({"status": "warn", "text": f"HTTP check: {str(e)[:60]}"})

    # robots.txt
    try:
        req = Request(f"https://{domain}/robots.txt", headers={"User-Agent": "ShieldScore/1.0"})
        resp = urlopen(req, timeout=5)
        content = resp.read().decode('utf-8', errors='ignore')[:2000]
        if "Disallow" in content:
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "robots.txt configured"})
        else:
            result["details"].append({"status": "warn", "text": "robots.txt empty"})
    except:
        result["details"].append({"status": "warn", "text": "robots.txt not found"})

    # security.txt
    try:
        req = Request(f"https://{domain}/.well-known/security.txt", headers={"User-Agent": "ShieldScore/1.0"})
        resp = urlopen(req, timeout=5)
        content = resp.read().decode('utf-8', errors='ignore')[:1000]
        if "Contact:" in content:
            result["score"] += 5
            result["details"].append({"status": "pass", "text": "security.txt present"})
        else:
            result["details"].append({"status": "warn", "text": "security.txt incomplete"})
    except:
        result["details"].append({"status": "warn", "text": "security.txt not found"})

    return result


def get_grade(score):
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def scan(domain):
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]

    checks = {
        "ssl": check_ssl(domain),
        "headers": check_headers(domain),
        "dns": check_dns(domain),
        "misc": check_misc(domain),
    }

    total = sum(c["score"] for c in checks.values())
    maximum = sum(c["max"] for c in checks.values())
    pct = round((total / maximum) * 100) if maximum > 0 else 0

    fails = sum(1 for c in checks.values() for d in c["details"] if d["status"] == "fail")
    warns = sum(1 for c in checks.values() for d in c["details"] if d["status"] == "warn")
    passes = sum(1 for c in checks.values() for d in c["details"] if d["status"] == "pass")

    return {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "score": pct,
        "grade": get_grade(pct),
        "total_points": total,
        "max_points": maximum,
        "summary": {"passed": passes, "warnings": warns, "failures": fails},
        "checks": checks,
    }


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self):
        self._send_json(200, {"status": "ok", "version": "1.0.0"})

    def do_POST(self):
        if AUTH_REQUIRED:
            if not API_KEYS:
                self._send_json(503, {
                    "error": "auth_misconfigured",
                    "message": "API_AUTH_REQUIRED is enabled but no API_KEY/API_KEYS configured.",
                })
                return
            token = _extract_token(self.headers)
            if not token or token not in API_KEYS:
                self._send_json(401, {
                    "error": "authentication_required",
                    "message": "Provide a valid X-API-Key header or Bearer token.",
                })
                return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
            return
        domain = data.get("domain", "")

        if not domain:
            self._send_json(400, {"error": "domain required"})
            return

        normalized_domain = domain.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0].lower()
        ip_address = (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

        ip_retry = _check_rate_limit(_ip_hits, ip_address, IP_RATE_LIMIT)
        if ip_retry is not None:
            self._send_json(429, {
                "error": "rate_limited",
                "scope": "ip",
                "limit": IP_RATE_LIMIT,
                "window_seconds": RATE_WINDOW_SECONDS,
                "retry_after_seconds": ip_retry,
            }, {"Retry-After": str(ip_retry)})
            return

        domain_retry = _check_rate_limit(_domain_hits, normalized_domain, DOMAIN_RATE_LIMIT)
        if domain_retry is not None:
            self._send_json(429, {
                "error": "rate_limited",
                "scope": "domain",
                "limit": DOMAIN_RATE_LIMIT,
                "window_seconds": RATE_WINDOW_SECONDS,
                "retry_after_seconds": domain_retry,
            }, {"Retry-After": str(domain_retry)})
            return

        if not _scan_slots.acquire(blocking=False):
            self._send_json(429, {
                "error": "scan_capacity_reached",
                "message": "Too many concurrent scans in progress.",
                "max_concurrent_scans": MAX_CONCURRENT_SCANS,
                "retry_after_seconds": 2,
            }, {"Retry-After": "2"})
            return

        try:
            future = _scan_executor.submit(scan, normalized_domain)
            try:
                results = future.result(timeout=SCAN_TIMEOUT_SECONDS)
                self._send_json(200, results)
            except FuturesTimeoutError:
                future.cancel()
                self._send_json(504, {
                    "error": "scan_timeout",
                    "message": "Scan exceeded configured timeout ceiling.",
                    "timeout_seconds": SCAN_TIMEOUT_SECONDS,
                })
        finally:
            _scan_slots.release()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.end_headers()
