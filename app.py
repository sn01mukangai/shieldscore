#!/usr/bin/env python3
"""
ShieldScore — Free Security Scoring API
MVP: scans any domain and returns a 0-100 security score.
"""

import socket
import ssl
from datetime import datetime

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver
import requests
from flask import Flask, jsonify, request, send_from_directory

from scanner.subdomain_provider import SubdomainProvider

app = Flask(__name__, static_folder='static', static_url_path='/static')


# ─── Scanner Engine ───

def _add_detail(result, status, text, error_code=None):
    entry = {"status": status, "text": text}
    if error_code:
        entry["error_code"] = error_code
    result["details"].append(entry)


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

            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.utcnow()).days

            if days_left > 90:
                result["score"] += 10
                _add_detail(result, "pass", f"Certificate valid ({days_left} days remaining)")
            elif days_left > 30:
                result["score"] += 5
                _add_detail(result, "warn", f"Certificate expiring soon ({days_left} days)")
            else:
                _add_detail(result, "fail", f"Certificate expiring in {days_left} days")

            if protocol in ('TLSv1.3',):
                result["score"] += 10
                _add_detail(result, "pass", f"Protocol: {protocol} (excellent)")
            elif protocol in ('TLSv1.2',):
                result["score"] += 7
                _add_detail(result, "warn", f"Protocol: {protocol} (consider upgrading to TLS 1.3)")
            else:
                _add_detail(result, "fail", f"Protocol: {protocol} (insecure)")

            cipher = s.cipher()
            if cipher and cipher[2] >= 256:
                result["score"] += 5
                _add_detail(result, "pass", f"Strong cipher: {cipher[0]} ({cipher[2]}-bit)")
            elif cipher and cipher[2] >= 128:
                result["score"] += 3
                _add_detail(result, "warn", f"Cipher: {cipher[0]} ({cipher[2]}-bit)")
            else:
                _add_detail(result, "fail", f"Weak cipher: {cipher[0] if cipher else 'unknown'}")

    except ssl.SSLCertVerificationError:
        _add_detail(result, "fail", "Certificate verification failed", error_code="tls_error")
    except socket.timeout:
        _add_detail(result, "fail", "SSL check timed out", error_code="timeout")
    except OSError:
        _add_detail(result, "fail", "SSL check failed", error_code="network_error")

    return result


def check_headers(domain):
    """Check HTTP security headers with redirect-aware requests."""
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

    session = requests.Session()
    session.max_redirects = 10

    response = None
    for target in (f"https://{domain}", f"https://www.{domain}"):
        try:
            response = session.get(target, timeout=10, allow_redirects=True)
            break
        except requests.exceptions.Timeout:
            _add_detail(result, "fail", f"Timed out fetching {target}", error_code="timeout")
            return result
        except requests.exceptions.RequestException:
            continue

    if response is None:
        _add_detail(result, "fail", "Headers check failed", error_code="network_error")
        return result

    headers = {k.lower(): v for k, v in response.headers.items()}

    for header, info in required_headers.items():
        if header in headers:
            result["score"] += info["points"]
            _add_detail(result, "pass", f"{info['name']} present")
        else:
            _add_detail(result, "fail", f"{info['name']} missing")

    server = headers.get("server", "")
    if any(v in server.lower() for v in ['apache', 'nginx', 'iis']):
        _add_detail(result, "warn", f"Server version exposed: {server}")

    return result


def _resolve_txt_records(target, resolver):
    answers = resolver.resolve(target, "TXT")
    return [b"".join(rdata.strings).decode("utf-8", errors="ignore") for rdata in answers]


def check_dns(domain):
    """Check DNS records (SPF, DMARC, DNSSEC) using dnspython."""
    result = {"score": 0, "max": 15, "details": []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10

    checks = [
        {"name": "SPF", "match": "v=spf1", "points": 5, "target": domain},
        {"name": "DMARC", "match": "v=dmarc1", "points": 5, "target": f"_dmarc.{domain}"},
    ]

    for check in checks:
        try:
            txt_values = _resolve_txt_records(check["target"], resolver)
            if any(check["match"] in txt.lower() for txt in txt_values):
                result["score"] += check["points"]
                _add_detail(result, "pass", f"{check['name']} record found")
            else:
                _add_detail(result, "fail", f"{check['name']} record not found")
        except dns.resolver.NoAnswer:
            _add_detail(result, "fail", f"{check['name']} record not found")
        except dns.exception.Timeout:
            _add_detail(result, "fail", f"{check['name']} lookup timed out", error_code="timeout")
        except dns.resolver.DNSException:
            _add_detail(result, "fail", f"{check['name']} lookup failed", error_code="dns_error")

    try:
        dnssec_resolver = dns.resolver.Resolver()
        dnssec_resolver.lifetime = 10
        dnssec_resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)
        answer = dnssec_resolver.resolve(domain, "A", raise_on_no_answer=False)
        has_rrsig = any(
            rrset.rdtype == dns.rdatatype.RRSIG
            for rrset in answer.response.answer
        )
        if has_rrsig:
            result["score"] += 5
            _add_detail(result, "pass", "DNSSEC enabled")
        else:
            _add_detail(result, "warn", "DNSSEC not detected")
    except dns.exception.Timeout:
        _add_detail(result, "warn", "DNSSEC lookup timed out", error_code="timeout")
    except dns.resolver.DNSException:
        _add_detail(result, "warn", "DNSSEC check failed", error_code="dns_error")

    return result


def check_subdomains(domain):
    """Quick subdomain enumeration via optional adapter."""
    result = {"score": 0, "max": 15, "details": [], "subdomains": []}
    provider = SubdomainProvider()
    provider_result = provider.enumerate(domain)

    if provider_result.error_code == "tool_missing":
        _add_detail(result, "warn", "subfinder not installed — skipping", error_code="tool_missing")
        return result
    if provider_result.error_code == "timeout":
        _add_detail(result, "warn", "Subdomain check timed out", error_code="timeout")
        return result
    if provider_result.error_code:
        _add_detail(result, "warn", "Subdomain check failed", error_code=provider_result.error_code)
        return result

    subs = provider_result.subdomains
    result["subdomains"] = subs[:20]
    count = len(subs)

    if count < 10:
        result["score"] += 15
        _add_detail(result, "pass", f"Small attack surface ({count} subdomains)")
    elif count < 30:
        result["score"] += 10
        _add_detail(result, "warn", f"Moderate attack surface ({count} subdomains)")
    elif count < 100:
        result["score"] += 5
        _add_detail(result, "warn", f"Large attack surface ({count} subdomains)")
    else:
        _add_detail(result, "fail", f"Very large attack surface ({count} subdomains)")

    return result


def check_misc(domain):
    """Miscellaneous security checks using requests."""
    result = {"score": 0, "max": 15, "details": []}

    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
        location = response.headers.get("Location", "")
        if response.is_redirect and location.lower().startswith("https://"):
            result["score"] += 5
            _add_detail(result, "pass", "HTTP → HTTPS redirect enabled")
        else:
            _add_detail(result, "fail", "No HTTP → HTTPS redirect")
    except requests.exceptions.Timeout:
        _add_detail(result, "warn", "HTTP redirect check timed out", error_code="timeout")
    except requests.exceptions.RequestException:
        _add_detail(result, "warn", "HTTP redirect check failed", error_code="network_error")

    try:
        response = requests.get(f"https://{domain}/robots.txt", timeout=5)
        if response.ok and "Disallow" in response.text:
            result["score"] += 5
            _add_detail(result, "pass", "robots.txt configured")
        else:
            _add_detail(result, "warn", "robots.txt not found or empty")
    except requests.exceptions.Timeout:
        _add_detail(result, "warn", "robots.txt check timed out", error_code="timeout")
    except requests.exceptions.RequestException:
        _add_detail(result, "warn", "robots.txt check failed", error_code="network_error")

    try:
        response = requests.get(f"https://{domain}/.well-known/security.txt", timeout=5)
        if response.ok and "Contact:" in response.text:
            result["score"] += 5
            _add_detail(result, "pass", "security.txt present (responsible disclosure)")
        else:
            _add_detail(result, "warn", "security.txt not found — consider adding one")
    except requests.exceptions.Timeout:
        _add_detail(result, "warn", "security.txt check timed out", error_code="timeout")
    except requests.exceptions.RequestException:
        _add_detail(result, "warn", "security.txt check failed", error_code="network_error")

    return result


def get_grade(score):
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def scan_domain(domain):
    """Run full scan on a domain and return results."""
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    results = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {}
    }

    results["checks"]["ssl"] = check_ssl(domain)
    results["checks"]["headers"] = check_headers(domain)
    results["checks"]["dns"] = check_dns(domain)
    results["checks"]["subdomains"] = check_subdomains(domain)
    results["checks"]["misc"] = check_misc(domain)

    total_score = sum(c["score"] for c in results["checks"].values())
    total_max = sum(c["max"] for c in results["checks"].values())
    percentage = round((total_score / total_max) * 100) if total_max > 0 else 0

    results["score"] = percentage
    results["grade"] = get_grade(percentage)
    results["total_points"] = total_score
    results["max_points"] = total_max

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
    data = request.get_json()
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    results = scan_domain(domain)
    return jsonify(results)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
