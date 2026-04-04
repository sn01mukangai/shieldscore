# 🛡️ ShieldScore

**Free security scoring for any domain. Know your security posture in 30 seconds.**

![ShieldScore](https://img.shields.io/badge/version-1.0.0-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## What is ShieldScore?

ShieldScore scans any domain and gives you a **0–100 security score** with a detailed breakdown across:

- 🔒 **SSL/TLS** — Certificate validity, protocol versions, cipher strength
- 🛡️ **HTTP Security Headers** — CSP, HSTS, X-Frame-Options, etc.
- 🌐 **DNS Hygiene** — SPF, DKIM, DMARC, DNSSEC
- 🔍 **Exposed Subdomains** — Surface area assessment
- ⚠️ **Known Vulnerabilities** — Detected via nuclei scanning
- 📋 **Compliance Readiness** — OWASP, GDPR, Kenya DPA

## Quick Start

```bash
# Clone
git clone https://github.com/sn01mukangai/shieldscore.git
cd shieldscore

# Install dependencies
pip install -r requirements.txt

# Run
python app.py

# Open http://localhost:5000
```

## Architecture

```
shieldscore/
├── app.py                 # Flask API server
├── scanner/
│   ├── engine.py          # Core scanning engine
│   ├── ssl_check.py       # SSL/TLS analysis
│   ├── headers_check.py   # Security headers
│   ├── dns_check.py       # DNS analysis
│   ├── subdomain_enum.py  # Subdomain discovery
│   └── scoring.py         # Score calculation
├── static/
│   ├── index.html         # Frontend
│   ├── style.css          # Styles
│   └── script.js          # Client-side logic
├── templates/
│   └── report.html        # PDF report template
├── requirements.txt
├── Dockerfile
└── README.md
```

## API Endpoints

```
POST /api/scan          # Start a new scan
GET  /api/scan/{id}     # Get scan results
GET  /api/score/{domain} # Quick score lookup
GET  /api/health        # Health check
```

## API Security

ShieldScore supports lightweight API hardening controls for `POST /api/scan`:

- **API authentication** (required by default):
  - Send `X-API-Key: <token>` **or** `Authorization: Bearer <token>`.
  - Configure valid tokens with `API_KEY` (single token) or `API_KEYS` (comma-separated list).
  - Toggle enforcement with `API_AUTH_REQUIRED` (`true` by default).
- **Rate limiting**:
  - Per-IP: `SCAN_RATE_LIMIT_IP` requests per window (default `10`).
  - Per-domain: `SCAN_RATE_LIMIT_DOMAIN` requests per window (default `5`).
  - Window size: `SCAN_RATE_WINDOW_SECONDS` (default `60`).
  - Limit responses return HTTP `429` plus `Retry-After` and `retry_after_seconds`.
- **Worker starvation protection**:
  - Request timeout ceiling: `SCAN_TIMEOUT_SECONDS` (default `90`).
  - Concurrent scan cap: `MAX_CONCURRENT_SCANS` (default `4`).
  - If scan capacity is exhausted, API returns HTTP `429`.
  - If a scan exceeds timeout, API returns HTTP `504`.

Example:

```bash
export API_AUTH_REQUIRED=true
export API_KEYS="dev-key-1,dev-key-2"
export SCAN_RATE_LIMIT_IP=10
export SCAN_RATE_LIMIT_DOMAIN=5
export SCAN_RATE_WINDOW_SECONDS=60
export SCAN_TIMEOUT_SECONDS=90
export MAX_CONCURRENT_SCANS=4
```

## Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## License

MIT — free to use, modify, and distribute.

## Roadmap

- [x] Core scanning engine
- [x] Security score calculation
- [x] Web frontend
- [x] REST API
- [ ] PDF report generation
- [ ] Email alerts
- [ ] Monthly monitoring subscriptions
- [ ] Compliance checklist (OWASP, GDPR, DPA)
- [ ] Public badge generation

---

Built with 🔱 by [CipherShield Security](https://github.com/sn01mukangai)
