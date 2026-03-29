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
