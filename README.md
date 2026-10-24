<div align="center">

<img src="assets/avatar.png" width="110" alt="CertWatch avatar" />

![Banner](assets/banner.png)

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=20&duration=2600&pause=900&color=06B6D4&center=true&vCenter=true&width=700&lines=Connecting+over+TLS...;Reading+the+peer+certificate...;Checking+expiry%2C+protocol%2C+and+chain...;Your+cert+health+report+is+ready+%E2%9C%85" alt="Typing SVG" />

<br/>

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)
![TLS](https://img.shields.io/badge/TLS%2FSSL-Auditing-0284c7?style=for-the-badge&logo=letsencrypt&logoColor=white)
![CLI](https://img.shields.io/badge/Interface-CLI-10b981?style=for-the-badge&logo=gnometerminal&logoColor=white)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)

</div>

<div align="center">

![divider](assets/divider.svg)

</div>

> ### ⚠️ Usage Notice — Please Read
> CertWatch only performs a **standard TLS handshake** — the same connection your browser makes on every HTTPS page load — and reads the certificate the server presents publicly. It does not probe, brute-force, or exploit anything.
>
> 🚫 **Do not copy this repository and re-publish it as your own project.** Use it, learn from it, link back to it — just don't re-upload it under your own name/profile.

---

## 📜 Table of Contents

- [About](#-about)
- [What Gets Checked](#-what-gets-checked)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [Example Output](#-example-output)
- [CI/Monitoring Integration](#-cimonitoring-integration)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

<div align="center">

![divider](assets/divider.svg)

</div>

## 📖 About

**CertWatch** is a command-line tool that connects to a host over TLS, pulls its certificate, and audits it for the kind of silent failures that take sites offline or leave them insecure — expired certificates, deprecated protocol versions, weak signature algorithms, and hostname mismatches.

> 💡 **Why this matters:** Expired certificates are one of the most common, entirely preventable causes of site outages. A five-second check can catch what a renewal reminder missed.

---

## 🔎 What Gets Checked

| Check | What It Catches |
|---|---|
| **Expiry Window** | Already-expired certs, or certs expiring within a configurable warning window |
| **Protocol Version** | Deprecated/weak negotiated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) |
| **Signature Algorithm** | Weak signing hashes (MD5, SHA-1) still lingering on old certificates |
| **Hostname Match (SAN)** | Whether the host you're checking is actually covered by the certificate's SAN list |

Each check returns **PASS / WARN / FAIL**, rolled up into one overall status: `healthy`, `warning`, or `critical`.

---

## 🗂️ Project Structure

```
CertWatch/
├── certwatch/
│   ├── __init__.py
│   ├── analyzer.py       # TLS handshake, cert parsing, and the check logic
│   ├── report.py          # Console + JSON report rendering
│   └── cli.py              # Command-line entrypoint
├── assets/
│   ├── banner.svg / banner.png
│   ├── avatar.svg / avatar.png     # Certificate-ribbon + clock motif
│   ├── footer.svg / footer.png
│   └── divider.svg
├── docs/
│   └── check-reference.md   # Deep dive on why each check exists
├── requirements.txt
├── setup.py
├── .gitignore
├── README.md
└── LICENSE
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- Internet access (to connect to the target host)

### Installation

```bash
git clone https://github.com/Syed-Muhammad-Tayyab/CertWatch.git
cd CertWatch

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
# Optional: install as a CLI command
pip install -e .
```

---

## 🖥️ Usage

```bash
# Basic scan (defaults to port 443)
python -m certwatch.cli example.com

# Or, if installed via setup.py:
certwatch example.com

# Check a non-standard port
certwatch mail.example.com --port 993

# Export a JSON report
certwatch example.com --json report.json

# Exit code 1 if cert expires within N days — useful for monitoring/alerts
certwatch example.com --warn-days 14
```

---

## 📟 Example Output

```
$ certwatch example.com

CertWatch Report
----------------------------------------------------
Host:            example.com:443
Subject:         commonName=example.com
Issuer:          organizationName=Example CA
Valid From:      2026-07-16 20:42:29+00:00
Valid Until:     2026-11-13 20:42:29+00:00
Days Remaining:  19
Protocol:        TLSv1.2
Cipher Suite:    ECDHE-RSA-AES128-GCM-SHA256
SAN Entries:     example.com, *.example.com
Overall Status:  WARNING
----------------------------------------------------

Checks
  [WARN] Expiry: Certificate expires in 19 day(s) — renew soon.
  [PASS] Protocol Version: Negotiated TLSv1.2.
  [PASS] Signature Algorithm: Uses sha256.
  [PASS] Hostname Match: 'example.com' is covered by the certificate's SAN list.
```

---

## 🔗 CI/Monitoring Integration

```yaml
# Example scheduled GitHub Actions check (cron)
- name: Check certificate expiry
  run: |
    pip install -r requirements.txt
    python -m certwatch.cli example.com --warn-days 14
```

Pair this with a scheduled workflow (`on: schedule`) to get an automatic failing build — and a notification — before a certificate actually expires in production.

---

## 🗺️ Roadmap

- [x] Expiry, protocol, signature algorithm, and SAN hostname checks
- [x] Console + JSON reports
- [x] `--warn-days` threshold for monitoring pipelines
- [ ] Full certificate chain validation (intermediate/root checks)
- [ ] Batch mode — scan a list of hosts from a file
- [ ] OCSP / revocation status check
- [ ] Slack/Discord webhook notifications on expiry warnings

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## 📬 Contact

<div align="center">

**Syed Muhammad Tayyab**

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Syed-Muhammad-Tayyab)

![Footer](assets/footer.png)

</div>
