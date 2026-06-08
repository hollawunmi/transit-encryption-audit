# Third-Party In-Transit Encryption Recertification Tool

A Python-based TLS/SSL scanner for auditing third-party vendor connections against organizational encryption compliance policy.

Built as a practical lab project aligned to real-world Application Security workflows in financial services environments.

---

## What It Does

- Probes live third-party endpoints via TLS handshake
- Evaluates each connection against a defined encryption policy
- Detects 10 categories of encryption failures
- Flags internal network endpoints for manual review escalation
- Generates a formatted Excel report with 4 sheets: Dashboard, Full Results, Findings Detail, and Manual Review Tracker

---

## Failure Types Detected

| Failure | Severity |
|---|---|
| Expired Certificate | CRITICAL |
| Revoked Certificate | CRITICAL |
| Hostname Mismatch | HIGH |
| Self-Signed Certificate | HIGH |
| Untrusted Root CA | HIGH |
| Incomplete Certificate Chain | HIGH |
| Weak Cipher (RC4) | HIGH |
| TLSv1.0 Protocol | HIGH |
| TLSv1.1 Protocol | MEDIUM |
| SHA-1 Intermediate Chain | MEDIUM |

---

## Compliance Policy

| Control | Requirement |
|---|---|
| Minimum TLS Version | TLSv1.2 (TLSv1.3 preferred) |
| Banned Protocols | SSLv2, SSLv3, TLSv1.0, TLSv1.1 |
| Cipher Requirement | AEAD ciphers with Perfect Forward Secrecy |
| Certificate Authority | Recognized public CA only |
| Certificate Validity | 90-day expiry warning threshold |

---

## Connection Inventory

28 connections scanned across three regions:

- **AMER** — Visa, SWIFT, Plaid, Moody's, Salesforce, TD Bank, Rosh-Will LLC, internal servers
- **EMEA** — Bloomberg, LexisNexis, legacy banking systems (Finacle, Temenos, Murex)
- **APAC** — Mastercard, AWS, legacy systems (FIS Global, Oracle FLEXCUBE, Finacle)

Internal private IP endpoints (10.x, 172.16.x, 192.168.x) are automatically flagged for on-site verification by Network Security.

---

## Output

Each scan run produces:
- `Encryption_Recertification_<timestamp>.xlsx` — 4-sheet formatted Excel report
- `scan_<timestamp>.json` — machine-readable output for SIEM/ticketing integration

---

## How to Run

```bash
pip install openpyxl
python tls_scanner.py
```

---

## Skills Demonstrated

- TLS/SSL protocol knowledge (version hierarchy, cipher suites, PFS, certificate chain validation)
- Python automation for security compliance workflows
- Encryption policy enforcement and evidence generation
- AMER/EMEA/APAC regional audit coordination workflow
- Excel report generation for stakeholder communication

---

## Author

Segun Olawunmi — Cybersecurity Analyst  
[LinkedIn](https://linkedin.com/in/segun-olawunmi) | [GitHub](https://github.com/hollawunmi)