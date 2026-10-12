# PhishScan (Mail-Detection)

A deterministic, rule-based email phishing detection and analysis CLI tool. PhishScan parses RFC 5322 `.eml` files, inspects email headers, bodies, links, and attachments offline without external API dependencies, and generates explainable threat reports with risk scores and severity classifications.

---

## Features

- **Strict Offline Operation**: Performs all threat analysis locally without external network requests or third-party API dependencies.
- **Safe Attachment Inspection**: Analyzes attachment extensions and file signatures using static byte inspection; attachments are never opened or executed.
- **Deterministic Risk Scoring**: Transparent, explainable weights aggregated into a 0–100 risk score and mapped to standard severity bands.
- **Multi-Vector Threat Analysis**:
  - **Header Checks**: SPF, DKIM, and DMARC status evaluation; sender domain alignment (From vs. Reply-To vs. Return-Path); display-name brand and executive role spoofing.
  - **Body Checks**: Text hiding techniques (`display:none`, `visibility:hidden`, `font-size:0`, white-on-white text); zero-width and invisible Unicode evasion characters; urgency, threat, and credential-harvesting phrases.
  - **Link Checks**: Anchor text vs. target destination domain mismatches; raw IP hostnames, URL shorteners, and punycode (`xn--`); lookalike and typosquatting domains.
  - **Attachment Checks**: Dangerous file extensions (`.exe`, `.js`, `.vbs`, `.scr`, `.iso`, macro-enabled Office files); double file extensions (`.pdf.exe`); content magic byte mismatches (e.g., executable disguised as PDF).
- **Flexible Reporting**: Human-readable terminal output with severity indicators and machine-readable JSON output for automated security pipelines.
- **Batch Processing**: Supports scanning individual `.eml` files as well as entire directories.

---

## Architecture Overview

```
.eml file / directory
         │
         ▼
┌─────────────────┐
│     Parser      │ ──► Headers, plain-text body, HTML body, links, attachments
└─────────────────┘
         │
         ├────────────────┬────────────────┬────────────────┐
         ▼                ▼                ▼                ▼
   Header Checks     Body Checks      Link Checks    Attachment Checks
         │                │                │                │
         └────────────────┴────────────────┴────────────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │ Scoring Engine  │ (Sum of weights capped at 100)
                         └─────────────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │Severity Mapping │ (Low / Medium / High / Critical)
                         └─────────────────┘
                                  │
                                  ▼
                     Terminal Report / JSON Report
```

---

## Installation

### Prerequisites

- Python 3.10 or higher
- Linux, macOS, or Windows

### Setup

Clone the repository and install dependencies in editable mode:

```bash
git clone https://github.com/Jaswanth2609/Mail-Detection.git
cd Mail-Detection
pip install -e .
```

To run with test dependencies:

```bash
pip install pytest pytest-cov
```

Verify installation:

```bash
phishscan --help
```

---

## Usage Guide

### 1. Analyze a Single Email

Run an analysis on any local `.eml` file:

```bash
phishscan analyze samples/phishing/account_suspended_urgent.eml
```

Example terminal output:

```text
======================================================================
PHISHSCAN EMAIL THREAT REPORT
======================================================================
File:      samples/phishing/account_suspended_urgent.eml
Subject:   URGENT ACTION REQUIRED: Account Suspended Immediately
Sender:    PayPal Security Support <security@paypal-update-alert.com>
Reply-To:  support@external-dropzone.net
Date:      Mon, 12 Oct 2026 10:15:00 +0000
----------------------------------------------------------------------
Score:     100/100   Severity: CRITICAL
----------------------------------------------------------------------
FINDINGS (10 detected):
  1. [HEADER] SPF authentication failed or softfailed (Weight: 15)
     SPF verification returned status 'fail', indicating the sending IP may not be authorized.
  2. [HEADER] DKIM authentication failed (Weight: 15)
     DKIM verification returned status 'fail', indicating possible message alteration or invalid signature.
  3. [HEADER] DMARC policy failed (Weight: 15)
     DMARC verification returned status 'fail', failing alignment or sender domain policy.
  4. [HEADER] Domain mismatch between From, Reply-To, or Return-Path (Weight: 15)
     Reply-To domain 'external-dropzone.net' != From domain 'paypal-update-alert.com'; Return-Path domain 'unrelated-server.org' != From domain 'paypal-update-alert.com'
  5. [HEADER] Display-name brand spoofing detected (Weight: 20)
     Sender display name 'PayPal Security Support' claims to be 'PayPal', but sender email domain is 'paypal-update-alert.com'.
  6. [BODY] Hidden text techniques detected (Weight: 15)
     Detected CSS/HTML text concealment methods: CSS 'display:none'.
  7. [BODY] Urgency or credential-request language detected (Weight: 10)
     Identified high-pressure or credential-harvesting phrases: urgent action required, within 24 hours, account suspended...
  8. [LINK] Link text domain differs from href destination (Weight: 25)
     Visible text displays 'https://www.paypal.com/signin' (domain: www.paypal.com), but destination points to 'paypa1-verification-login.com'
  9. [ATTACHMENT] High-risk attachment extension detected (Weight: 25)
     'verification_form.pdf.exe' has dangerous extension (.exe)
  10. [ATTACHMENT] Double file extension detected (Weight: 25)
     'verification_form.pdf.exe' disguises executable payload with double extension
======================================================================
```

### 2. JSON Output for Automated Pipelines

Generate structured JSON output:

```bash
phishscan analyze samples/phishing/account_suspended_urgent.eml --format json
```

Save directly to a file:

```bash
phishscan analyze samples/phishing/account_suspended_urgent.eml --format json --out report.json
```

### 3. Batch Scanning Directories

Analyze all `.eml` files in a folder:

```bash
phishscan analyze samples/phishing/
```

### 4. Verbose Mode

Include additional header details and metadata in terminal output:

```bash
phishscan analyze samples/legitimate/welcome_newsletter.eml --verbose
```

---

## Risk Scoring & Severity Bands

The risk score is calculated by summing the weights of all triggered findings, capped at 100:

$$\text{Final Score} = \min\left(100, \sum \text{Weights}\right)$$

### Default Severity Bands

| Score Range | Severity Level | Interpretation |
| :--- | :--- | :--- |
| **0 – 24** | **Low** | Legitimate or benign email with valid authentication. |
| **25 – 49** | **Medium** | Minor anomalies detected (e.g., missing authentication or external Reply-To). Requires review. |
| **50 – 74** | **High** | Strong indicators of phishing or deception (e.g., lookalike domains, credential language). |
| **75 – 100** | **Critical** | Multiple critical threats (e.g., spoofing, malicious attachments, domain mismatch). |

### Default Rule Weights

| Category | Finding | Default Weight |
| :--- | :--- | :--- |
| Header | SPF / DKIM / DMARC failure | 15 each (capped at 30 max) |
| Header | From / Reply-To / Return-Path domain mismatch | 15 |
| Header | Display-name brand or role spoofing | 20 |
| Body | Hidden text techniques (`display:none`, white-on-white) | 15 |
| Body | Zero-width or invisible Unicode characters | 10 |
| Body | Urgency, threat, or credential-request language | 10 |
| Link | Link visible text vs. target href domain mismatch | 25 |
| Link | Raw IP address, URL shortener, or punycode domain | 15 |
| Link | Lookalike or typosquatting domain | 25 |
| Attachment | High-risk attachment extension (`.exe`, `.scr`, `.vbs`, etc.) | 25 |
| Attachment | Double extension or declared type mismatch | 25 |

---

## Configuration (`config.toml`)

All finding weights, keyword lists, popular brand catalogs, URL shorteners, and attachment rules are fully customizable in `config.toml`:

```toml
[weights]
auth_failure = 15
auth_failure_max = 30
domain_mismatch = 15
display_name_spoofing = 20
hidden_text = 15
invisible_characters = 10
urgency_credential_language = 10
link_text_href_mismatch = 25
suspicious_url_structure = 15
lookalike_domain = 25
high_risk_attachment = 25
attachment_type_or_double_extension = 25

[severity_bands]
low_max = 24
medium_max = 49
high_max = 74
critical_max = 100
```

You can supply an alternate configuration file using the `--config` flag:

```bash
phishscan analyze email.eml --config custom_config.toml
```

---

## Project Structure

```
Mail-Detection/
├── config.toml                 # Central configuration for weights and rules
├── pyproject.toml              # Build metadata and entry points
├── README.md                   # Documentation and usage guide
├── src/
│   └── phishscan/
│       ├── __init__.py         # Package initialization
│       ├── cli.py              # CLI argument parser and command runner
│       ├── parser.py           # RFC 5322 parser and component extractor
│       ├── models.py           # Dataclass models (ParsedEmail, Finding, Result)
│       ├── scoring.py          # Weight aggregation and severity mapper
│       ├── report.py           # Terminal and JSON formatters
│       └── checks/
│           ├── __init__.py
│           ├── headers.py      # SPF/DKIM/DMARC, domain mismatch, display spoof
│           ├── body.py         # Hidden text, invisible Unicode, urgency phrases
│           ├── links.py        # Domain mismatch, IP/shorteners, typosquatting
│           └── attachments.py  # High-risk extensions, double ext, magic bytes
├── samples/
│   ├── phishing/               # Handcrafted realistic phishing examples
│   └── legitimate/             # Handcrafted legitimate benchmark emails
└── tests/
    ├── conftest.py             # Pytest fixtures
    ├── test_parser.py          # Parser unit tests
    ├── test_headers.py         # Header check unit tests
    ├── test_body.py            # Body check unit tests
    ├── test_links.py           # Link check unit tests
    ├── test_attachments.py     # Attachment check unit tests
    ├── test_scoring.py         # Scoring and band mapping unit tests
    ├── test_cli.py             # CLI commands, options, and exit code tests
    └── test_integration.py     # End-to-end integration and performance tests
```

---

## Running Tests

Run the complete test suite with `pytest`:

```bash
pytest -v
```

Run test suite with code coverage:

```bash
pytest --cov=phishscan --cov-report=term-missing
```

### Exit Codes

- `0`: Execution succeeded.
- `2`: Input or runtime error (missing file, empty file, unreadable file, or invalid arguments).

---

## License

MIT License. See LICENSE for details.
