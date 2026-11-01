# PhishScan

PhishScan is an offline-first command-line tool that analyzes RFC 5322 `.eml` email files, computes a deterministic risk score from 0 to 100, assigns a severity level (Low, Medium, High, Critical), and produces an explainable report detailing every detected indicator.

PhishScan operates primarily on rule-based static inspection. Threat intelligence and LLM review are optional enrichments that add context without altering offline independence.

---

## Architecture & Analysis Pipeline

```text
               Input .eml File
                      │
                      ▼
              RFC 5322 Parser
     (Headers, Body, Links, Attachments)
                      │
     ┌────────────────┼────────────────┬────────────────┐
     ▼                ▼                ▼                ▼
Header Checks    Body Checks      Link Checks     Attachment Checks
 (SPF/DKIM/DMARC, (Hidden CSS,     (Anchor mismatch, (High-risk ext,
  domain mismatch, invisible chars, IP/shortener,     double ext,
  display spoof)   urgency words)   lookalikes)       magic mismatch)
     │                │                │                │
     └────────────────┼────────────────┴────────────────┘
                      ▼
               Threat Intel (Optional)
           (VirusTotal & WHOIS + SQLite Cache)
                      │
                      ▼
                 Rule Scoring
              (Sum of weights, capped at 100)
                      │
         ┌────────────┴────────────┐
         │ Score in gray zone?     │
         │ (30 to 70 + API key)    │
         └────────────┬────────────┘
               Yes    │    No
        ┌─────────────┘    └──────────────┐
        ▼                                 ▼
   LLM Review                       Final Score
(Prompt-injection defense,        (Maps to Low, Medium,
 score blending 60/40)             High, or Critical)
        │                                 │
        └─────────────┬───────────────────┘
                      ▼
      Report Generation (Terminal, JSON, CSV, HTML)
```

---

## Features

- **Offline-First Analysis**: Core rule engine inspects headers, bodies, links, and attachments locally with zero external network dependencies.
- **Safe Static Attachment Inspection**: Identifies file signatures using magic byte headers without executing or opening attachments.
- **Multi-Vector Threat Detection**:
  - **Headers**: SPF, DKIM, and DMARC verification results; From vs. Reply-To vs. Return-Path domain alignment; brand and executive role display-name spoofing.
  - **Body & Text**: Hidden text detection (`display:none`, `visibility:hidden`, `font-size:0`, white-on-white text); zero-width Unicode characters and abnormal whitespace runs; configurable urgency and credential-harvesting phrases.
  - **Links**: Visible text vs. destination domain mismatches; raw IP addresses, URL shorteners, punycode (`xn--`), and deep subdomain chains; lookalike and typosquatting domains.
  - **Attachments**: Dangerous file extensions (`.exe`, `.scr`, `.iso`, `.docm`); double extensions (`.pdf.exe`); declared MIME vs. content magic byte mismatches.
- **Threat Intelligence & Caching**: Optional VirusTotal and WHOIS RDAP lookups with local SQLite caching (`24-hour default TTL`) and automatic rate-limit back-off.
- **LLM Review (Gray Zone)**: Optional LLM review triggered only for borderline scores (`30 to 70`). Enforces strict prompt-injection defenses, PII redaction (emails and phone numbers), and structured JSON validation. LLM scores blend with rules ($S_{final} = 0.6 \cdot S_{rules} + 0.4 \cdot S_{LLM}$) and cannot lower a Critical rule verdict.
- **Versatile Reporting**: Supports human-readable terminal output, schema-compliant JSON, CSV batch summaries, and self-contained HTML reports.

---

## Installation

### Requirements

- Python 3.10 or later
- Supported on Linux, macOS, and Windows

### Setup

```bash
git clone https://github.com/Jaswanth2609/Mail-Detection.git
cd Mail-Detection
pip install .
```

To install development dependencies (pytest):

```bash
pip install .[dev]
```

---

## Usage

### 1. Analyze a Single Email

```bash
phishscan analyze samples/phishing/account_suspended_urgent.eml
```

Example terminal output:

```text
File: account_suspended_urgent.eml Severity: CRITICAL Final score: 100/100
Rule score: 100                    LLM review: no

Findings
  +15  SPF verification returned 'fail'.  (HDR_SPF_FAIL)
  +15  DKIM verification returned 'fail'.  (HDR_DKIM_FAIL)
  +15  DMARC verification returned 'fail'.  (HDR_DMARC_FAIL)
  +15  Reply-To 'external-dropzone.net' != From 'paypal-update-alert.com'  (HDR_DOMAIN_MISMATCH)
  +20  Display name 'PayPal Security Support' claims brand 'PayPal' but domain is 'paypal-update-alert.com'.  (HDR_DISPLAY_SPOOF_BRAND)
  +15  HTML concealment methods detected: display:none.  (BODY_HIDDEN_TEXT)
  +10  Phrases detected: urgent action required, within 24 hours.  (BODY_URGENCY_LANGUAGE)
  +25  Visible text shows 'https://www.paypal.com/signin' but href points to 'paypa1-verification-login.com'.  (LINK_DOMAIN_MISMATCH)
  +25  'verification_form.pdf.exe' has dangerous extension (.exe).  (ATT_HIGH_RISK_EXT)
  +25  'verification_form.pdf.exe' disguises payload with double extension.  (ATT_DOUBLE_EXT)

Skipped: VirusTotal lookup (VT_API_KEY environment variable not set)
```

### 2. Exporting Reports (JSON, CSV, HTML)

```bash
# JSON output
phishscan analyze email.eml --format json --out report.json

# Self-contained HTML report
phishscan analyze email.eml --format html --out report.html

# CSV summary
phishscan analyze email.eml --format csv --out report.csv
```

### 3. Batch Scanning a Directory

```bash
phishscan batch ./samples/phishing --format terminal
```

### 4. Automated CI/CD Gating (`--fail-on`)

Exit with code `1` if the email severity reaches or exceeds the specified threshold:

```bash
phishscan analyze incoming.eml --fail-on high
```

Exit codes:
- `0`: Analysis completed successfully and did not trigger `--fail-on`.
- `1`: Target met or exceeded the `--fail-on` severity threshold.
- `2`: Input or runtime error (missing file, unreadable file, empty file, invalid argument).

### 5. Running Offline

To guarantee no outbound network calls are attempted:

```bash
phishscan analyze email.eml --offline
```

---

## Benchmarking

PhishScan includes a built-in benchmark runner to evaluate detection accuracy and false-positive rates against labeled email datasets (`labels.csv` with `filename,label` format).

```bash
phishscan benchmark samples --labels samples/labels.csv
```

### Measured Benchmark Results (50 Sample Dataset)

Tested on 50 balanced RFC 5322 samples (25 phishing, 25 legitimate):

| Metric | Measured Value | SRS Acceptance Target | Status |
| :--- | :--- | :--- | :--- |
| **Detection Rate (Phishing $\ge$ Medium)** | **100.0%** (25/25) | $\ge$ 85% (AC-2) | **Pass** |
| **False-Positive Rate (Legit $\ge$ High)** | **0.0%** (0/25) | $\le$ 10% (AC-3) | **Pass** |
| **Overall Accuracy** | **100.0%** (50/50) | — | **Pass** |
| **Precision** | **100.0%** | — | **Pass** |
| **Recall** | **100.0%** | — | **Pass** |
| **F1-Score** | **100.0%** | — | **Pass** |

---

## Configuration (`config.toml`)

Finding weights, severity thresholds, gray-zone bounds, and detection catalogs are configurable via `config.toml`:

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

[gray_zone]
min = 30
max = 70
```

Specify a custom configuration file at runtime:

```bash
phishscan analyze email.eml --config custom_config.toml
```

---

## Testing

Run the full automated test suite using pytest or the standalone runner:

```bash
# Using pytest
pytest -v

# Or using the built-in runner
python3 run_tests.py
```

---

## Project Structure

```text
Mail-Detection/
├── config.toml             # Configurable weights, severity bands, and brand catalogs
├── pyproject.toml          # Build configuration and project metadata
├── README.md               # Documentation and benchmark results
├── run_tests.py            # Standalone test runner
├── src/
│   └── phishscan/
│       ├── __init__.py     # Package version
│       ├── cli.py          # Command-line interface (analyze, batch, benchmark)
│       ├── intel.py        # Threat intelligence (VirusTotal, WHOIS) & SQLite cache
│       ├── llm.py          # Borderline LLM review with anti-prompt-injection defense
│       ├── models.py       # Dataclass models (ParsedEmail, Finding, Result)
│       ├── parser.py       # RFC 5322 parser, safe attachment extractor, PII redactor
│       ├── report.py       # Formatters for Terminal, JSON, CSV, and HTML
│       ├── scoring.py      # Weight aggregation, auth cap, severity bands, score blending
│       └── checks/
│           ├── attachments.py # High-risk ext, double ext, magic byte mismatch
│           ├── body.py        # Hidden CSS text, zero-width chars, urgency phrases
│           ├── headers.py     # SPF/DKIM/DMARC status, domain mismatch, display spoof
│           └── links.py       # Anchor mismatch, IP/shortener, lookalike domains
├── samples/
│   ├── labels.csv          # Ground-truth labels for 50 benchmark emails
│   ├── phishing/           # 25 realistic phishing samples
│   └── legitimate/         # 25 realistic legitimate samples
└── tests/
    ├── conftest.py         # Test fixtures and pytest compatibility shim
    ├── test_attachments.py # Attachment check tests
    ├── test_benchmark.py   # Benchmark acceptance criteria tests
    ├── test_body.py        # Body check tests
    ├── test_cli.py         # CLI commands and exit code tests
    ├── test_headers.py     # Header check tests
    ├── test_integration.py # End-to-end integration tests
    ├── test_intel.py       # Threat intel and SQLite cache tests
    ├── test_links.py       # Link check tests
    ├── test_llm.py         # LLM review, blending, and injection defense tests
    ├── test_parser.py      # Parser and PII redaction tests
    ├── test_report.py      # Report format tests
    └── test_scoring.py     # Scoring and band mapping tests
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
