# Kaanan — AI-Driven SAST, UAT Documentation & VAPT CLI

**Kaanan** is an open-source, AI-powered security and documentation CLI tool. It combines Static Application Security Testing (SAST), UAT Documentation generation, and Vulnerability Assessment & Penetration Testing (VAPT) into a single command-line interface, powered by any LiteLLM-compatible language model.

---

## ⚠️ Disclaimer — Please Read Before Use

### VAPT Authorisation

**You must have explicit written authorisation from the system owner before invoking `kaanan vapt` or `kaanan run pipeline` against any target.** The VAPT agent fires real HTTP attack payloads against a live server. Running it against systems you do not own or have not been granted permission to test is illegal.

**Kaanan and its authors accept no liability** for any damage, disruption, data loss, legal consequences, or other outcomes arising from the use of this tool. Use at your own risk.

### Data Privacy

Kaanan does **not** collect or transmit your source code to its own servers. All processing happens locally. However, Kaanan sends your code to the LLM provider you configure (e.g. OpenAI, Anthropic, Ollama). Review your provider's data policy before scanning proprietary code, or use a local model for maximum privacy.

---

## Features

### SAST — Static Application Security Testing
- AI-powered scanning using any LiteLLM-compatible model
- Detects injection flaws, hardcoded secrets, broken authentication, SSRF, IDOR, path traversal, and more
- Maps findings to **CWE IDs** and **OWASP Top 10 2021**
- Generates a **PDF report** with line-highlighted code snippets, impact assessments, and remediation guidance

### UAT Documentation Agent
- Classifies every file as **Backend**, **Frontend-Web**, **Frontend-App**, or **Non-Code**
- **Backend files**: extracts endpoint routes, authentication requirements, request/response schemas, and a ready-to-run cURL command per endpoint
- **Frontend files**: extracts screen identity, testable element selectors, user flows, and API bindings
- Generates a structured **UAT PDF report** ready to share with QA engineers

### VAPT — Vulnerability Assessment & Penetration Testing
- Extracts the full API surface from source code, then attacks each endpoint against the live running application
- Covers SQL Injection, BOLA/IDOR, Broken Authentication, Command Injection, Path Traversal, SSRF, XSS, Mass Assignment, and Sensitive Data Exposure
- Baseline comparison confirms vulnerabilities from live HTTP responses — not just payload firing
- Every attack attempt is recorded with the LLM analyst's reasoning, whether confirmed or not
- Generates a **VAPT PDF report** with confirmed findings, evidence, payloads, and remediation

### Pipeline
- Runs all three agents in sequence — SAST → UAT → VAPT — in a single command
- Each report is saved to disk as its stage completes, so a failure in Stage 3 still preserves Stages 1 and 2
- VAPT reuses SAST findings and the UAT endpoint map — no work is repeated

### General
- Supports OpenAI, Anthropic, Google Gemini, Azure OpenAI, AWS Bedrock, and local Ollama via LiteLLM
- Configurable file extension whitelist
- Zero telemetry

---

## Installation

Requires **Python 3.10+**.

```bash
pip install kaanan
```

---

## Quick Start

### Step 1 — Scaffold your config

```bash
kaanan init
```

Creates a `.env` and `kaanan_whitelist.txt` in your current directory.

### Step 2 — Edit `.env`

```env
# Required for all modes
KAANAN_API_KEY=your_api_key_here
KAANAN_MODEL=gpt-4o

# Required for VAPT and pipeline (uncomment and set before running)
# KAANAN_TARGET_IP=127.0.0.1
# KAANAN_TARGET_PORT=5000
# KAANAN_TARGET_FILE=app.py
# KAANAN_MAX_TOKENS_PER_API=10000
```

### Step 3 — Run a SAST scan

```bash
kaanan scan --dir ./src
```

### Step 4 — Generate UAT documentation

```bash
kaanan document scan --dir ./src
```

### Step 5 — Run VAPT against your live application

```bash
# Start your application first, then:
kaanan vapt --dir ./src
```

An authorisation confirmation prompt appears before any attack payload is fired.

### Step 6 — Run the full pipeline

```bash
# SAST + UAT + VAPT in one command
kaanan run pipeline --dir ./src

# Save all reports to a custom directory
kaanan run pipeline --dir ./src --output-dir ./reports

# SAST + UAT only, skip VAPT
kaanan run pipeline --dir ./src --skip-vapt
```

### Step 7 — Open the PDF reports

| Report | Default filename |
|--------|-----------------|
| SAST | `kaanan_report.pdf` |
| UAT Documentation | `kaanan_uat_report.pdf` |
| VAPT Assessment | `kaanan_vapt_report.pdf` |

---

## Supported LLM Providers

| Provider       | `KAANAN_MODEL` value                                    |
|----------------|---------------------------------------------------------|
| OpenAI         | `gpt-4o` / `gpt-4o-mini` / `gpt-4-turbo`               |
| Anthropic      | `claude-3-5-sonnet-20241022` / `claude-3-opus-20240229` |
| Google         | `gemini/gemini-1.5-pro`                                 |
| Local (Ollama) | `ollama/llama3` / `ollama/mistral`                      |
| Azure OpenAI   | `azure/your-deployment-name`                            |
| AWS Bedrock    | `bedrock/anthropic.claude-3-sonnet`                     |

Full provider list: https://docs.litellm.ai/docs/providers

For local Ollama models, set `KAANAN_API_KEY=dummy`.

---

## Configuration

### `.env` File

Place a `.env` in the directory where you run `kaanan`.

```env
# Required for all modes
KAANAN_API_KEY=sk-...
KAANAN_MODEL=gpt-4o

# Required for VAPT and pipeline
KAANAN_TARGET_IP=127.0.0.1
KAANAN_TARGET_PORT=5000
KAANAN_TARGET_FILE=app.py
KAANAN_MAX_TOKENS_PER_API=10000

# Optional — for auto-authentication during VAPT
# KAANAN_TEST_USERNAME=admin
# KAANAN_TEST_PASSWORD=admin123
```

### `kaanan_whitelist.txt` (Optional)

Controls which file extensions are scanned. One extension per line. If absent, Kaanan uses sensible defaults per mode. Run `kaanan --help` to see the defaults.

---

## Commands

```bash
kaanan --help                                     # Show setup guide
kaanan init                                       # Scaffold .env + whitelist
kaanan scan --dir PATH                            # SAST security scan
kaanan scan --dir PATH --output FILE              # SAST with custom report path
kaanan document scan --dir PATH                   # Generate UAT documentation
kaanan document scan --dir PATH --output FILE     # UAT docs with custom report path
kaanan vapt --dir PATH                            # VAPT against a live application
kaanan vapt --dir PATH --output FILE              # VAPT with custom report path
kaanan run pipeline --dir PATH                    # Run SAST + UAT + VAPT in sequence
kaanan run pipeline --dir PATH --output-dir DIR   # Pipeline with custom report directory
kaanan run pipeline --dir PATH --skip-vapt        # SAST + UAT only
```

---

## Examples

```bash
# SAST — scan your entire project
kaanan scan --dir .

# UAT — document all backend and frontend files
kaanan document scan --dir ./src

# VAPT — start your app first, then run
kaanan vapt --dir ./src

# Pipeline — run everything in one command
kaanan run pipeline --dir ./src

# Pipeline — save reports to a dated folder
kaanan run pipeline --dir ./src --output-dir ./reports/$(date +%Y%m%d)

# Pipeline — SAST + UAT only, no VAPT
kaanan run pipeline --dir ./src --skip-vapt

# Use a local Ollama model (no API key, maximum privacy)
# Set KAANAN_MODEL=ollama/llama3 and KAANAN_API_KEY=dummy in .env
kaanan scan --dir ./src
```

---

## Project Structure

```
kaanan/
├── cli.py            # All commands
├── config.py         # Config loaders
├── scanner.py        # SAST engine
├── report.py         # SAST PDF report
├── doc_scanner.py    # UAT doc scanner
├── doc_report.py     # UAT PDF report
├── vapt_scanner.py   # VAPT engine
└── vapt_report.py    # VAPT PDF report
```

---

## Contributing

Issues and pull requests are welcome. Please open an issue before submitting large changes.

---

*Kaanan is not affiliated with OpenAI, Anthropic, Google, or any LLM provider. All trademarks belong to their respective owners.*