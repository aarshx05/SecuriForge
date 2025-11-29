# SecuriForge - Binary Security Analysis Tool for CI/CD

> **Comprehensive binary security analysis with SBOM generation, malware detection, hardening checks, and AI-powered reporting**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://hub.docker.com/)

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Module Overview](#-module-overview)
- [GitHub Actions Integration](#-github-actions-integration)
- [Exit Codes](#-exit-codes)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🔍 **Four Analysis Modules**
- **SBOM Generation**: Software Bill of Materials in SPDX & CycloneDX formats
- **Hardening Checks**: NX, PIE, RELRO, Stack Canaries, Fortify Source, ASLR
- **Malware Detection**: Entropy analysis, YARA rule matching, suspicious imports, string analysis
- **Risk Assessment**: Reverse engineering difficulty scoring with weighted metrics

### 🤖 **AI-Powered Intelligence**
- Generate security reports using GROQ API (Llama 3.3 70B)
- Three report modes: Executive Summary, Technical Remediation, Full Report
- Smart context extraction with semantic embeddings
- Export to professional PDF format

### 📧 **Automated Workflows**
- Email notifications with customizable templates
- Gmail/Outlook/Yahoo presets + custom SMTP
- Attach JSON and PDF reports automatically
- CI/CD pipeline integration with exit codes

### 🐳 **Production Ready**
- Docker container: `ghcr.io/aarshx05/securiforge:latest`
- Configurable risk thresholds for pipeline gates
- Caching support for faster repeated scans
- Cross-platform: Linux, macOS, Windows

---

## 🚀 Quick Start

### 1. Basic Analysis
```bash
python unified_binary_analysis.py your_app.exe -o report.json
```
**Output:** JSON report with all security findings

### 2. With AI Report
```bash
export GROQ_API_KEY="your-key-here"
python unified_binary_analysis.py your_app.exe \
  --ai-report \
  --export-pdf report.pdf
```
**Output:** JSON + AI-generated PDF report

### 3. CI/CD Pipeline Integration
```bash
python unified_binary_analysis.py build/artifact \
  --fail-on-high \
  -o security-report.json
```
**Output:** Exits with code 3 if high risk detected

### 4. Email Notification
```bash
python unified_binary_analysis.py app.exe \
  --ai-report \
  --export-pdf report.pdf \
  --email-to security@company.com \
  --email-from scanner@company.com \
  --email-password "$EMAIL_PASS" \
  --email-preset gmail \
  --email-attach-pdf
```
**Output:** Sends professional email with PDF report attached

---

## 📦 Installation

### Option 1: Docker (Recommended)
```bash
# Pull latest image
docker pull ghcr.io/aarshx05/securiforge:latest

# Run analysis
docker run --rm -v $(pwd):/workspace \
  ghcr.io/aarshx05/securiforge:latest \
  python3 unified_binary_analysis.py /workspace/binary.exe -o /workspace/report.json
```

### Option 2: Local Installation
```bash
# Clone repository
git clone https://github.com/your-org/securiforge.git
cd securiforge

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python unified_binary_analysis.py --help
```

### System Requirements
- **Python**: 3.9 or higher
- **RAM**: 4GB minimum (8GB recommended for AI features)
- **Disk**: 2GB for dependencies + models
- **OS**: Linux, macOS, Windows (WSL2 recommended)

---

## 🎯 Usage

### Basic Syntax
```bash
python unified_binary_analysis.py <BINARY> [OPTIONS]
```

### Common Use Cases

#### 1. Full Security Analysis
```bash
python unified_binary_analysis.py app.exe \
  -o full-report.json \
  --verbose
```

#### 2. Malware Scan with YARA Rules
```bash
python unified_binary_analysis.py suspicious.exe \
  --only-malware \
  -y ./yara \
  --fail-on-yara
```

#### 3. SBOM Generation (Both Formats)
```bash
python unified_binary_analysis.py app.exe \
  --only-sbom \
  --sbom-format both \
  -o sbom.json
```

#### 4. Hardening Compliance Check
```bash
python unified_binary_analysis.py app.exe \
  --only-hardening \
  --fail-on-medium
```

#### 5. Complete Workflow (All Features)
```bash
python unified_binary_analysis.py production.exe \
  -o analysis.json \
  --output-dir ./reports/ \
  --sbom-format both \
  -y ./yara \
  --ai-report \
  --report-mode report \
  --export-pdf security-report.pdf \
  --email-to security@company.com \
  --email-from scanner@company.com \
  --email-password "$EMAIL_PASS" \
  --email-preset gmail \
  --email-attach-json \
  --email-attach-pdf \
  --fail-on-high \
  --verbose
```

---

## 🔧 Module Overview

### 1️⃣ SBOM Generation (`--only-sbom`)
Generates Software Bill of Materials for supply chain security.

**Features:**
- SPDX 2.3 JSON format
- CycloneDX 1.4 JSON format
- Library dependency extraction
- Import function analysis
- Package version detection

**Use Cases:**
- Software composition analysis
- License compliance checking
- Vulnerability tracking
- Supply chain risk management

---

### 2️⃣ Hardening Checks (`--only-hardening`)
Validates security hardening features in binaries.

**Checks:**
- **NX (No-Execute)**: Stack execution prevention
- **PIE (Position Independent Executable)**: ASLR support
- **RELRO**: GOT hardening
- **Stack Canary**: Buffer overflow protection
- **Fortify Source**: Enhanced security functions
- **ASLR**: Address space randomization

**Exit Criteria:**
- ✅ All checks pass → Low risk
- ⚠️ 50% pass → Medium risk
- 🚨 <50% pass → High risk

---

### 3️⃣ Malware Detection (`--only-malware`)
Multi-layered malware analysis with YARA integration.

**Features:**
- **Entropy Analysis**: Detects obfuscation/packing
- **YARA Rules**: Signature-based detection (722 APT rules included)
- **Suspicious Imports**: API call analysis (GetProcAddress, VirtualAlloc, etc.)
- **String Analysis**: Suspicious keywords, URLs, IPs
- **Section Analysis**: Writable-executable sections

**Default YARA Rules:**
- APT10, APT28, APT29 (Nobelium)
- Malware families: Agent.BTZ, AlienSpy, HyperBro
- Auto-loaded from `./yara` directory

---

### 4️⃣ Risk Assessment (`--only-risk`)
Evaluates reverse engineering difficulty.

**Scoring Factors:**
- Symbols presence/absence
- Anti-debugging techniques
- Obfuscation indicators
- Code complexity
- Binary hardening features

**Risk Levels:**
- **Low (0.0-0.4)**: Easy to reverse engineer
- **Medium (0.4-0.7)**: Moderate protection
- **High (0.7-1.0)**: Strong anti-RE measures

---

### 5️⃣ AI Report Generation (`--ai-report`)
Intelligent report generation using GROQ API.

**Modes:**
- `--report-mode summary`: Executive summary (300 words)
- `--report-mode remediation`: Prioritized fixes with code examples
- `--report-mode report`: Full technical analysis (default)

**Requirements:**
- GROQ API key: Get from https://console.groq.com/
- Set via `--groq-key` or `GROQ_API_KEY` environment variable

---

## 🔄 GitHub Actions Integration

### Quick Setup

1. **Add Secrets** (Settings → Secrets and variables → Actions):
   - `GROQ_API_KEY`: Your GROQ API key
   - `EMAIL_APP_PASSWORD`: Gmail app password (optional)

2. **Create Workflow File**: `.github/workflows/security-scan.yml`
   - See [WORKFLOW.md](WORKFLOW.md) for complete examples

3. **Push and Run**: Workflow triggers automatically on push/PR

### Example Workflow (Minimal)
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run SecuriForge
        run: |
          docker pull ghcr.io/aarshx05/securiforge:latest
          docker run --rm -v $PWD:/workspace \
            ghcr.io/aarshx05/securiforge:latest \
            python3 unified_binary_analysis.py \
              /workspace/build/app.exe \
              -o /workspace/report.json \
              --fail-on-high
      
      - uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.json
```

**See [WORKFLOW.md](WORKFLOW.md) for production-ready workflows with:**
- PR comments with security findings
- Email notifications
- Baseline comparisons
- Multi-job pipelines
- Artifact uploads

---

## 🔢 Exit Codes

SecuriForge uses exit codes for CI/CD pipeline integration:

| Exit Code | Risk Level | Score Range | Action |
|-----------|-----------|-------------|--------|
| **0** | Low | 0.0 - 0.4 | ✅ Pass - Safe to deploy |
| **2** | Medium | 0.4 - 0.7 | ⚠️ Warning - Review recommended |
| **3** | High | 0.7 - 1.0 | 🚨 Fail - Block deployment |
| **10** | YARA Match | N/A | 🛑 Malware detected |
| **1** | Error | N/A | ❌ Analysis failed |

### Controlling Exit Behavior

```bash
# Default: Exit with risk level (0, 2, or 3)
python unified_binary_analysis.py app.exe

# Fail only on high risk
python unified_binary_analysis.py app.exe --fail-on-high

# Fail on medium or above
python unified_binary_analysis.py app.exe --fail-on-medium

# Custom threshold (0.0-1.0)
python unified_binary_analysis.py app.exe --fail-threshold 0.6

# Fail immediately on YARA match
python unified_binary_analysis.py app.exe -y rules.yar --fail-on-yara
```

### Script Integration Example
```bash
#!/bin/bash
python unified_binary_analysis.py build/app.exe --fail-on-high -o report.json

if [ $? -eq 0 ]; then
    echo "✅ Security check passed - deploying..."
    ./deploy.sh
elif [ $? -eq 2 ]; then
    echo "⚠️ Medium risk - requesting approval..."
    ./request_approval.sh
else
    echo "🚨 High risk or malware detected - blocking deployment"
    exit 1
fi
```

---

## 📚 Documentation

### Complete Documentation Files

| File | Description |
|------|-------------|
| **[README.md](README.md)** | This file - main documentation |
| **[COMMANDS.md](COMMANDS.md)** | All possible command combinations (1000+) |
| **[WORKFLOW.md](WORKFLOW.md)** | Production GitHub Actions workflows |

### Quick Reference

```bash
# Show all options
python unified_binary_analysis.py --help
```

---

## 🧪 Testing

### Local Testing
```bash
# Run test suite
python test_setup.py

# Test with sample binary
python unified_binary_analysis.py test_binary.exe -o test.json --verbose
```

### Expected Output
```
2025-11-29 21:43:58 - INFO - Found 722 YARA rules in ./yara
2025-11-29 21:43:59 - INFO - Running SBOM generation...
2025-11-29 21:43:59 - INFO - SBOM generation completed
2025-11-29 21:43:59 - INFO - Running hardening checks...
2025-11-29 21:43:59 - INFO - Hardening checks completed
2025-11-29 21:43:59 - INFO - Running malware detection...
2025-11-29 21:44:19 - INFO - Malware detection completed
2025-11-29 21:44:19 - INFO - Running risk assessment...
2025-11-29 21:44:19 - INFO - Risk assessment completed
============================================================
ANALYSIS SUMMARY
============================================================
Malware Risk: Low (0.153)
RE Risk: High (0.76)
Hardening: 3/6 checks passed
------------------------------------------------------------
Overall Weighted Risk: Medium (0.439)
============================================================
Exit Code: 2 (Medium Risk)
```

---

## 🤝 Contributing

We welcome contributions!

### Development Setup
```bash
# Clone repo
git clone https://github.com/your-org/securiforge.git
cd securiforge

# Install dev dependencies
pip install -r requirements.txt

# Run tests
python test_setup.py
```

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **LIEF**: Binary parsing library
- **YARA**: Pattern matching engine
- **Capstone**: Disassembly framework
- **GROQ**: AI inference API
- **sentence-transformers**: Semantic embeddings

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/securiforge/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/securiforge/discussions)

---

## 🗺️ Roadmap

- [ ] Support for macOS Mach-O binaries
- [ ] Integration with DefectDojo
- [ ] Custom YARA rule management UI
- [ ] Baseline comparison and regression detection
- [ ] Multi-binary batch analysis
- [ ] VSCode extension

---

**Made with ❤️ by the Aarsh Chaurasia (aarshc.me)**

⭐ Star us on GitHub if this tool helps secure your software!
