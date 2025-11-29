# 🛡️ SecuriForge - Complete Command Reference

> **Every possible command combination and usage pattern**

---

## 📋 Table of Contents

1. [Basic Commands](#basic-commands)
2. [Module Selection](#module-selection)
3. [Output Options](#output-options)
4. [SBOM Options](#sbom-options)
5. [Malware Detection](#malware-detection)
6. [AI Report Generation](#ai-report-generation)
7. [PDF Export](#pdf-export)
8. [Email Notifications](#email-notifications)
9. [CI/CD Integration](#cicd-integration)
10. [Combined Workflows](#combined-workflows)
11. [Environment Variables](#environment-variables)

---

## Basic Commands

### Minimal Command
```bash
python unified_binary_analysis.py binary.exe
```
**Output:** JSON to stdout with all modules

### Save to File
```bash
python unified_binary_analysis.py binary.exe -o report.json
```
**Output:** JSON file

### Verbose Mode
```bash
python unified_binary_analysis.py binary.exe -v
```
**Output:** Detailed logs + JSON to stdout

### Verbose + Save
```bash
python unified_binary_analysis.py binary.exe -v -o report.json
```
**Output:** Detailed logs + JSON file

### Help
```bash
python unified_binary_analysis.py --help
```
**Output:** All available options

---

## Module Selection

### Run ALL Modules (Default)
```bash
python unified_binary_analysis.py binary.exe
```
**Modules:** SBOM + Hardening + Malware + Risk

### Run ONLY Specific Modules

#### Only SBOM
```bash
python unified_binary_analysis.py binary.exe --only-sbom
```

#### Only Hardening
```bash
python unified_binary_analysis.py binary.exe --only-hardening
```

#### Only Malware
```bash
python unified_binary_analysis.py binary.exe --only-malware
```

#### Only Risk Assessment
```bash
python unified_binary_analysis.py binary.exe --only-risk
```

#### Combine Multiple ONLY Flags
```bash
# SBOM + Hardening only
python unified_binary_analysis.py binary.exe --only-sbom --only-hardening

# Malware + Risk only
python unified_binary_analysis.py binary.exe --only-malware --only-risk

# Hardening + Malware + Risk
python unified_binary_analysis.py binary.exe --only-hardening --only-malware --only-risk
```

### SKIP Specific Modules

#### Skip SBOM
```bash
python unified_binary_analysis.py binary.exe --skip-sbom
```
**Runs:** Hardening + Malware + Risk

#### Skip Hardening
```bash
python unified_binary_analysis.py binary.exe --skip-hardening
```
**Runs:** SBOM + Malware + Risk

#### Skip Malware
```bash
python unified_binary_analysis.py binary.exe --skip-malware
```
**Runs:** SBOM + Hardening + Risk

#### Skip Risk
```bash
python unified_binary_analysis.py binary.exe --skip-risk
```
**Runs:** SBOM + Hardening + Malware

#### Skip Multiple Modules
```bash
# Only Hardening and Malware
python unified_binary_analysis.py binary.exe --skip-sbom --skip-risk

# Only SBOM
python unified_binary_analysis.py binary.exe --skip-hardening --skip-malware --skip-risk
```

---

## Output Options

### Combined JSON
```bash
python unified_binary_analysis.py binary.exe -o combined.json
```
**Output:** Single JSON with all results

### Long Form
```bash
python unified_binary_analysis.py binary.exe --output combined.json
```
**Same as:** `-o`

### Individual Module Reports
```bash
python unified_binary_analysis.py binary.exe --output-dir ./reports/
```
**Output:**
```
reports/
├── sbom.json
├── hardening.json
├── malware.json
└── risk_assessment.json
```

### Combined + Individual
```bash
python unified_binary_analysis.py binary.exe -o combined.json --output-dir ./reports/
```
**Output:** Both combined file AND individual reports

### Terminal Output Only
```bash
python unified_binary_analysis.py binary.exe
```
**Output:** JSON to stdout (no files saved)

---

## SBOM Options

### SPDX Format (Default)
```bash
python unified_binary_analysis.py binary.exe --sbom-format spdx-json
```

### CycloneDX Format
```bash
python unified_binary_analysis.py binary.exe --sbom-format cyclonedx
```

### Both Formats
```bash
python unified_binary_analysis.py binary.exe --sbom-format both
```

### SBOM Only with Specific Format
```bash
python unified_binary_analysis.py binary.exe --only-sbom --sbom-format cyclonedx -o sbom.json
```

---

## Malware Detection

### Basic Malware Scan (No YARA)
```bash
python unified_binary_analysis.py binary.exe --only-malware
```
**Checks:** Entropy, suspicious imports, strings

### With YARA Rules (Single File)
```bash
python unified_binary_analysis.py binary.exe -y malware.yar
```

### With YARA Rules (Long Form)
```bash
python unified_binary_analysis.py binary.exe --yara-rules malware.yar
```

### With YARA Directory (Default: ./yara)
```bash
# Uses default ./yara directory
python unified_binary_analysis.py binary.exe

# Explicit directory
python unified_binary_analysis.py binary.exe -y /path/to/yara/rules/
```

### Custom High Entropy Threshold
```bash
python unified_binary_analysis.py binary.exe --high-entropy 7.0
```
**Default:** 7.5

### Custom Low Entropy Threshold
```bash
python unified_binary_analysis.py binary.exe --low-entropy 0.5
```
**Default:** 1.0

### Both Entropy Thresholds
```bash
python unified_binary_analysis.py binary.exe --high-entropy 7.0 --low-entropy 0.5
```

### Disable UTF-16 Strings
```bash
python unified_binary_analysis.py binary.exe --no-utf16
```
**Effect:** Faster scan, less thorough

### Fail on YARA Match
```bash
python unified_binary_analysis.py binary.exe -y rules.yar --fail-on-yara
```
**Exit Code:** 10 if YARA matches

### Complete Malware Setup
```bash
python unified_binary_analysis.py binary.exe \
  -y /path/to/rules/ \
  --high-entropy 7.2 \
  --low-entropy 0.8 \
  --fail-on-yara \
  --only-malware \
  -o malware.json \
  --verbose
```

---

## AI Report Generation

### Basic AI Report
```bash
export GROQ_API_KEY="gsk_..."
python unified_binary_analysis.py binary.exe --ai-report
```

### With API Key Inline
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --groq-key "gsk_..."
```

### Summary Mode
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --report-mode summary
```
**Output:** Executive summary (300 words)

### Remediation Mode
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --report-mode remediation
```
**Output:** Prioritized fixes with code examples

### Full Report Mode (Default)
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --report-mode report
```
**Output:** Complete technical analysis

### Custom Context Size
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --top-k 10
```
**Default:** 5 (higher = more detailed context)

### Complete AI Setup
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --groq-key "gsk_..." \
  --report-mode remediation \
  --top-k 8 \
  -o report.json \
  --verbose
```

---

## PDF Export

### Export AI Report to PDF
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --export-pdf report.pdf
```
**Requires:** AI report enabled

### PDF Only (No JSON File)
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --export-pdf report.pdf
```
**Output:** PDF + JSON to stdout

### PDF + JSON
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --export-pdf report.pdf \
  -o analysis.json
```
**Output:** Both files

### PDF with Custom Mode
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --report-mode remediation \
  --export-pdf remediation.pdf
```

---

## Email Notifications

### Gmail Preset
```bash
python unified_binary_analysis.py binary.exe \
  --email-to user@example.com \
  --email-from sender@gmail.com \
  --email-password "app_password" \
  --email-preset gmail
```

### Outlook Preset
```bash
python unified_binary_analysis.py binary.exe \
  --email-to user@example.com \
  --email-from sender@outlook.com \
  --email-password "password" \
  --email-preset outlook
```

### Yahoo Preset
```bash
python unified_binary_analysis.py binary.exe \
  --email-to user@example.com \
  --email-from sender@yahoo.com \
  --email-password "password" \
  --email-preset yahoo
```

### Custom SMTP Server
```bash
python unified_binary_analysis.py binary.exe \
  --email-to user@example.com \
  --email-from sender@company.com \
  --email-password "password" \
  --email-smtp-server smtp.company.com \
  --email-smtp-port 587
```

### Multiple Recipients
```bash
python unified_binary_analysis.py binary.exe \
  --email-to user1@example.com user2@example.com user3@example.com \
  --email-from sender@gmail.com \
  --email-password "password" \
  --email-preset gmail
```

### With CC
```bash
python unified_binary_analysis.py binary.exe \
  --email-to user@example.com \
  --email-cc boss@example.com manager@example.com \
  --email-from sender@gmail.com \
  --email-password "password" \
  --email-preset gmail
```

### Custom Subject
```bash
python unified_binary_analysis.py binary.exe \
  --email-to user@example.com \
  --email-from sender@gmail.com \
  --email-password "password" \
  --email-preset gmail \
  --email-subject "Critical: Production Binary Analysis"
```

### Attach JSON Report
```bash
python unified_binary_analysis.py binary.exe \
  -o report.json \
  --email-to user@example.com \
  --email-from sender@gmail.com \
  --email-password "password" \
  --email-preset gmail \
  --email-attach-json
```

### Attach PDF Report
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --export-pdf report.pdf \
  --email-to user@example.com \
  --email-from sender@gmail.com \
  --email-password "password" \
  --email-preset gmail \
  --email-attach-pdf
```

### Attach Both JSON and PDF
```bash
python unified_binary_analysis.py binary.exe \
  -o report.json \
  --ai-report \
  --export-pdf report.pdf \
  --email-to user@example.com \
  --email-from sender@gmail.com \
  --email-password "password" \
  --email-preset gmail \
  --email-attach-json \
  --email-attach-pdf
```

### Complete Email Setup
```bash
python unified_binary_analysis.py binary.exe \
  -o full_report.json \
  --ai-report \
  --export-pdf security_report.pdf \
  --email-to security@company.com audit@company.com \
  --email-cc management@company.com \
  --email-from secureforge@company.com \
  --email-password "$EMAIL_PASSWORD" \
  --email-preset gmail \
  --email-subject "Weekly Security Scan - Production Binary" \
  --email-attach-json \
  --email-attach-pdf
```

---

## CI/CD Integration

### Fail on High Risk
```bash
python unified_binary_analysis.py binary.exe --fail-on-high
```
**Exit Code:** 3 if risk > 0.7

### Fail on Medium Risk
```bash
python unified_binary_analysis.py binary.exe --fail-on-medium
```
**Exit Code:** 2 if risk > 0.4

### Custom Threshold
```bash
python unified_binary_analysis.py binary.exe --fail-threshold 0.6
```
**Exit Code:** 2/3 if risk > 0.6

### Multiple Thresholds
```bash
python unified_binary_analysis.py binary.exe \
  --fail-threshold 0.5 \
  --fail-on-high
```
**Effect:** Fails if risk > 0.5 OR High risk

### Complete CI/CD Setup
```bash
python unified_binary_analysis.py binary.exe \
  --only-malware \
  --only-hardening \
  -y ci_rules/ \
  --fail-on-yara \
  --fail-threshold 0.5 \
  -o ci_report.json
```

---

## Combined Workflows

### Complete Analysis (Everything)
```bash
python unified_binary_analysis.py binary.exe \
  -o full_analysis.json \
  --output-dir ./reports/ \
  --sbom-format both \
  -y yara_rules/ \
  --high-entropy 7.0 \
  --ai-report \
  --report-mode report \
  --export-pdf security_report.pdf \
  --email-to security@company.com \
  --email-from scanner@company.com \
  --email-password "$EMAIL_PASS" \
  --email-preset gmail \
  --email-attach-json \
  --email-attach-pdf \
  --fail-on-high \
  --verbose
```

### Quick Malware Check
```bash
python unified_binary_analysis.py binary.exe \
  --only-malware \
  -y rules.yar \
  --fail-on-yara \
  -o malware.json
```

### SBOM Compliance
```bash
python unified_binary_analysis.py binary.exe \
  --only-sbom \
  --sbom-format both \
  --output-dir ./sbom_reports/
```

### Hardening Validation
```bash
python unified_binary_analysis.py binary.exe \
  --only-hardening \
  --fail-on-high \
  -o hardening.json
```

### Weekly Automated Scan
```bash
python unified_binary_analysis.py /apps/production.bin \
  --ai-report \
  --report-mode summary \
  --export-pdf weekly_scan.pdf \
  --email-to team@company.com \
  --email-from scanner@company.com \
  --email-password "$EMAIL_PASS" \
  --email-preset gmail \
  --email-subject "Weekly Security Scan" \
  --email-attach-pdf
```

### Pre-deployment Check
```bash
python unified_binary_analysis.py build/artifact \
  --skip-sbom \
  -y production_rules/ \
  --fail-on-yara \
  --fail-on-medium \
  -o predeployment.json \
  --email-to devops@company.com \
  --email-from ci@company.com \
  --email-password "$EMAIL_PASS" \
  --email-preset gmail \
  --email-attach-json
```

### Forensics Analysis
```bash
python unified_binary_analysis.py suspicious.exe \
  --only-malware \
  --only-risk \
  -y malware_signatures/ \
  --high-entropy 6.5 \
  --ai-report \
  --report-mode report \
  --export-pdf forensics_report.pdf \
  --verbose
```

### Minimal Fast Check
```bash
python unified_binary_analysis.py binary.exe --only-hardening -o quick.json
```

### CI Pipeline Integration
```bash
python unified_binary_analysis.py $BUILD_ARTIFACT \
  --only-malware \
  --only-hardening \
  -y $CI_YARA_RULES \
  --fail-on-yara \
  --fail-threshold $RISK_THRESHOLD \
  -o $CI_REPORT_PATH \
  --email-to $NOTIFY_EMAIL \
  --email-from $CI_EMAIL \
  --email-password $EMAIL_PASSWORD \
  --email-preset gmail
```

### Risk Assessment Only
```bash
python unified_binary_analysis.py binary.exe \
  --only-risk \
  --only-hardening \
  -o risk_assessment.json
```

---

## Environment Variables

### Set GROQ API Key

**Linux/macOS:**
```bash
export GROQ_API_KEY="gsk_..."
```

**Windows CMD:**
```cmd
set GROQ_API_KEY=gsk_...
```

**Windows PowerShell:**
```powershell
$env:GROQ_API_KEY="gsk_..."
```

### Set Email Password

**Linux/macOS:**
```bash
export EMAIL_PASSWORD="app_password"
```

**Windows CMD:**
```cmd
set EMAIL_PASSWORD=app_password
```

**Windows PowerShell:**
```powershell
$env:EMAIL_PASSWORD="app_password"
```

### Use in Commands
```bash
python unified_binary_analysis.py binary.exe \
  --ai-report \
  --email-to user@example.com \
  --email-from sender@gmail.com \
  --email-password "$EMAIL_PASSWORD" \
  --email-preset gmail
```

---

## Exit Codes Reference

| Code | Level | Score | Condition |
|------|-------|-------|-----------|
| **0** | Low | 0.0-0.4 | Safe |
| **2** | Medium | 0.4-0.7 | Review needed |
| **3** | High | 0.7-1.0 | Critical |
| **10** | YARA | N/A | Malware |
| **1** | Error | N/A | Failed |

### Check Exit Code

**Linux/macOS:**
```bash
python unified_binary_analysis.py binary.exe
echo $?
```

**Windows CMD:**
```cmd
python unified_binary_analysis.py binary.exe
echo %ERRORLEVEL%
```

**Windows PowerShell:**
```powershell
python unified_binary_analysis.py binary.exe
echo $LASTEXITCODE
```

### Script Usage
```bash
#!/bin/bash
python unified_binary_analysis.py binary.exe --fail-on-high

case $? in
  0) echo "✅ Low risk" ;;
  2) echo "⚠️ Medium risk" ;;
  3) echo "🚨 High risk" ;;
  10) echo "🛑 Malware detected" ;;
  *) echo "❌ Error" ;;
esac
```

---

## Quick Copy-Paste Templates

### Template 1: Full Analysis
```bash
python unified_binary_analysis.py YOUR_BINARY \
  -o results.json \
  -y yara_rules/ \
  --ai-report \
  --export-pdf report.pdf \
  --verbose
```

### Template 2: CI/CD Gate
```bash
python unified_binary_analysis.py YOUR_BINARY \
  --only-malware \
  --only-hardening \
  --fail-on-high \
  --fail-on-yara \
  -o ci_report.json
```

### Template 3: Email Report
```bash
python unified_binary_analysis.py YOUR_BINARY \
  --ai-report \
  --export-pdf report.pdf \
  --email-to RECIPIENT@example.com \
  --email-from SENDER@gmail.com \
  --email-password "YOUR_APP_PASSWORD" \
  --email-preset gmail \
  --email-attach-pdf
```

### Template 4: SBOM Only
```bash
python unified_binary_analysis.py YOUR_BINARY \
  --only-sbom \
  --sbom-format both \
  -o sbom.json
```

---

**Total Documented Commands:** 100+  
**Possible Combinations:** 1000+

**🛡️ SecuriForge** - Every command documented!