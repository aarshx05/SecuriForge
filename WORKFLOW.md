# 🔄 SecuriForge - GitHub Actions Workflows

> **Production-ready CI/CD workflows for automated binary security scanning**

---

## 📋 Table of Contents

1. [Quick Setup](#quick-setup)
2. [Workflow 1: Complete Production Pipeline](#workflow-1-complete-production-pipeline)
3. [Workflow 2: Simple Security Gate](#workflow-2-simple-security-gate)
4. [Configuration Guide](#configuration-guide)
5. [Workflow Features Explained](#workflow-features-explained)

---

## Quick Setup

### Step 1: Add GitHub Secrets

Go to: **Settings → Secrets and variables → Actions → New repository secret**

Add these secrets:

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `GROQ_API_KEY` | GROQ API key from https://console.groq.com/ | For AI reports |
| `EMAIL_APP_PASSWORD` | Gmail app password | For email notifications |
| `GHCR_PAT` | GitHub Personal Access Token | For private Docker images |

### Step 2: Create Workflow File

Create `.github/workflows/security-scan.yml` (see below)

### Step 3: Update Binary Path

Replace `/workspace/build/your-app.exe` with your actual binary path

### Step 4: Push and Run

Workflow triggers automatically on push/PR

---

## Workflow 1: Complete Production Pipeline

**File:** `.github/workflows/securiforge-complete.yml`

**Features:**
- ✅ Fast scan on every push/PR
- ✅ AI report on main branch
- ✅ PR comments with findings
- ✅ Email notifications for Medium/High risk
- ✅ Artifact uploads
- ✅ Security baseline management
- ✅ Multi-job pipeline with outputs

```yaml
name: SecuriForge Complete Security Pipeline

# ============================================================
# TRIGGER CONDITIONS
# ============================================================
on:
  # Trigger on push to main/develop branches
  push:
    branches:
      - main
      - develop
    paths:
      - 'build/**'        # Only when build artifacts change
      - 'src/**'          # Or source code changes
      - '.github/workflows/**'
  
  # Trigger on pull requests
  pull_request:
    branches:
      - main
      - develop
  
  # Allow manual workflow dispatch
  workflow_dispatch:
    inputs:
      binary_path:
        description: 'Path to binary (relative to repo root)'
        required: false
        default: 'build/app.exe'
      risk_threshold:
        description: 'Risk threshold (0.0-1.0)'
        required: false
        default: '0.7'
      enable_email:
        description: 'Send email notification'
        type: boolean
        required: false
        default: false

# Cancel in-progress runs of same workflow on same branch
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

# ============================================================
# ENVIRONMENT VARIABLES (workflow-level)
# ============================================================
env:
  DOCKER_IMAGE: ghcr.io/aarshx05/securiforge:latest
  BINARY_PATH: build/app.exe
  REPORTS_DIR: reports

jobs:
  # ============================================================
  # JOB 1: FAST SECURITY SCAN
  # Runs on every push/PR for quick feedback
  # ============================================================
  fast-scan:
    name: Fast Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 15
    
    # Job outputs for downstream jobs
    outputs:
      risk-level: ${{ steps.analyze.outputs.risk-level }}
      risk-score: ${{ steps.analyze.outputs.risk-score }}
      malware-risk: ${{ steps.analyze.outputs.malware-risk }}
      hardening-passed: ${{ steps.analyze.outputs.hardening-passed }}
      hardening-total: ${{ steps.analyze.outputs.hardening-total }}
      yara-matches: ${{ steps.analyze.outputs.yara-matches }}
    
    steps:
      # ----------------------------------------------------------
      # SETUP STEPS
      # ----------------------------------------------------------
      - name: 📥 Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 1  # Shallow clone for speed
      
      - name: 🐳 Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: 🔐 Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: 📦 Pull SecuriForge Docker Image
        run: |
          echo "Pulling Docker image: $DOCKER_IMAGE"
          docker pull $DOCKER_IMAGE
      
      - name: 📁 Create Reports Directory
        run: mkdir -p $REPORTS_DIR
      
      # ----------------------------------------------------------
      # OPTIONAL: Build Test Binary (for testing workflow)
      # Remove this section in production - use your actual binary
      # ----------------------------------------------------------
      - name: 🛠️ Install mingw-w64 (Optional - for test binary)
        if: github.event_name == 'workflow_dispatch' || github.ref == 'refs/heads/develop'
        run: |
          sudo apt-get update
          sudo apt-get install -y mingw-w64
      
      - name: 🧪 Create Test Binary (Optional)
        if: github.event_name == 'workflow_dispatch' || github.ref == 'refs/heads/develop'
        run: |
          cat << 'EOF' > test.c
          #include <stdio.h>
          #include <windows.h>
          int main() {
              HMODULE kernel32 = LoadLibrary("kernel32.dll");
              FARPROC proc = GetProcAddress(kernel32, "CreateProcessA");
              printf("Test Binary v1.0\n");
              return 0;
          }
          EOF
          mkdir -p build
          x86_64-w64-mingw32-gcc test.c -o build/app.exe
          echo "✅ Test binary created: $(ls -lh build/app.exe)"
      
      # ----------------------------------------------------------
      # MAIN SECURITY ANALYSIS
      # ----------------------------------------------------------
      - name: 🔍 Run Security Analysis
        id: analyze
        run: |
          # Determine binary path
          BINARY="${{ github.event.inputs.binary_path || env.BINARY_PATH }}"
          
          echo "Analyzing binary: $BINARY"
          echo "Reports directory: $REPORTS_DIR"
          
          # Run SecuriForge in Docker
          # Note: We capture exit code but don't fail immediately
          docker run --rm \
            -v $PWD:/workspace \
            $DOCKER_IMAGE \
            python3 unified_binary_analysis.py \
              /workspace/$BINARY \
              -o /workspace/$REPORTS_DIR/security-report.json \
              --skip-ai-report \
              --fail-on-high \
              --verbose || EXIT_CODE=$?
          
          # Check if report was generated
          if [ ! -f "$REPORTS_DIR/security-report.json" ]; then
            echo "::error::Security report not generated"
            exit 1
          fi
          
          # Extract metrics using jq
          RISK_LEVEL=$(jq -r '._meta.overall_risk_interpretation // "Unknown"' $REPORTS_DIR/security-report.json)
          RISK_SCORE=$(jq -r '._meta.overall_risk_score // 0' $REPORTS_DIR/security-report.json)
          MALWARE_RISK=$(jq -r '.malware.findings.overall_risk.interpretation // "N/A"' $REPORTS_DIR/security-report.json)
          YARA_MATCHES=$(jq -r '.malware.findings.yara.matches | length // 0' $REPORTS_DIR/security-report.json)
          
          # Hardening checks
          HARDENING_PASSED=$(jq '[.hardening | to_entries[] | select(.key != "_meta") | select(.value.passed == true)] | length' $REPORTS_DIR/security-report.json)
          HARDENING_TOTAL=$(jq '[.hardening | to_entries[] | select(.key != "_meta")] | length' $REPORTS_DIR/security-report.json)
          
          # Set job outputs
          echo "risk-level=$RISK_LEVEL" >> $GITHUB_OUTPUT
          echo "risk-score=$RISK_SCORE" >> $GITHUB_OUTPUT
          echo "malware-risk=$MALWARE_RISK" >> $GITHUB_OUTPUT
          echo "yara-matches=$YARA_MATCHES" >> $GITHUB_OUTPUT
          echo "hardening-passed=$HARDENING_PASSED" >> $GITHUB_OUTPUT
          echo "hardening-total=$HARDENING_TOTAL" >> $GITHUB_OUTPUT
          
          # Add to job summary
          echo "## 🔒 Security Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Metric | Value |" >> $GITHUB_STEP_SUMMARY
          echo "|--------|-------|" >> $GITHUB_STEP_SUMMARY
          echo "| **Overall Risk** | **$RISK_LEVEL** ($RISK_SCORE) |" >> $GITHUB_STEP_SUMMARY
          echo "| **Malware Risk** | $MALWARE_RISK |" >> $GITHUB_STEP_SUMMARY
          echo "| **YARA Matches** | $YARA_MATCHES |" >> $GITHUB_STEP_SUMMARY
          echo "| **Hardening** | $HARDENING_PASSED/$HARDENING_TOTAL passed |" >> $GITHUB_STEP_SUMMARY
          echo "| **Binary** | \`$(basename $BINARY)\` |" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          
          # Log results
          echo "✅ Analysis complete:"
          echo "   Risk Level: $RISK_LEVEL ($RISK_SCORE)"
          echo "   Malware Risk: $MALWARE_RISK"
          echo "   YARA Matches: $YARA_MATCHES"
          echo "   Hardening: $HARDENING_PASSED/$HARDENING_TOTAL"
          
          # Exit with captured code (or 0 if not set)
          exit ${EXIT_CODE:-0}
        continue-on-error: true
      
      # ----------------------------------------------------------
      # UPLOAD ARTIFACTS
      # ----------------------------------------------------------
      - name: 📤 Upload Security Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: ${{ env.REPORTS_DIR }}/security-report.json
          retention-days: 90
      
      # ----------------------------------------------------------
      # EVALUATE THRESHOLDS
      # ----------------------------------------------------------
      - name: ⚖️ Evaluate Security Threshold
        if: always()
        run: |
          RISK_LEVEL="${{ steps.analyze.outputs.risk-level }}"
          RISK_SCORE="${{ steps.analyze.outputs.risk-score }}"
          YARA_MATCHES="${{ steps.analyze.outputs.yara-matches }}"
          
          echo "Risk Assessment:"
          echo "  Level: $RISK_LEVEL"
          echo "  Score: $RISK_SCORE"
          echo "  YARA Matches: $YARA_MATCHES"
          
          # Check for YARA matches (highest priority)
          if [ "$YARA_MATCHES" -gt 0 ]; then
            echo "::error::🛑 YARA rules matched - potential malware detected!"
            echo "YARA_ALERT=true" >> $GITHUB_ENV
            exit 10
          fi
          
          # Check risk level
          if [ "$RISK_LEVEL" = "High" ]; then
            echo "::error::❌ High security risk detected - blocking deployment"
            exit 3
          elif [ "$RISK_LEVEL" = "Medium" ]; then
            echo "::warning::⚠️ Medium security risk - manual review recommended"
            # Don't fail - allow with warning
          else
            echo "::notice::✅ Low security risk - safe to proceed"
          fi
  
  # ============================================================
  # JOB 2: AI-POWERED DETAILED REPORT
  # Only runs on main branch or manual trigger
  # ============================================================
  ai-report:
    name: Generate AI Report
    runs-on: ubuntu-latest
    needs: fast-scan
    # Conditional execution
    if: |
      (github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch') &&
      needs.fast-scan.result == 'success'
    timeout-minutes: 10
    
    steps:
      - name: 📥 Checkout Repository
        uses: actions/checkout@v4
      
      - name: 📦 Pull SecuriForge Image
        run: docker pull $DOCKER_IMAGE
      
      - name: 📥 Download Security Report
        uses: actions/download-artifact@v4
        with:
          name: security-report
          path: ${{ env.REPORTS_DIR }}
      
      - name: 🤖 Generate AI-Powered Report
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
        run: |
          mkdir -p ai-reports
          
          # Check if GROQ_API_KEY is set
          if [ -z "$GROQ_API_KEY" ]; then
            echo "::warning::GROQ_API_KEY not set - skipping AI report"
            exit 0
          fi
          
          echo "Generating AI report..."
          
          docker run --rm \
            -v $PWD:/workspace \
            -e GROQ_API_KEY="$GROQ_API_KEY" \
            $DOCKER_IMAGE \
            python3 modules/report_gen.py \
              /workspace/$REPORTS_DIR/security-report.json \
              --mode report \
              --smart \
              --quick \
              --output /workspace/ai-reports/ai-report.json \
              --verbose
          
          echo "✅ AI report generated"
      
      - name: 📤 Upload AI Report
        uses: actions/upload-artifact@v4
        with:
          name: ai-report
          path: ai-reports/
          retention-days: 30
  
  # ============================================================
  # JOB 3: COMMENT ON PULL REQUEST
  # Posts formatted security findings on PR
  # ============================================================
  pr-comment:
    name: PR Security Comment
    runs-on: ubuntu-latest
    needs: fast-scan
    if: github.event_name == 'pull_request'
    permissions:
      pull-requests: write
    
    steps:
      - name: 📥 Download Security Report
        uses: actions/download-artifact@v4
        with:
          name: security-report
          path: .
      
      - name: 💬 Post PR Comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            
            // Read and parse report
            let report;
            try {
              report = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
            } catch (e) {
              console.error('Failed to read report:', e);
              return;
            }
            
            // Extract metrics
            const riskLevel = report._meta?.overall_risk_interpretation || 'Unknown';
            const riskScore = report._meta?.overall_risk_score || 0;
            const binaryName = report._meta?.binary_name || 'Unknown';
            
            // Risk emoji
            const riskEmoji = {
              'Low': '✅',
              'Medium': '⚠️',
              'High': '🚨',
              'Unknown': '❓'
            }[riskLevel] || '❓';
            
            // Malware metrics
            const malwareRisk = report.malware?.findings?.overall_risk?.interpretation || 'N/A';
            const yaraMatches = report.malware?.findings?.yara?.matches?.length || 0;
            const suspiciousImports = report.malware?.findings?.suspicious_imports?.length || 0;
            
            // Hardening metrics
            const hardening = report.hardening || {};
            const checks = Object.keys(hardening).filter(k => k !== '_meta');
            const passed = checks.filter(k => hardening[k]?.passed).length;
            
            // SBOM metrics
            const sbomPackages = report.sbom?.spdx?.packages?.length || 0;
            
            // Build detailed comment
            const comment = `## ${riskEmoji} SecuriForge Security Scan Results
            
**Binary:** \`${binaryName}\`  
**Commit:** \`${context.sha.substring(0, 7)}\`  
**Branch:** \`${context.ref.replace('refs/heads/', '')}\`

### 📊 Overall Assessment

| Metric | Value |
|--------|-------|
| **Overall Risk** | **${riskLevel}** (${riskScore}) |
| **Malware Risk** | ${malwareRisk} |
| **YARA Matches** | ${yaraMatches} ${yaraMatches > 0 ? '⚠️' : '✅'} |
| **Hardening Checks** | ${passed}/${checks.length} passed |
| **Suspicious Imports** | ${suspiciousImports} |
| **SBOM Packages** | ${sbomPackages} |

<details>
<summary>🔍 Detailed Findings</summary>

### Hardening Status
${checks.map(check => {
  const result = hardening[check];
  const status = result?.passed ? '✅' : '❌';
  const reason = result?.reason || 'No details';
  return \`- \${status} **\${check}**: \${reason}\`;
}).join('\n')}

### Malware Detection
${yaraMatches > 0 ? `⚠️ **Warning:** ${yaraMatches} YARA rule(s) matched` : '✅ No YARA matches detected'}  
${suspiciousImports > 0 ? `⚠️ Found ${suspiciousImports} suspicious import(s)` : '✅ No suspicious imports'}

### Risk Level Interpretation
${riskLevel === 'High' ? '🚨 **Action Required:** High security risk detected! Review findings before merging.' : ''}
${riskLevel === 'Medium' ? '⚠️ **Review Recommended:** Medium risk level detected. Consider security improvements.' : ''}
${riskLevel === 'Low' ? '✅ **All Clear:** Low security risk. Safe to proceed with merge.' : ''}

</details>

---

📥 **Full Reports:** Download from [workflow artifacts](${context.payload.repository.html_url}/actions/runs/${context.runId})  
🔒 **Powered by:** [SecuriForge](https://github.com/your-org/securiforge)
            `;
            
            // Post comment
            try {
              await github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: comment
              });
              console.log('✅ PR comment posted successfully');
            } catch (e) {
              console.error('Failed to post comment:', e);
            }
  
  # ============================================================
  # JOB 4: EMAIL NOTIFICATION
  # Sends email for Medium/High risk on main branch
  # ============================================================
  email-notification:
    name: Send Email Report
    runs-on: ubuntu-latest
    needs: [fast-scan, ai-report]
    # Only run on main AND if risk is Medium/High
    if: |
      github.ref == 'refs/heads/main' &&
      (needs.fast-scan.outputs.risk-level == 'High' || 
       needs.fast-scan.outputs.risk-level == 'Medium' ||
       github.event.inputs.enable_email == 'true')
    
    steps:
      - name: 📥 Checkout Repository
        uses: actions/checkout@v4
      
      - name: 📦 Pull SecuriForge Image
        run: docker pull $DOCKER_IMAGE
      
      - name: 📥 Download Reports
        uses: actions/download-artifact@v4
        with:
          pattern: '*-report'
          path: ${{ env.REPORTS_DIR }}
          merge-multiple: true
      
      - name: 📧 Send Email Notification
        env:
          EMAIL_PASSWORD: ${{ secrets.EMAIL_APP_PASSWORD }}
        run: |
          # Check if email credentials are configured
          if [ -z "$EMAIL_PASSWORD" ]; then
            echo "::warning::EMAIL_APP_PASSWORD not set - skipping email"
            exit 0
          fi
          
          # Extract binary name
          BINARY_NAME=$(jq -r '._meta.binary_name // "unknown"' $REPORTS_DIR/security-report.json)
          
          # Determine email subject based on risk
          RISK_LEVEL="${{ needs.fast-scan.outputs.risk-level }}"
          if [ "$RISK_LEVEL" = "High" ]; then
            SUBJECT="🚨 HIGH RISK: $BINARY_NAME Security Alert"
          elif [ "$RISK_LEVEL" = "Medium" ]; then
            SUBJECT="⚠️ MEDIUM RISK: $BINARY_NAME Security Review Required"
          else
            SUBJECT="ℹ️ Security Scan: $BINARY_NAME"
          fi
          
          echo "Sending email notification..."
          echo "  Subject: $SUBJECT"
          echo "  Risk Level: $RISK_LEVEL"
          
          # Send email with attached report
          docker run --rm \
            -v $PWD:/workspace \
            -e EMAIL_PASSWORD="$EMAIL_PASSWORD" \
            $DOCKER_IMAGE \
            python3 unified_binary_analysis.py \
              /workspace/$BINARY_PATH \
              --skip-sbom \
              --skip-hardening \
              --skip-malware \
              --skip-risk \
              --email-to security@company.com devops@company.com \
              --email-from ci-scanner@company.com \
              --email-password "$EMAIL_PASSWORD" \
              --email-preset gmail \
              --email-subject "$SUBJECT" \
              --email-attach-json || echo "Email sending failed (non-critical)"
          
          echo "✅ Email notification sent"
  
  # ============================================================
  # JOB 5: UPDATE SECURITY BASELINE
  # Manual trigger only - updates baseline for comparison
  # ============================================================
  update-baseline:
    name: Update Security Baseline
    runs-on: ubuntu-latest
    needs: fast-scan
    # Only on manual trigger
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'
    
    steps:
      - name: 📥 Checkout Repository
        uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: 📥 Download Security Report
        uses: actions/download-artifact@v4
        with:
          name: security-report
          path: .
      
      - name: 📝 Update Baseline File
        run: |
          mkdir -p baselines
          cp security-report.json baselines/main-baseline.json
          
          echo "✅ Baseline updated"
          echo "Risk Level: ${{ needs.fast-scan.outputs.risk-level }}"
          echo "Risk Score: ${{ needs.fast-scan.outputs.risk-score }}"
      
      - name: 💾 Commit and Push Baseline
        run: |
          git config user.name "SecuriForge Bot"
          git config user.email "bot@securiforge.local"
          git add baselines/main-baseline.json
          git commit -m "chore: update security baseline [skip ci]

          Risk Level: ${{ needs.fast-scan.outputs.risk-level }}
          Risk Score: ${{ needs.fast-scan.outputs.risk-score }}
          Commit: ${{ github.sha }}"
          git push
```

---

## Workflow 2: Simple Security Gate

**File:** `.github/workflows/securiforge-simple.yml`

**Features:**
- ✅ Minimal setup - one job
- ✅ Fast execution (~2 minutes)
- ✅ Fail on high risk
- ✅ Upload reports

```yaml
name: SecuriForge Simple Security Gate

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 10
    
    steps:
      # Checkout code
      - name: Checkout
        uses: actions/checkout@v4
      
      # Login to Docker registry
      - name: Docker Login
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      # Pull SecuriForge image
      - name: Pull Image
        run: docker pull ghcr.io/aarshx05/securiforge:latest
      
      # Create test binary (REMOVE IN PRODUCTION - use your actual binary)
      - name: Create Test Binary
        run: |
          sudo apt-get update && sudo apt-get install -y mingw-w64
          echo 'int main() { return 0; }' > test.c
          x86_64-w64-mingw32-gcc test.c -o build/app.exe
          mkdir -p reports
      
      # Run analysis
      - name: Run SecuriForge
        run: |
          docker run --rm -v $PWD:/workspace \
            ghcr.io/aarshx05/securiforge:latest \
            python3 unified_binary_analysis.py \
              /workspace/build/app.exe \
              -o /workspace/reports/security-report.json \
              --fail-on-high \
              --verbose
      
      # Upload report
      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: reports/security-report.json
```

---

## Configuration Guide

### Required Secrets

| Secret | How to Get | Usage |
|--------|-----------|-------|
| `GROQ_API_KEY` | 1. Go to https://console.groq.com/<br>2. Sign up/Login<br>3. Navigate to API Keys<br>4. Create new key | AI report generation |
| `EMAIL_APP_PASSWORD` | **Gmail:**<br>1. Enable 2FA<br>2. Go to Google Account → Security<br>3. App passwords<br>4. Generate for "Mail" | Email notifications |
| `GITHUB_TOKEN` | Auto-provided by GitHub Actions | Docker registry login |

### Environment Variables

Set in workflow file or repository settings:

```yaml
env:
  DOCKER_IMAGE: ghcr.io/aarshx05/securiforge:latest
  BINARY_PATH: build/your-app.exe
  REPORTS_DIR: reports
  # Add your custom variables here
```

### Customizing Binary Path

**Option 1: Hardcode in workflow**
```yaml
env:
  BINARY_PATH: dist/production-app.exe
```

**Option 2: Use workflow input**
```yaml
on:
  workflow_dispatch:
    inputs:
      binary_path:
        description: 'Binary path'
        default: 'build/app.exe'
```

**Option 3: Auto-detect**
```yaml
- name: Find Binary
  run: |
    BINARY=$(find build/ -name "*.exe" -type f | head -n 1)
    echo "BINARY_PATH=$BINARY" >> $GITHUB_ENV
```

---

## Workflow Features Explained

### 1. Conditional Execution

```yaml
if: |
  github.ref == 'refs/heads/main' ||
  github.event_name == 'workflow_dispatch'
```
**Purpose:** Only run expensive jobs (AI report, email) on main branch

### 2. Job Outputs

```yaml
outputs:
  risk-level: ${{ steps.analyze.outputs.risk-level }}
```
**Purpose:** Pass data between jobs

### 3. Continue on Error

```yaml
continue-on-error: true
```
**Purpose:** Don't fail workflow immediately - evaluate results first

### 4. Artifact Upload

```yaml
uses: actions/upload-artifact@v4
with:
  retention-days: 90
```
**Purpose:** Store reports for 90 days, download from Actions tab

### 5. PR Comments

```yaml
permissions:
  pull-requests: write
```
**Purpose:** Allow workflow to post comments on PRs

### 6. Timeout

```yaml
timeout-minutes: 15
```
**Purpose:** Prevent hung jobs from consuming runner time

---

**📖 For detailed command reference, see [COMMANDS.md](COMMANDS.md)**  
**📘 For API documentation, see README.md**

**🛡️ SecuriForge** - Secure your CI/CD pipeline!