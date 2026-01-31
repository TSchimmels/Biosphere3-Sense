# 🤖 AttackAgent - Complete Usage Guide

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Scan Modes](#scan-modes)
5. [All Command Line Flags](#all-command-line-flags)
6. [Standalone Commands](#standalone-commands)
7. [Usage Examples](#usage-examples)
8. [Whitelist Configuration](#whitelist-configuration)
9. [Understanding the Output](#understanding-the-output)
10. [Dashboard](#dashboard)
11. [Report Formats](#report-formats)
12. [Database Storage](#database-storage)
13. [Best Practices](#best-practices)
14. [Troubleshooting](#troubleshooting)

---

## Overview

AttackAgent is an advanced AI-powered security testing tool designed to perform comprehensive security assessments of web applications. It combines automated penetration testing with machine learning to identify vulnerabilities and provide actionable remediation guidance.

### Key Features
- 🔍 **Comprehensive Vulnerability Scanning** - Tests for SQL injection, XSS, authentication bypass, and more
- 🤖 **AI-Powered Learning** - Learns from each scan to improve accuracy
- 📊 **Multiple Report Formats** - Generates optimized JSON and PDF reports
- ⚡ **Concurrent Testing** - Fast parallel security testing
- 🎯 **Gray-Box Testing** - Can analyze source code when provided
- 📄 **Local File Analysis** - Scans configuration files for exposed credentials
- 🌐 **Live Dashboard** - Interactive web dashboard to view scan results
- 💾 **Database Storage** - Stores vulnerabilities in SQL Server for ML training
- 🔎 **Database Dashboard** - Browse all historical vulnerabilities with filtering, sorting, and detailed popup views

---

## Prerequisites

- **.NET 8.0 SDK** or later
- **Windows, Linux, or macOS**
- **Internet connection** (for testing remote targets)
- **SQL Server** (optional - for vulnerability database storage)

---

## Quick Start

```bash
# Navigate to the AttackAgent directory
cd AttackAgent

# Build the project
dotnet build

# Run a quick scan on your target
dotnet run -- http://localhost:3000 --quick
```

---

## Scan Modes

AttackAgent has **three scan modes** that determine how thorough and aggressive the testing will be:

### 🔵 DEFAULT MODE (Full Comprehensive Scan)
**Command:** `dotnet run -- <target-url>`

This is the **most thorough** scan mode. If you don't specify `--quick` or `--stealth`, this is what runs.

| Phase | What It Does | Duration |
|-------|--------------|----------|
| **1. Reconnaissance** | OSINT gathering, DNS enumeration, port scanning (1000+ ports), service fingerprinting, certificate analysis, directory enumeration, technology stack analysis | ~3-5 minutes |
| **2. File System Access** | Directory traversal testing, config file access, backup file discovery, source code access, sensitive data discovery, log/database/environment file access | ~1-2 minutes |
| **3. Application Discovery** | Endpoint discovery (Swagger/OpenAPI, black-box), technology detection, security feature analysis, credential scanning | ~2-5 minutes |
| **4. Advanced Exploitation** | Deep exploitation testing (currently skipped pending restoration) | - |
| **5. Security Testing** | AI-enhanced SQL injection, comprehensive XSS (reflected + stored), CORS testing, file security, security headers, rate limiting | ~2-5 minutes |
| **6. Cleanup** | Removes ALL test payloads and injected data from target | ~30 seconds |

**Best For:** Production security audits, thorough penetration testing, compliance requirements

**Example:**
```bash
dotnet run -- https://myapp.com --verbose
```

---

### ⚡ QUICK MODE (Fast Scan)
**Command:** `dotnet run -- <target-url> --quick`

A **faster scan** with reduced testing depth. Skips some reconnaissance and uses fewer test payloads.

| What's Different |
|-----------------|
| ✅ Runs all 6 phases but with reduced depth |
| ✅ Fewer port scan targets |
| ✅ Reduced XSS/SQLi payload count |
| ✅ Skips some advanced exploitation techniques |
| ✅ Still performs cleanup |

**Duration:** ~2-5 minutes (vs 10-15 minutes for full scan)

**Best For:** Quick security checks, CI/CD pipelines, initial assessments, development testing

**Example:**
```bash
dotnet run -- http://localhost:5285 --quick --verbose
```

---

### 🥷 STEALTH MODE (Passive Reconnaissance Only)
**Command:** `dotnet run -- <target-url> --stealth`

**Passive reconnaissance only** - no active exploitation or attack payloads sent.

| What It Does | What It Doesn't Do |
|--------------|-------------------|
| ✅ OSINT intelligence gathering | ❌ No SQL injection testing |
| ✅ DNS enumeration | ❌ No XSS testing |
| ✅ Basic port scanning | ❌ No active exploitation |
| ✅ Technology fingerprinting | ❌ No payload injection |
| ✅ Certificate analysis | ❌ No stored attack testing |

**Duration:** ~1-3 minutes

**Best For:** Initial reconnaissance, when you want minimal footprint, pre-engagement information gathering

**Example:**
```bash
dotnet run -- https://target.com --stealth --verbose
```

---

### 📊 Mode Comparison Table

| Feature | Default (Full) | Quick | Stealth |
|---------|---------------|-------|---------|
| **Reconnaissance** | Full (OSINT, DNS, ports, certs) | Reduced | Passive only |
| **Port Scanning** | 1000+ ports | Common ports | Basic |
| **Endpoint Discovery** | Full wordlist + API patterns | Reduced | None |
| **SQL Injection Testing** | AI-enhanced, multiple payloads | Reduced payloads | ❌ None |
| **XSS Testing** | Reflected + Stored, 1000+ tests | Reduced tests | ❌ None |
| **File Security Testing** | Full | Basic | ❌ None |
| **CORS Testing** | ✅ Yes | ✅ Yes | ❌ None |
| **Security Headers** | ✅ Yes | ✅ Yes | ❌ None |
| **Cleanup** | ✅ Full | ✅ Full | N/A |
| **Duration** | 10-15 min | 2-5 min | 1-3 min |
| **Detection Risk** | Higher | Medium | Low |

---

## All Command Line Flags

### Basic Syntax
```bash
dotnet run -- <target-url> [options]
```

### Scan Mode Flags

| Flag | Description |
|------|-------------|
| *(none)* | **DEFAULT:** Full comprehensive scan - most thorough testing |
| `--quick` | Quick mode - faster scan with reduced testing depth |
| `--stealth` | Stealth mode - passive reconnaissance only, no active attacks |

### Configuration Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--verbose` | Enable detailed logging output | `--verbose` |
| `--timeout <seconds>` | Set HTTP request timeout (default: 30s) | `--timeout 60` |
| `--output <directory>` | Specify output directory for reports (default: ./reports) | `--output ./my-reports` |

### Advanced Testing Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--source-code <path>` | **Gray-box testing:** Provide source code path for enhanced endpoint discovery | `--source-code ../MyApp` |
| `--local-files <files>` | Analyze local config files for exposed credentials (comma-separated) | `--local-files "appsettings.json,.env"` |

### Utility Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--cleanup-only` | Run cleanup operations only (remove test payloads from previous scans) | `--cleanup-only` |

---

## Standalone Commands

These commands run **without a target URL** and provide utility functions:

### 📊 `--dashboard` - Vulnerability Database Dashboard
```bash
dotnet run -- --dashboard
```

Launches an interactive web dashboard showing **ALL vulnerabilities** from the database across all scans.

**Features:**
- View all historical vulnerabilities
- Sort by any column (ID, Timestamp, Severity, Type, etc.)
- Filter by severity, type, or status
- Search through all vulnerabilities
- **Click any row** to see full details in a popup modal:
  - Complete vulnerability information
  - Payload and evidence
  - Recommended solution
- Filter options: All, Real Only (Hide FPs), Verified, False Positives, Pending Review

**Access:** Opens automatically at `http://localhost:5000`

---

### 📋 `--list-vulns` - List Vulnerabilities in Console
```bash
dotnet run -- --list-vulns
```

Prints all vulnerabilities from the database to the console. Useful for quick review without launching the dashboard.

**Output includes:**
- Vulnerability ID
- Scan ID
- Application URL
- Type and Severity
- Endpoint

---

### 🧹 `--cleanup-db` - Database Cleanup
```bash
dotnet run -- --cleanup-db
```

Cleans up the vulnerability database:
- Marks DoS (Denial of Service) vulnerabilities as false positives
- Removes duplicate XSS/SQLi entries (keeps highest confidence)
- Shows before/after statistics

---

## Usage Examples

### Example 1: Full Comprehensive Scan (DEFAULT)
```bash
dotnet run -- http://localhost:5285 --verbose
```
**What it does:** Most thorough testing - all phases, all payloads, full exploitation.

---

### Example 2: Quick Security Check
```bash
dotnet run -- http://localhost:5285 --quick --verbose
```
**What it does:** Faster scan with reduced depth - good for regular checks.

---

### Example 3: Stealth Reconnaissance
```bash
dotnet run -- https://target.com --stealth --verbose
```
**What it does:** Passive reconnaissance only - no attacks, minimal detection risk.

---

### Example 4: Gray-Box Testing with Source Code
```bash
dotnet run -- https://myapp.com --source-code ./MyAppSource --verbose
```
**What it does:** 
- Analyzes source code to discover ALL endpoints (not just publicly visible ones)
- Extracts parameters from code
- Combines static analysis with runtime testing
- **Maximum coverage** - finds hidden endpoints and parameters

---

### Example 5: Local Configuration File Analysis
```bash
dotnet run -- http://localhost:5285 --local-files "appsettings.json,.env,config.json" --verbose
```
**What it does:**
- Scans web application normally
- **Also analyzes local config files** for exposed credentials
- Detects API keys, passwords, connection strings, secrets

---

### Example 6: Extended Timeout for Slow Servers
```bash
dotnet run -- https://slow-server.com --timeout 120 --verbose
```
**What it does:** Sets 120-second timeout for HTTP requests (default is 30s).

---

### Example 7: Custom Output Directory
```bash
dotnet run -- http://localhost:5285 --output ./security-reports --verbose
```
**What it does:** Saves all reports to `./security-reports` instead of default `./reports`.

---

### Example 8: Cleanup Only (Remove Test Data)
```bash
dotnet run -- https://myapp.com --cleanup-only
```
**What it does:** Removes test payloads from a previous scan without running new tests.

---

### Example 9: Launch Database Dashboard
```bash
dotnet run -- --dashboard
```
**What it does:** Opens interactive dashboard to browse ALL vulnerabilities from database.

---

### Example 10: Combined Flags
```bash
dotnet run -- https://myapp.com --quick --source-code ./src --local-files ".env" --verbose --timeout 60
```
**What it does:** Quick scan + source code analysis + local file check + verbose output + 60s timeout.

---

## Whitelist Configuration

AttackAgent requires targets to be whitelisted before testing. This is a security feature to prevent unauthorized testing.

### Whitelist File
Edit `whitelist.txt` in the AttackAgent directory:

```
# Add your authorized URLs below this line:
https://your-staging-server.com/
https://your-production-app.com/api/
http://localhost:8080
```

### Automatically Allowed (No Whitelist Needed)
- **Localhost:** `localhost`, `127.0.0.1`, `::1`
- **Private IPs:** `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`
- **JetStream Cloud:** `aicore-app-server.tra220030.projects.jetstream-cloud.org/*`

### Format Rules
- One URL per line
- Lines starting with `#` are comments
- Supports `http://` and `https://`
- With or without trailing slash

---

## Understanding the Output

### Execution Phases

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Reconnaissance** | OSINT, DNS, port scanning, technology analysis |
| 2 | **File System Access** | Directory traversal, config/backup/source files |
| 3 | **Application Discovery** | Endpoint discovery, technology detection |
| 4 | **Advanced Exploitation** | Deep exploitation (pending restoration) |
| 5 | **Security Testing** | SQL injection, XSS, CORS, headers, rate limiting |
| 6 | **Cleanup** | Remove all test payloads |

### Vulnerability Severity Levels

| Level | Icon | Priority | Examples |
|-------|------|----------|----------|
| **Critical** | 🔴 | Immediate | SQL injection, exposed credentials, RCE |
| **High** | 🟠 | High | XSS, authentication bypass, path traversal |
| **Medium** | 🟡 | Medium | Missing security headers, CORS issues |
| **Low** | 🟢 | Low | Minor configuration issues |
| **Info** | ℹ️ | Informational | Technology fingerprinting, version disclosure |

---

## Dashboard

### Two Types of Dashboards

#### 1. Scan Dashboard (After Each Scan)
- Opens automatically after scan completes
- Shows vulnerabilities from **current scan only**
- URL: `http://localhost:5001`

#### 2. Database Dashboard (Standalone)
- Launch with `--dashboard` flag
- Shows **ALL vulnerabilities** from all scans
- URL: `http://localhost:5000`

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Sort** | Click any column header to sort ascending/descending |
| **Filter by Severity** | Critical, High, Medium, Low, Info |
| **Filter by Type** | XSS, SQL Injection, etc. |
| **Filter by Status** | Real Only, Verified, False Positives, Pending |
| **Search** | Search across all fields |
| **Click Row** | Opens detailed popup with full vulnerability info |

### Popup Modal Details
When you click a vulnerability row, you see:
- Complete metadata (ID, Scan ID, Timestamp, Application)
- Severity with colored badge
- Full endpoint and HTTP method
- Parameter that was vulnerable
- **Complete payload** that was used
- **Evidence** of the vulnerability
- Status (Verified/False Positive/Pending)
- **Recommended solution** for remediation

---

## Report Formats

Reports are saved in `reports/` directory:

```
reports/
├── pdf/          # Professional PDF reports
└── optimized/    # AI-optimized JSON + executive summaries
```

### Report Types

| Type | Location | Description |
|------|----------|-------------|
| **Optimized JSON** | `reports/optimized/optimized-security-report-*.json` | Primary report - deduplicated, filtered, best quality |
| **Executive Summary** | `reports/optimized/executive-summary-*.txt` | High-level summary for management |
| **PDF Report** | `reports/pdf/security-report-*.pdf` | Professional presentation format |

### Automatic Optimization
- **Deduplication:** Removes duplicate findings (typically 50-95% reduction)
- **False Positive Filtering:** Filters low-confidence findings
- **Confidence Scoring:** Assigns confidence scores to all findings

---

## Database Storage

### Schema
```sql
CREATE TABLE AttackAgentVulnerabilities (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    ScanId NVARCHAR(50) NOT NULL,           -- Unique scan session ID
    ApplicationScanned NVARCHAR(500) NULL,   -- Full URL of scanned app
    ScanTime DATETIME2 NULL,                 -- Timestamp
    VulnerabilityType NVARCHAR(50) NOT NULL,
    Severity NVARCHAR(20) NOT NULL,
    Confidence DECIMAL(3,2) NOT NULL,
    Endpoint NVARCHAR(500) NULL,
    Method NVARCHAR(10) NULL,
    Parameter NVARCHAR(200) NULL,
    Payload NVARCHAR(2000) NULL,
    Evidence NVARCHAR(MAX) NULL,
    FalsePositive BIT NOT NULL DEFAULT 0,
    Verified BIT NOT NULL DEFAULT 0
);
```

### Database Commands Summary

| Command | Description |
|---------|-------------|
| `--dashboard` | Browse all vulnerabilities in web UI |
| `--list-vulns` | Print all vulnerabilities to console |
| `--cleanup-db` | Remove false positives and duplicates |

---

## Best Practices

### 1. Start with Quick Mode
```bash
dotnet run -- http://localhost:3000 --quick --verbose
```
Verify target is accessible before running full scan.

### 2. Use Source Code When Available
```bash
dotnet run -- https://myapp.com --source-code ./MyApp --verbose
```
Gets **significantly better coverage** by finding hidden endpoints.

### 3. Check Configuration Files
```bash
dotnet run -- http://localhost:3000 --local-files "appsettings.json,.env" --verbose
```
Catches exposed credentials in config files.

### 4. Review the Dashboard
Use `--dashboard` to review all findings. Click each vulnerability for details and solutions.

### 5. Maintain Database Quality
```bash
dotnet run -- --cleanup-db
```
Periodically clean up false positives and duplicates.

---

## Troubleshooting

### Common Issues

| Error | Solution |
|-------|----------|
| "Target not in whitelist" | Add URL to `whitelist.txt` |
| Connection timeout | Use `--timeout 120` for slower servers |
| Dashboard won't open | Kill existing process: `taskkill /F /IM AttackAgent.exe` |
| Database errors | Verify SQL Server is running and connection string is correct |

### Debug Mode
```bash
dotnet run -- http://example.com --verbose
```

### Log Levels
- `[INF]` - Information (normal)
- `[WRN]` - Warning (non-critical)
- `[ERR]` - Error (critical)

---

## Quick Reference Card

```bash
# === SCAN MODES ===
dotnet run -- <url>                    # DEFAULT: Full comprehensive scan
dotnet run -- <url> --quick            # QUICK: Faster, reduced depth
dotnet run -- <url> --stealth          # STEALTH: Passive recon only

# === STANDALONE COMMANDS ===
dotnet run -- --dashboard              # Open vulnerability database dashboard
dotnet run -- --list-vulns             # List all vulnerabilities in console
dotnet run -- --cleanup-db             # Clean up database

# === COMMON OPTIONS ===
--verbose                              # Detailed logging
--timeout 60                           # Set request timeout
--output ./reports                     # Set output directory
--source-code ./src                    # Gray-box testing with source
--local-files "appsettings.json,.env"  # Scan local config files
--cleanup-only                         # Remove test data only

# === EXAMPLE COMBINATIONS ===
dotnet run -- http://localhost:5285 --quick --verbose
dotnet run -- https://myapp.com --source-code ./src --verbose
dotnet run -- https://target.com --stealth --verbose
dotnet run -- https://myapp.com --cleanup-only
```

---

## Security Considerations

⚠️ **Important:** Always ensure you have proper authorization before testing any system.

- Only test systems you own or have explicit permission to test
- Unauthorized testing may violate laws and regulations
- Get written authorization for production systems
- Use the whitelist to control which targets can be tested
- Reports contain sensitive information - secure appropriately

---

**Last Updated:** December 2025  
**Version:** 3.1
