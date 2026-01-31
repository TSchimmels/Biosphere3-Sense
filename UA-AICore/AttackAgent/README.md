# 🤖 AttackAgent

An advanced AI-powered security testing tool for web applications. Combines automated penetration testing with machine learning to identify vulnerabilities and provide actionable remediation guidance.

![.NET](https://img.shields.io/badge/.NET-8.0-purple)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## 📌 Quick Start for Cursor Users

> **For testing purposes:** If you are using Cursor, ask it to look over AttackAgent and read the file `HOW_TO_USE_ATTACKAGENT.md` - it should understand how to run it on your web app.
>
> **You will need to provide:**
> 1. A URL to your locally or remotely hosted web app (must be running separately so it can be tested)
> 2. Optionally, the location of the source code for gray-box testing
>
> **To find reports:** Look under `reports/pdf/` for PDF reports or `reports/optimized/` for JSON reports.
>
> **To self-secure your app:** Give the JSON report (`reports/optimized/`) to Cursor and it can help secure your web app. JSON files are formatted to be easily read and understood by AI assistants.
>
> **Questions?** Contact David, or ask Cursor after it scans through AttackAgent to understand how it works.

---

## ✨ Features

- 🔍 **Comprehensive Vulnerability Scanning** - SQL injection, XSS, authentication bypass, path traversal, and more
- 🤖 **AI-Powered Learning** - Reinforcement learning improves accuracy over time
- ⚡ **Multiple Scan Modes** - Full, Quick, or Stealth reconnaissance
- 🎯 **Gray-Box Testing** - Analyze source code for enhanced endpoint discovery
- 📊 **Interactive Dashboard** - Web-based UI with sorting, filtering, and clickable detail popups
- 💾 **Database Storage** - Store vulnerabilities in SQL Server for ML training
- 📄 **Professional Reports** - PDF, JSON, and optimized reports with deduplication
- 🧹 **Auto-Cleanup** - Removes all test payloads after scanning
- 🔒 **Whitelist Security** - SHA256 integrity verification and anti-tamper protection

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building the Project](#building-the-project)
3. [Scan Modes](#scan-modes)
4. [Command Line Options](#command-line-options)
5. [Usage Examples](#usage-examples)
6. [Dashboard](#dashboard)
7. [Understanding the Output](#understanding-the-output)
8. [Report Formats](#report-formats)
9. [Whitelist Configuration](#whitelist-configuration)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **.NET 8.0 SDK** or later
- **Windows, Linux, or macOS**
- **Internet connection** (for testing remote targets)
- **SQL Server** (optional - for vulnerability database storage)

---

## Building the Project

```bash
# Navigate to AttackAgent directory
cd AttackAgent

# Build the project
dotnet build

# The executable will be created in:
# Windows: bin\Debug\net8.0\AttackAgent.exe
# Linux/macOS: bin/Debug/net8.0/AttackAgent
```

---

## Scan Modes

AttackAgent has **three scan modes** that determine testing thoroughness:

| Mode | Command | Description | Duration |
|------|---------|-------------|----------|
| 🔵 **Full** (Default) | `dotnet run -- <url>` | Most thorough - all phases, all payloads | 10-15 min |
| ⚡ **Quick** | `dotnet run -- <url> --quick` | Faster scan with reduced depth | 2-5 min |
| 🥷 **Stealth** | `dotnet run -- <url> --stealth` | Passive reconnaissance only | 1-3 min |

### Mode Comparison

| Feature | Full (Default) | Quick | Stealth |
|---------|---------------|-------|---------|
| Reconnaissance | Full | Reduced | Passive only |
| Port Scanning | 1000+ ports | Common ports | Basic |
| SQL Injection Testing | AI-enhanced | Reduced | ❌ None |
| XSS Testing | Reflected + Stored | Reduced | ❌ None |
| Detection Risk | Higher | Medium | Low |

---

## Command Line Options

### Basic Syntax
```bash
dotnet run -- <target-url> [options]
```

### Scan Mode Flags

| Flag | Description |
|------|-------------|
| *(none)* | **DEFAULT:** Full comprehensive scan |
| `--quick` | Quick mode - faster, reduced depth |
| `--stealth` | Stealth mode - passive reconnaissance only |

### Configuration Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--verbose` | Enable detailed logging | `--verbose` |
| `--timeout <sec>` | Set request timeout (default: 30s) | `--timeout 60` |
| `--output <dir>` | Output directory for reports | `--output ./my-reports` |
| `--source-code <path>` | Source code path for gray-box testing | `--source-code ../MyApp` |
| `--local-files <files>` | Scan local config files (comma-separated) | `--local-files "appsettings.json,.env"` |
| `--cleanup-only` | Remove test data from previous scans | `--cleanup-only` |

### Standalone Commands (No target URL required)

| Command | Description |
|---------|-------------|
| `--dashboard` | Launch interactive vulnerability database dashboard |
| `--list-vulns` | List all vulnerabilities from database in console |
| `--cleanup-db` | Clean up database false positives and duplicates |

---

## Usage Examples

### Basic Web Application Test
```bash
# Full comprehensive scan (DEFAULT)
dotnet run -- http://localhost:5285 --verbose
```

### Quick Security Check
```bash
# Faster scan for regular checks
dotnet run -- http://localhost:5285 --quick --verbose
```

### Gray-Box Testing (Recommended)
```bash
# Test with source code analysis for best coverage
dotnet run -- https://example.com --source-code ./MyApp --verbose
```

**Benefits of gray-box testing:**
- Discovers all endpoints (even hidden ones)
- Extracts parameter names from code
- Better understanding of application structure
- More accurate vulnerability detection

### Local Configuration File Analysis
```bash
# Scan web app AND check config files for exposed credentials
dotnet run -- http://localhost:5285 --local-files "appsettings.json,.env,web.config" --verbose
```

### Stealth Reconnaissance
```bash
# Passive scanning only - minimal detection
dotnet run -- https://target.com --stealth --verbose
```

### Production Server Testing
```bash
# Extended timeout for slower servers
dotnet run -- https://production.com --timeout 120 --verbose
```

### Launch Vulnerability Dashboard
```bash
# View ALL vulnerabilities from database in web UI
dotnet run -- --dashboard
```

### Cleanup Test Data
```bash
# Remove injected payloads from previous scans
dotnet run -- https://example.com --cleanup-only
```

### Comprehensive Combined Test
```bash
dotnet run -- https://example.com \
  --source-code ./MyApp \
  --local-files "appsettings.json,.env" \
  --timeout 120 \
  --verbose
```

---

## Dashboard

AttackAgent provides two types of dashboards:

### 1. Scan Dashboard (After Each Scan)
- Opens automatically after scan completes
- Shows vulnerabilities from **current scan only**
- URL: `http://localhost:5001`

### 2. Database Dashboard (Standalone)
```bash
dotnet run -- --dashboard
```
- Shows **ALL vulnerabilities** from all scans in database
- URL: `http://localhost:5000`

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Sort** | Click any column header to sort |
| **Filter by Severity** | Critical, High, Medium, Low, Info |
| **Filter by Type** | XSS, SQL Injection, etc. |
| **Filter by Status** | Real Only, Verified, False Positives, Pending |
| **Search** | Search across all fields |
| **Click Row** | Opens detailed popup with full info |

### Clickable Detail Popup
When you click any vulnerability row, you see:
- Complete metadata (ID, Scan ID, Timestamp, Application URL)
- Severity with colored badge
- Full endpoint and HTTP method
- Vulnerable parameter
- **Complete payload** that was used
- **Evidence** of the vulnerability
- Status (Verified/False Positive/Pending)
- **Recommended solution** for remediation

---

## Understanding the Output

### Execution Phases

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Reconnaissance** | OSINT, DNS enumeration, port scanning, technology analysis |
| 2 | **File System Access** | Directory traversal, config/backup/source file discovery |
| 3 | **Application Discovery** | Endpoint discovery, Swagger/OpenAPI, technology detection |
| 4 | **Advanced Exploitation** | SQL injection, XSS, command injection, file upload testing |
| 5 | **Security Testing** | Security headers, rate limiting, CORS, authentication |
| 6 | **Cleanup** | Remove all test payloads and injected data |

### Sample Output
```
[10:44:23 INF] 🤖 AI Attack Agent Starting...
[10:44:23 INF] 🎯 Target: https://example.com
[10:44:23 INF] 🔍 Phase 1: Reconnaissance
[10:44:25 INF] 📁 Phase 2: File System Access
[10:44:27 INF] 🔍 Phase 3: Application Discovery
[10:44:30 INF] ⚔️ Phase 4: Advanced Exploitation
[10:44:45 INF] 🛡️ Phase 5: Security Testing
[10:45:00 INF] 📊 Phase 6: Enhanced Report Generation
[10:45:02 INF] 🧹 Phase 6: Cleanup
[10:45:05 INF] ✅ Attack Agent completed successfully!
```

### Vulnerability Severity Levels

| Level | Icon | Priority | Examples |
|-------|------|----------|----------|
| **Critical** | 🔴 | Immediate | SQL injection, exposed credentials, RCE |
| **High** | 🟠 | High | XSS, authentication bypass, path traversal |
| **Medium** | 🟡 | Medium | Missing security headers, CORS issues |
| **Low** | 🟢 | Low | Minor configuration issues |
| **Info** | ℹ️ | Informational | Technology fingerprinting |

---

## Report Formats

Reports are saved in `reports/` directory:

```
reports/
├── pdf/          # Professional PDF reports (for stakeholders)
└── optimized/    # AI-optimized JSON + executive summaries
```

### Report Types

| Type | Location | Description | Use For |
|------|----------|-------------|---------|
| **PDF** | `reports/pdf/` | Professional presentation format | Stakeholders, clients |
| **Optimized JSON** | `reports/optimized/` | Deduplicated, filtered findings | AI assistants (Cursor) |
| **Executive Summary** | `reports/optimized/` | High-level summary | Management |

### Report Optimization

AttackAgent automatically optimizes reports:
- **Deduplication**: Removes duplicates (typically 50-95% reduction)
- **False Positive Filtering**: Filters low-confidence findings
- **Confidence Scoring**: Assigns confidence scores to all findings

Example:
```
📊 Optimization Results:
  • Original vulnerabilities: 163
  • After deduplication: 7
  • Overall reduction: 95.7%
```

---

## Whitelist Configuration

AttackAgent requires targets to be whitelisted for security.

### Edit `whitelist.txt`:
```
# Add your authorized URLs:
https://your-staging-server.com/
http://localhost:8080
```

### Auto-Allowed Targets (No whitelist needed):
- **Localhost**: `localhost`, `127.0.0.1`, `::1`
- **Private IPs**: `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`

### Security Features:
- SHA256 file integrity verification
- Anti-tampering detection
- Security audit logging

---

## Best Practices

### 1. Start with Quick Mode
```bash
dotnet run -- http://localhost:3000 --quick --verbose
```

### 2. Use Gray-Box Testing When Possible
```bash
dotnet run -- https://myapp.com --source-code ./src --verbose
```

### 3. Always Check Configuration Files
```bash
dotnet run -- http://localhost:3000 --local-files "appsettings.json,.env" --verbose
```

### 4. Review Reports
- Start with **executive summary** for overview
- Use **optimized JSON** for AI-assisted remediation
- Share **PDF reports** with stakeholders

### 5. Use the Dashboard
```bash
dotnet run -- --dashboard
```
Click vulnerabilities for detailed info and solutions.

### 6. Cleanup After Testing
AttackAgent auto-cleans, but you can run manually:
```bash
dotnet run -- https://example.com --cleanup-only
```

---

## Troubleshooting

### Common Issues

| Error | Solution |
|-------|----------|
| "Target not in whitelist" | Add URL to `whitelist.txt` |
| Connection timeout | Use `--timeout 120` |
| "Invalid target URL" | Ensure URL starts with `http://` or `https://` |
| Dashboard won't open | Run `taskkill /F /IM AttackAgent.exe` then retry |
| Source code path not found | Use absolute path or correct relative path |

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
dotnet run -- <url>                    # Full comprehensive scan (DEFAULT)
dotnet run -- <url> --quick            # Quick scan
dotnet run -- <url> --stealth          # Passive recon only

# === STANDALONE COMMANDS ===
dotnet run -- --dashboard              # Launch vulnerability dashboard
dotnet run -- --list-vulns             # List all vulnerabilities
dotnet run -- --cleanup-db             # Clean up database

# === COMMON OPTIONS ===
--verbose                              # Detailed logging
--timeout 60                           # Request timeout
--source-code ./src                    # Gray-box testing
--local-files "appsettings.json,.env"  # Scan config files
--cleanup-only                         # Remove test data

# === RECOMMENDED COMMANDS ===
dotnet run -- http://localhost:5285 --quick --verbose
dotnet run -- https://myapp.com --source-code ./src --verbose
dotnet run -- --dashboard
```

---

## Security Considerations

⚠️ **Important:** Always ensure you have proper authorization before testing any system.

- **Only test systems you own** or have explicit written permission to test
- **Unauthorized testing may violate laws** and regulations
- **Reports contain sensitive information** - secure appropriately
- Follow **responsible disclosure** practices

---

## Documentation

For detailed documentation, see:
- **[HOW_TO_USE_ATTACKAGENT.md](HOW_TO_USE_ATTACKAGENT.md)** - Complete usage guide with all flags and examples

---

## Support

**Questions?** Contact David, or ask Cursor after it scans through AttackAgent.

---

**Last Updated:** December 2025  
**Version:** 3.1
