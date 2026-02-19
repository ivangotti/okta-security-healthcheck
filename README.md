# Okta Security Health Check 🔒

[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-ISC-blue.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/github-ivangotti%2Fokta--security--healthcheck-blue)](https://github.com/ivangotti/okta-security-healthcheck)

A powerful Node.js application that executes security detection rules against your Okta tenant using the System Log API. This tool implements detection rules from the official [Okta customer-detections repository](https://github.com/okta/customer-detections) to help identify potential security threats in real-time.

## 🚀 Features

- **22+ Security Detections** - Automatically executes OIE-compatible detection rules
- **Dynamic Updates** - Fetches latest detection rules from GitHub on every run
- **PDF Report Generation** - Beautiful, professional PDF reports with all findings automatically generated
- **Verbose Output** - Color-coded terminal output with detailed event information
- **Smart Caching** - Falls back to cached detections if GitHub is unavailable
- **Offline Mode** - Run scans using cached detection rules
- **Risk Assessment** - Automatic risk level calculation (LOW/MODERATE/HIGH)

## 🎯 What It Detects

This tool scans for various security threats including:

| Category | Detections |
|----------|-----------|
| **Access Control** | Unauthorized admin console access, weak MFA usage |
| **Authentication** | Policy downgrades, suspicious MFA abandonment |
| **Persistence** | New API tokens, new admin accounts |
| **Credential Access** | Password spray, brute force attempts |
| **Lateral Movement** | Session cookie theft, unusual device access |
| **Defense Evasion** | Log stream tampering |
| **Collection** | OAuth client secret reads |
| **Impact** | Protected action changes |

## 📋 Prerequisites

- Node.js 14 or higher
- An Okta tenant with admin access
- Okta API token with `okta.logs.read` scope

## 🔧 Installation

1. **Clone the repository**
```bash
git clone https://github.com/ivangotti/okta-security-healthcheck.git
cd okta-security-healthcheck
```

2. **Install dependencies**
```bash
npm install
```

3. **Configure your Okta credentials**
```bash
cp config.json.example config.json
```

4. **Edit `config.json` with your Okta details**
```json
{
  "okta": {
    "domain": "your-domain.okta.com",
    "apiToken": "your-api-token-here"
  },
  "query": {
    "since": "2024-01-01T00:00:00Z",
    "limit": 100
  }
}
```

## 🔑 Getting an Okta API Token

1. Log in to your **Okta Admin Console**
2. Navigate to **Security > API > Tokens**
3. Click **Create Token**
4. Give it a name (e.g., "Security Health Check")
5. Copy the token immediately (you won't see it again!)
6. Paste it into your `config.json`

**Note:** The token needs the `okta.logs.read` scope to access system logs.

## 💻 Usage

> **Note:** The app automatically fetches the latest detection rules from GitHub on every run, ensuring you always have the most up-to-date security checks.

### Run All Detections
```bash
npm start
```

### List Available Detections
```bash
npm start -- --list
```

### Run a Specific Detection
```bash
npm start -- --detection "admin console"
```

### Override Time Range
```bash
npm start -- --since "2024-02-01T00:00:00Z"
```

### Use Offline Mode
```bash
npm start -- --offline
```
Use this to skip GitHub fetch and use cached detection rules.

### Show Help
```bash
npm start -- --help
```

## 📊 Output Example

For each detection, the tool displays:

```
================================================================================
[1/22] New Okta API Token Created
================================================================================

Description:
  Detects a new Okta API token being created by an Okta Administrator.
  An adversary with access to an admin account may create an API token
  to maintain persistence in the environment.

Executing query...

Results: 6 event(s) found

⚠️  FINDINGS DETECTED

Event 1:
  Time: 2026-02-11T17:32:49.940Z
  Event Type: system.api_token.create
  Actor: admin@company.com
  IP Address: 192.168.1.100
  Location: San Francisco, CA, United States
  Outcome: SUCCESS
  Target: HealthCheck

Analysis:
  ⚠️  6 event(s) matching this detection pattern
  Review these events to determine if they represent genuine security concerns

False Positives:
  - Legitimate new Okta API tokens being created for approved integrations

================================================================================
SECURITY SCAN SUMMARY
================================================================================

Detections Executed: 22
✓ Successful: 22

Security Findings: 7 detection(s) triggered
Total Events: 159

⚠️  DETECTIONS WITH FINDINGS:

1. New Okta API Token Created
   Events Found: 6
   Tactic: Persistence

2. ThreatInsight - Password Spray
   Events Found: 100
   Tactic: Credential Access

3. OAuth Client Secret Read
   Events Found: 46
   Tactic: Credential Access

⚠️  Action Required: Review the findings above for potential security issues
   Scroll up to see detailed event information for each detection
```

## 🎨 Output Features

- **Color-coded results** for easy scanning
- **Bold cyan labels** with white values for clarity
- **Outcome highlighting**:
  - 🟢 SUCCESS (green)
  - 🔴 FAILURE (red)
  - ⚪ DENY (white)
- **Comprehensive event details** including time, actor, IP, location
- **MITRE ATT&CK tactics** for threat context
- **False positive guidance** to reduce alert fatigue

## 📄 PDF Report

After each scan completes, a beautiful PDF report is automatically generated with the filename: `okta-security-scan-YYYY-MM-DD.pdf`

### Report Contents

**Title Page**
- Scan date and time
- Okta tenant information
- Query period

**Executive Summary**
- Key metrics (detections executed, triggered, total events)
- Risk assessment (LOW/MODERATE/HIGH) with color coding
- Summary of key findings

**Detailed Findings**
- Each detection with findings gets a dedicated section
- Detection description and MITRE ATT&CK tactics
- Event details including:
  - Timestamp
  - Actor (user/service)
  - IP address and geolocation
  - Outcome (SUCCESS/FAILURE/DENY)
  - Target resources
- False positive guidance

**Professional Formatting**
- Clean typography with Helvetica fonts
- Color-coded risk indicators
- Statistics boxes with visual appeal
- Page headers and footers with page numbers
- Organized sections for easy navigation

The PDF is perfect for:
- Sharing with security teams
- Compliance documentation
- Executive reporting
- Historical tracking of security posture

## 🏗️ Architecture

```
sec-healthcheck/
├── src/
│   ├── index.js            # Main entry point & CLI
│   ├── oktaClient.js       # Okta API wrapper
│   ├── detectionLoader.js  # GitHub detection fetcher
│   ├── detectionRunner.js  # Detection executor
│   └── pdfGenerator.js     # PDF report generator
├── config.json.example     # Configuration template
├── package.json           # Dependencies
├── README.md             # This file
└── CLAUDE.md            # Developer documentation
```

### How It Works

1. **Detection Loader** fetches 31 YAML files from [Okta customer-detections](https://github.com/okta/customer-detections)
2. **Parser** extracts OIE-compatible filter queries (ignores Splunk/complex formats)
3. **Okta Client** executes each query against your tenant's System Log API
4. **Runner** displays results with comprehensive context and analysis
5. **PDF Generator** creates a beautiful report with all findings
6. **Smart Caching** saves detections locally as backup

## 🔒 Security Considerations

- **API Token Security**: Your API token is never committed to git (excluded in `.gitignore`)
- **Read-Only Access**: This tool only reads system logs, no write operations
- **Sensitive Data**: System logs contain usernames and IPs - handle results appropriately
- **Rate Limits**: Built-in delays respect Okta API rate limits

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| **Connection test failed** | Check domain and API token in `config.json` |
| **401 Unauthorized** | Verify token has `okta.logs.read` scope |
| **No events found** | Normal if no security events match. Try wider time range with `--since` |
| **Rate limit exceeded** | App includes delays, but you may need to wait before retrying |

## 🤝 Contributing

This tool uses community-maintained detection rules from Okta. To suggest improvements or report issues with specific detections, visit the [Okta customer-detections repository](https://github.com/okta/customer-detections).

## 📝 License

ISC

## ⚠️ Disclaimer

This tool is provided as-is for security monitoring purposes. Always review and validate findings in the context of your environment before taking action.

---

**Built with ❤️ for Okta security professionals**

[![Star on GitHub](https://img.shields.io/github/stars/ivangotti/okta-security-healthcheck?style=social)](https://github.com/ivangotti/okta-security-healthcheck)
