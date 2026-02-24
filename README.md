# Okta Security Health Check 🔒

[![License](https://img.shields.io/badge/license-ISC-blue.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/github-ivangotti%2Fokta--security--healthcheck-blue)](https://github.com/ivangotti/okta-security-healthcheck)

A powerful security scanner that executes detection rules and threat hunts against your Okta tenant using the System Log API. This tool implements detection rules and threat hunting queries from the official [Okta customer-detections repository](https://github.com/okta/customer-detections) to help identify potential security threats in real-time.

## 🚀 Features

- **🎨 Interactive Terminal UI** - Full-screen interface with fixed header, animated owl mascot, and scrolling output
- **43+ Security Checks** - Automatically executes 31+ detection rules and 12+ threat hunts
- **📋 Enhanced Event Display** - Beautifully formatted events with box borders, contextual colors, and rich details
- **Dynamic Updates** - Fetches latest detections and hunts from GitHub on every run
- **Risk Correlation Analysis** - Automatically correlates events across findings to identify high-risk users and IPs
- **PDF Report Generation** - Professional PDF reports with findings and risk analysis
- **Intelligent Risk Scoring** - Calculates risk scores based on patterns, frequency, and severity
- **Top Risk Entities** - Identifies top 10 risk users and IPs with detailed breakdown
- **Colorful Output** - Rich emoji usage 🛡️🔍📊 and color-coded messages throughout
- **Hunt vs Detection** - Clearly distinguishes between real-time detections and proactive threat hunts
- **Smart Caching** - Falls back to cached rules if GitHub is unavailable
- **Offline Mode** - Run scans using cached detection rules and hunts

## 🎯 What It Detects

### Security Detections (31+ rules)
| Category | Examples |
|----------|-----------|
| **Access Control** | Unauthorized admin console access, weak MFA usage |
| **Authentication** | Policy downgrades, suspicious MFA abandonment |
| **Persistence** | New API tokens, new admin accounts |
| **Credential Access** | Password spray, brute force attempts |
| **Lateral Movement** | Session cookie theft, unusual device access |
| **Defense Evasion** | Log stream tampering |
| **Collection** | OAuth client secret reads |
| **Impact** | Protected action changes |

### Threat Hunts (12+ queries)
| Category | Examples |
|----------|-----------|
| **Authentication Anomalies** | MFA abandonment, failed number challenges, rejected MFA pushes |
| **Identity Management** | AD user imports, failed identity verification |
| **Access Patterns** | Sign-ins from proxies, rich client abuse, cloud infra access |
| **Policy Issues** | Authentication policy denies, app password reveals |
| **MFA Events** | Factor resets, suspicious MFA patterns |
| **API Security** | Unusual API activity patterns |

## 📋 Prerequisites

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

## 🎨 Terminal UI

The app features a beautiful, interactive terminal interface with a fixed header and scrolling content area.

### Header Section
```
┌─────────────────────────────────────────────────────────────┐
│ 🔒 Okta Security Healthcheck by Ivan Gotti       ,___,      │
│ 📅 2026-02-23 ⏰ 14:30:45                        [o.o]      │
│ 🌐 Scanning: your-company.okta.com               )::(       │
└─────────────────────────────────────────────────────────────┘
```

- **Live Date/Time** - Current date and time updated every second
- **Okta Org URL** - Shows which tenant is being scanned
- **Animated Owl Mascot** - 8 expressions (normal, happy, vigilant, wink, alert, sleepy, excited)

### Enhanced Event Display

Events are displayed with rich formatting, contextual colors, and comprehensive details:

```
┌─ 📋 Event 1 ─────────────────────────────────
│ ⏰ Time:       Feb 23, 2024, 14:30:45
│ 📌 Event Type:  user.session.access_admin_app
│ 👤 Actor:      compromised.user@example.com
│   Display Name: John Doe
│ 🌐 IP Address:  203.0.113.42
│   🖥️  User Agent: Mozilla/5.0 (Windows NT 10.0...)
│ 📍 Location:   Moscow, Moscow, Russia
│   📱 Device: Computer
│ ❌ Outcome:   FAILURE
│   💬 Reason: VERIFICATION_ERROR
│ 🎯 Target:     Okta Admin Console (AppInstance)
│   🔗 Request: /admin/dashboard
└───────────────────────────────────────────────────
```

**Color Coding:**
- Event types in **magenta**
- Actors in **green**
- IP addresses in **cyan**
- Locations in **yellow**
- Outcomes with contextual emojis: ✅ SUCCESS, ❌ FAILURE, 🚫 DENY

### Interactive Controls

- **Mouse Wheel** - Scroll through results
- **Arrow Keys** - Navigate up/down
- **Page Up/Down** - Scroll by page
- **ESC or Q** - Exit the application

## 💻 Usage

> **Note:** The app automatically fetches the latest detection rules and threat hunts from GitHub on every run.

### Run All Detections and Hunts
```bash
npm start
```

### List Available Detections and Hunts
```bash
npm start -- --list
```

### Run a Specific Detection or Hunt
```bash
npm start -- --detection "admin console"
npm start -- --detection "mfa abandonment"
```

### Override Time Range
```bash
npm start -- --since "2024-02-01T00:00:00Z"
```

### Use Offline Mode
```bash
npm start -- --offline
```

### Show Help
```bash
npm start -- --help
```

## 🔍 Risk Correlation Analysis

After all detections and hunts complete, the app performs intelligent correlation analysis to identify the highest-risk entities.

### Risk Scoring Algorithm

**User Risk Factors:**
- Number of different security findings triggered (20 points each)
- Total security events (2 points each, capped at 100)
- Multiple IP addresses used (10 points per IP - compromise indicator)
- Multiple geographic locations (15 points per location - impossible travel)
- Failed/denied authentication attempts (3 points each)

**Risk Levels:**
- 🔴 **CRITICAL** (150+ points) - Immediate investigation required
- 🟠 **HIGH** (100-149 points) - Prompt review recommended
- 🟡 **MODERATE** (50-99 points) - Monitor closely
- 🟢 **LOW** (<50 points) - Normal activity

### Output

- **Top 10 Risk Users** with detailed breakdown
- **Top 10 Risk IPs** with affected user counts
- **Correlation Statistics** (total users, IPs, devices analyzed)
- **Risk Distribution** (count by risk level)

## 📄 PDF Report

After each scan, a PDF report is automatically generated: `okta-security-scan-YYYY-MM-DD.pdf`

### Report Contents

- **Executive Summary** - Key metrics and risk assessment
- **Risk Correlation Analysis** - Top risk users and IPs with scores
- **Detailed Findings** - Each detection with events, MITRE ATT&CK tactics, and false positive guidance
- **Professional Formatting** - Color-coded risk indicators, clean typography, page numbers

## 🏗️ Architecture

```
sec-healthcheck/
├── src/
│   ├── index.js              # Main entry point & CLI
│   ├── oktaClient.js         # Okta API wrapper
│   ├── detectionLoader.js    # GitHub detection fetcher
│   ├── detectionRunner.js    # Detection executor
│   ├── terminalGui.js        # Blessed-based terminal UI
│   ├── correlationAnalyzer.js # Risk correlation engine
│   └── pdfGenerator.js       # PDF report generator
├── config.json.example       # Configuration template
├── package.json              # Dependencies
└── README.md                 # This file
```

### How It Works

1. **Detection Loader** fetches YAML files from `/detections` and `/hunts` directories in [Okta customer-detections](https://github.com/okta/customer-detections)
2. **Parser** extracts OIE-compatible filter queries and tags each with type (detection vs hunt)
3. **Okta Client** executes each query against your tenant's System Log API
4. **Terminal GUI** displays results with comprehensive context and enhanced formatting
5. **Correlation Analyzer** examines all events to identify high-risk users, IPs, and devices
6. **PDF Generator** creates a professional report with findings and risk analysis

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

This tool uses community-maintained detection rules and threat hunts from Okta. To suggest improvements or report issues with specific detections or hunts, visit the [Okta customer-detections repository](https://github.com/okta/customer-detections).

## 📝 License

ISC

## ⚠️ Disclaimer

This tool is provided as-is for security monitoring purposes. Always review and validate findings in the context of your environment before taking action.

---

**Built with ❤️ for Okta security professionals by Ivan Gotti**

[![Star on GitHub](https://img.shields.io/github/stars/ivangotti/okta-security-healthcheck?style=social)](https://github.com/ivangotti/okta-security-healthcheck)
