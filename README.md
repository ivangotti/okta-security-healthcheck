# Okta Security Health Check

A Node.js application that executes security detection rules against your Okta tenant using the System Log API. This tool implements detection rules from the official [Okta customer-detections repository](https://github.com/okta/customer-detections) to help identify potential security issues.

## Features

- Executes 31+ security detection rules from Okta's detection catalog
- Verbose terminal output explaining each detection and its results
- Color-coded results for easy scanning
- Supports filtering by specific detections or time ranges
- Caches detection rules locally for faster subsequent runs
- Handles pagination and rate limiting automatically

## Detection Categories

This tool scans for various security threats including:

- Unauthorized admin console access attempts
- Weak MFA usage in admin console
- API token creation and excessive access
- Authentication policy downgrades
- Device enrollment anomalies
- Adversary-in-the-middle (AiTM) phishing attacks
- Brute force and password spray attempts
- Session hijacking indicators
- Privilege escalation attempts
- Log tampering

## Prerequisites

- Node.js 14 or higher
- An Okta tenant with admin access
- Okta API token with `okta.logs.read` scope

## Installation

1. Clone or download this repository
2. Install dependencies:
```bash
npm install
```

3. Create configuration file:
```bash
cp config.json.example config.json
```

4. Edit `config.json` with your Okta credentials:
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

## Getting an Okta API Token

1. Log in to your Okta Admin Console
2. Navigate to **Security > API > Tokens**
3. Click **Create Token**
4. Give it a name (e.g., "Security Health Check")
5. Copy the token immediately (you won't see it again)
6. Paste it into your `config.json`

The token needs the `okta.logs.read` scope to access system logs.

## Usage

**Note:** By default, the app fetches the latest detection rules from GitHub on every run to ensure you always have the most up-to-date security checks. This means new detection rules are automatically included as they're added to the [Okta customer-detections repository](https://github.com/okta/customer-detections).

### Run All Detections
```bash
npm start
# or
node src/index.js
```

### List Available Detections
```bash
npm start -- --list
# or
node src/index.js --list
```

### Run a Specific Detection
```bash
npm start -- --detection "admin console"
# or
node src/index.js --detection "admin console"
```

### Override Time Range
```bash
npm start -- --since "2024-02-01T00:00:00Z"
# or
node src/index.js --since "2024-02-01T00:00:00Z"
```

### Use Offline Mode (Cached Detections)
```bash
npm start -- --offline
# or
node src/index.js --offline
```

Use this when you want to skip fetching from GitHub and use previously cached detection rules.

### Show Help
```bash
npm start -- --help
# or
node src/index.js --help
```

## Output Format

For each detection, the tool displays:

1. **Detection Name and Description** - What it's looking for
2. **Threat Intelligence** - MITRE ATT&CK tactics and techniques
3. **Query** - The exact Okta System Log filter being executed
4. **Results** - Events found (if any) with details:
   - Timestamp
   - User/actor
   - IP address and location
   - Outcome and reason
   - Target resources
5. **Analysis** - Interpretation of findings
6. **False Positives** - Known benign scenarios to consider

### Example Output

```
================================================================================
[1/31] Access to Admin Console Denied
================================================================================

Description:
  Detects when an attempt was made to access the Okta Admin Console but failed.
  Adversaries may try to access after compromising an admin but get denied.

Threat Intelligence:
  Tactic: Initial Access
  Technique: T1078: Valid Accounts

Okta System Log Query:
  eventType eq "user.session.access_admin_app" AND outcome.result eq "FAILURE"

Executing query...

Results: 3 event(s) found

⚠️  FINDINGS DETECTED

Event 1:
  UUID: abc123...
  Time: 2024-02-11T10:23:45Z
  Event Type: user.session.access_admin_app
  Actor: admin@company.com
  IP Address: 192.168.1.100
  Location: San Francisco, CA, US
  Outcome: FAILURE
  Reason: Policy evaluation failed

...

Analysis:
  ⚠️  3 event(s) matching this detection pattern
  Review these events to determine if they represent genuine security concerns

False Positives:
  - Legitimate administrative users causing failures due to user-error.
    Look for multiple instances from the same source.

================================================================================
```

## Security Considerations

- **API Token Security**: Keep your API token secure. Never commit it to version control.
- **Read-Only Access**: This tool only reads system logs and makes no changes to your Okta configuration.
- **Sensitive Data**: System logs contain sensitive information (usernames, IP addresses). Handle results appropriately.
- **Rate Limits**: The tool includes delays to respect Okta API rate limits.

## Troubleshooting

### Connection Errors
- Verify your Okta domain is correct (e.g., `your-domain.okta.com`, not `https://your-domain.okta.com`)
- Check that your API token is valid and hasn't expired

### Authentication Errors
- Ensure your API token has the `okta.logs.read` scope
- Verify you copied the entire token without extra spaces

### No Events Found
- This is normal if no security events match the detection criteria
- Try a wider time range with `--since` parameter
- Some detections may not trigger in your environment

### Skipped Detections
Some detections require SIEM-specific implementations (Splunk, Datadog) and cannot be directly executed via the Okta API. These are listed at the end of the scan.

## Contributing

This tool is designed to work with the community-maintained detection rules from Okta. To suggest improvements or report issues with specific detections, please visit the [Okta customer-detections repository](https://github.com/okta/customer-detections).

## License

ISC

## Disclaimer

This tool is provided as-is for security monitoring purposes. Always review and validate findings in the context of your environment before taking action.
