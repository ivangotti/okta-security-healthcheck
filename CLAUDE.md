# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Node.js security detection scanner that queries Okta System Logs using detection rules and threat hunts from the [Okta customer-detections repository](https://github.com/okta/customer-detections). The application executes 31+ security detection rules and 12+ threat hunt queries, providing verbose terminal output explaining what is being queried and the results.

## Development Commands

### Setup
```bash
npm install
```

### Configuration
```bash
# Copy example config and fill in your Okta credentials
cp config.json.example config.json
```

### Run Application
```bash
# Run all detections
node src/index.js

# List all available detections
node src/index.js --list

# Run a specific detection
node src/index.js --detection "admin console"

# Override query time range
node src/index.js --since "2024-02-01T00:00:00Z"

# Use offline mode (cached detections, skip GitHub fetch)
node src/index.js --offline

# Show help
node src/index.js --help
```

**Note:** The app dynamically fetches the latest detection rules and threat hunts from GitHub on every run by default. This ensures new detections and hunts are automatically included when added to the upstream repository.

## Architecture

### Core Components

**src/index.js** - Main entry point
- Handles CLI argument parsing
- Orchestrates the detection workflow
- Manages configuration loading
- Provides user-facing commands (list, run specific, run all)

**src/oktaClient.js** - Okta API Wrapper
- Authenticates with Okta System Log API using SSWS token
- Executes filter queries against `/api/v1/logs` endpoint
- Handles pagination (follows `rel="next"` links in response headers)
- Implements rate limiting delays (100ms between requests)
- Error handling for network and API errors

**src/detectionLoader.js** - Detection Rule and Hunt Management
- **Dynamic Loading:** Fetches YAML files from both `detections/` and `hunts/` directories on GitHub by default
- Automatically picks up new detection rules and threat hunts as they're added to the upstream repository
- Parses YAML using `js-yaml` library
- Filters to only load OIE-compatible detections and hunts (skips Splunk/Complex formats)
- Tags each item with `sourceType` field ('detection' or 'hunt') for distinction
- Caches all rules locally in `detections/` directory as backup
- Falls back to cache if GitHub is unavailable
- Extracts `detection.okta_systemlog.OIE` field as the executable query
- Use `--offline` flag to skip GitHub fetch and use cached rules

**src/detectionRunner.js** - Detection and Hunt Execution Engine
- Runs detections and hunts sequentially with delays
- Distinguishes between detections and hunts with color-coded labels ([DETECTION] vs [HUNT])
- Provides verbose colored terminal output using `chalk`
- For each detection or hunt, displays:
  - Type label (detection or hunt)
  - Title and description
  - MITRE ATT&CK tactics/techniques
  - The exact Okta filter query
  - Results with event details (time, actor, IP, outcome)
  - Analysis and interpretation
  - False positive notes
- Generates summary statistics and PDF reports

### Detection File Structure

Each YAML detection file contains:
```yaml
title: Detection Name
id: unique-hash
description: What this detects and why it matters
threat:
  Tactic: [MITRE ATT&CK Tactic]
  Technique: [MITRE ATT&CK Technique ID]
detection:
  okta_systemlog:
    OIE: |
      # Okta filter query (this is what we execute)
      eventType eq "some.event" AND outcome.result eq "FAILURE"
false_positives:
  - Known benign scenarios
```

### Okta System Log API

**Endpoint**: `https://{domain}/api/v1/logs`

**Authentication**: `Authorization: SSWS {apiToken}`

**Filter Query Language**:
- `eq` - Equals
- `ne` - Not equal
- `co` - Contains
- `sw` - Starts with
- `ew` - Ends with
- `AND` / `OR` - Logical operators
- `not` - Negation

**Example Query**:
```
eventType eq "user.session.access_admin_app" AND outcome.result eq "FAILURE"
```

**Pagination**: Response includes `Link` header with `rel="next"` for pagination

### Configuration

**config.json** structure:
```json
{
  "okta": {
    "domain": "your-domain.okta.com",  // Your Okta tenant domain
    "apiToken": "00xxx...xxx"           // API token with read:system_log scope
  },
  "query": {
    "since": "2024-01-01T00:00:00Z",   // Optional: query start time (ISO 8601)
    "limit": 100                        // Max results per detection
  }
}
```

**API Token Requirements**:
- Must have `okta.logs.read` scope
- Create in Okta Admin Console: Security > API > Tokens
- Keep secure - never commit to git (excluded in .gitignore)

## Key Design Patterns

### Error Handling
- Individual detection failures don't stop the scan
- Network errors are caught and reported
- Invalid queries skip gracefully
- API authentication failures stop execution with clear message

### Rate Limiting
- 100ms delay between pagination requests
- 200ms delay between different detections
- Prevents overwhelming Okta API

### Dynamic Detection and Hunt Loading
- App fetches latest detection rules and threat hunts from GitHub on every run by default
- Loads from both `/detections` and `/hunts` directories in the upstream repository
- Ensures new detections and hunts are automatically included as they're added upstream
- All files cached in `detections/` directory as backup
- Falls back to cache if GitHub is unavailable (network issues, rate limits)
- Use `--offline` flag to skip GitHub fetch and use cached rules only

### Verbose Output Philosophy
- Every detection shows what it's looking for
- Query is displayed before execution
- Results include relevant context (actor, IP, time)
- Analysis helps interpret findings
- False positive notes aid investigation

## Detection and Hunt Categories

The 31+ detection rules and 12+ threat hunts cover:

### Detections (Real-time security events)
1. **Access Control** - Admin console access denied, weak MFA
2. **Authentication** - Policy downgrades, suspicious MFA abandonment
3. **Persistence** - New API tokens, new admins
4. **Credential Access** - Password spray, brute force
5. **Lateral Movement** - Session cookie theft
6. **Defense Evasion** - Log stream tampering
7. **Collection** - OAuth client secret reads
8. **Impact** - Protected action changes

### Hunts (Proactive threat hunting queries)
1. **AD User Imports** - Suspicious Active Directory user imports
2. **API Activity** - Unusual API usage patterns
3. **App Password Reveals** - Application password exposure events
4. **Authentication Policy Denies** - Denied authentication attempts
5. **Cloud Infrastructure Access** - Cloud resource access patterns
6. **Failed Identity Verification** - Identity verification failures
7. **Failed Number Challenges** - Phone number challenge failures
8. **MFA Abandonment** - Abandoned multi-factor authentication
9. **Factor Resets** - MFA factor reset events
10. **Rejected MFA Pushes** - Rejected push notification attempts
11. **Rich Client Abuse** - Native/rich client authentication abuse
12. **Sign-ins from Proxies** - Authentication from proxy/VPN services

## Common Development Tasks

### Adding New Detection/Hunt Sources
Modify `detectionLoader.js` `sources` array to support additional GitHub directories, repositories, or local YAML files. Each source requires a `name`, `githubBaseUrl`, `rawBaseUrl`, and `type` field.

### Supporting New Query Types
Currently only OIE format is executable. To support Splunk/Datadog queries, implement translation logic in `detectionRunner.js`.

### Customizing Output Format
Modify `detectionRunner.js` display methods, particularly `displayEvent()` and `runDetection()`.

### Adding Export Functionality
Extend `detectionRunner.js` to write results to JSON/CSV files for further analysis.

## Security Considerations

- API tokens provide read-only access to system logs
- No write operations are performed
- Logs may contain sensitive information (usernames, IPs)
- Results should be handled according to your security policies
- Consider outputting to secure logging systems

## Troubleshooting

**"Connection test failed"**: Check domain and API token in config.json

**"401 Unauthorized"**: Verify API token has `okta.logs.read` scope

**"No events found"**: Normal if no security events match the detection or hunt. Try wider time range with `--since`.

**"Rate limit exceeded"**: Okta API has rate limits. The app includes delays, but you may need to wait before retrying.

**Detection/Hunt shows "Skipped (Splunk)"**: This rule uses SIEM-specific queries and cannot be directly executed via Okta API.
