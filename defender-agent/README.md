# Microsoft Defender & Entra Security Agent

Automated security monitoring agent for Microsoft 365 environments, analyzing Defender alerts and Entra ID sign-in logs.

## Features

- **Daily Security Monitoring**
  - Microsoft Defender alert analysis
  - Entra ID risky sign-in detection
  - Failed MFA attempt tracking
  - Guest user activity monitoring

- **Weekly Analysis**
  - Comprehensive threat trending
  - Conditional Access policy effectiveness
  - Device compliance checking
  - Security posture recommendations

- **Real-time Alerts**
  - Critical security incident detection
  - Suspicious sign-in patterns (brute force, password spray)
  - Legacy authentication usage
  - Impossible travel detection

## Quick Start

### 1. Azure Setup

Follow the guide in `SETUP_AZURE_APP.md` to:
1. Create Azure AD app registration
2. Configure API permissions
3. Generate certificate for authentication

### 2. Installation

```bash
# Clone or navigate to the defender-agent directory
cd defender-agent

# Install dependencies
pip install -r requirements.txt

# Copy and configure the config file
cp agent_config.json.template agent_config.json
# Edit agent_config.json with your Azure credentials
```

### 3. Test Connection

```bash
# Test API connection and permissions
python defender_agent.py --test
```

### 4. Run Analysis

```bash
# Run daily analysis (per SECURITY_CHECKLIST.md)
python defender_agent.py --daily

# Run weekly comprehensive analysis
python defender_agent.py --weekly

# Quick security check (last 4 hours)
python defender_agent.py --check quick

# Specific checks
python defender_agent.py --check signin   # Sign-in analysis only
python defender_agent.py --check defender  # Defender alerts only
```

## Configuration

Edit `agent_config.json` to customize:

- **Authentication**: Certificate or client secret
- **Analysis Settings**: Time ranges, risk thresholds
- **Notifications**: GitHub, Slack, Teams, Email
- **Features**: Enable/disable specific analyses
- **Security**: PII redaction, data retention

## Scheduling

### Windows Task Scheduler

Use the provided PowerShell script:
```powershell
.\setup_scheduler.ps1
```

### Linux/Mac (cron)

Add to crontab:
```bash
# Daily analysis at 8 AM
0 8 * * * /usr/bin/python3 /path/to/defender_agent.py --daily

# Weekly analysis on Mondays at 9 AM
0 9 * * 1 /usr/bin/python3 /path/to/defender_agent.py --weekly
```

## Reports

Reports are saved in the `./reports` directory:

- **JSON**: Machine-readable detailed analysis
- **Markdown**: Human-readable summary with recommendations

Example report structure:
```
reports/
├── daily_report_20240115_080000.json
├── daily_report_20240115_080000.md
├── weekly_report_20240115_090000.json
└── weekly_report_20240115_090000.md
```

## Security Analysis Components

### Sign-in Analysis
- Risky sign-ins with risk factors
- MFA failure tracking
- Legacy authentication detection
- Suspicious patterns (brute force, password spray)
- Geographic anomaly detection
- Guest user activity

### Defender Analysis
- Critical alert prioritization
- Threat categorization (MITRE ATT&CK)
- Affected asset tracking
- Incident correlation
- Trend analysis
- Automated vs manual remediation tracking

### Recommendations Engine
- Prioritized security actions
- Risk-based recommendations
- Compliance suggestions
- Configuration improvements

## Integration

### GitHub Issues
Configure in `agent_config.json`:
```json
"github_integration": true,
"github_repo": "your-org/security-repo"
```

Critical findings automatically create GitHub issues with:
- Alert details
- Affected users/devices
- Recommended actions
- Links to Azure portal

### Slack/Teams Notifications
Configure webhooks for real-time alerts on:
- High-severity Defender alerts
- Suspicious sign-in patterns
- Failed MFA attempts exceeding threshold

## Troubleshooting

### Common Issues

1. **"Insufficient privileges" error**
   - Ensure all API permissions are granted with admin consent
   - Wait 5-10 minutes for permissions to propagate

2. **Certificate authentication fails**
   - Verify certificate thumbprint matches Azure registration
   - Check certificate hasn't expired
   - Ensure .pfx file has correct password

3. **No data returned**
   - Verify Azure AD P1/P2 licensing for advanced features
   - Check if audit logs are enabled in Azure AD
   - Ensure Defender for Endpoint is configured

### Debug Mode

Enable verbose logging:
```bash
python defender_agent.py --daily --verbose
```

Check logs in `defender_agent.log`

## API Permissions Required

Minimum required Microsoft Graph permissions:
- `SecurityEvents.Read.All`
- `AuditLog.Read.All`
- `Directory.Read.All`
- `IdentityRiskEvent.Read.All`
- `SignIns.Read.All`

Optional for enhanced features:
- `Reports.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `SecurityIncident.Read.All`

## Architecture

```
defender-agent/
├── defender_agent.py          # Main orchestrator
├── auth_handler.py            # OAuth2 authentication
├── api_client.py              # Microsoft Graph API wrapper
├── analyzers/
│   ├── signin_analyzer.py    # Sign-in log analysis
│   └── defender_analyzer.py  # Defender alert analysis
├── reports/                  # Generated reports
├── agent_config.json         # Configuration
└── requirements.txt          # Python dependencies
```

## Security Considerations

- **Credentials**: Never commit `agent_config.json` with real credentials
- **Certificates**: Store .pfx files securely with restricted permissions
- **Reports**: May contain sensitive data - handle according to policy
- **API Keys**: Rotate certificates/secrets regularly
- **Audit**: All API calls are logged for compliance

## Contributing

This agent follows the principles in `../AGENT.md`:
- Human-in-the-loop for critical decisions
- Read-only operations (no automatic remediation)
- Clear audit trail of all actions
- Integration with existing security workflows

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review Azure portal audit logs
3. Open a GitHub issue with sanitized logs

## License

Internal use only - Jess Ford IT Operations