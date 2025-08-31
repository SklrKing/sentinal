# Microsoft Defender & Entra Security Agent - Claude Implementation

**Created:** January 2025  
**Purpose:** Automated security monitoring and analysis for Jess Ford's Microsoft 365 environment  
**Agent Type:** Claude Code defensive security automation  

## Executive Summary

This Claude-powered security agent automates the daily and weekly security monitoring tasks outlined in `SECURITY_CHECKLIST.md`. It connects to Microsoft Defender and Entra ID (Azure AD) to analyze security alerts, sign-in patterns, and user behaviors, generating actionable intelligence while maintaining the human-in-the-loop principle defined in `AGENT.md`.

**Key Capabilities:**
- Automated analysis of Microsoft Defender security alerts
- Detection of suspicious sign-in patterns (brute force, password spray, impossible travel)  
- Risk assessment of users and devices
- Integration with existing security workflows via GitHub Issues and notifications
- Comprehensive reporting aligned with compliance requirements

## Business Value

### Time Savings
- **Daily Tasks:** Reduces 30-45 minutes of manual portal checking to 5-minute report review
- **Weekly Analysis:** Automates 2-3 hours of comprehensive security review into structured reports
- **Alert Triage:** Prioritizes critical issues, eliminating noise from low-priority alerts

### Risk Reduction
- **Early Detection:** Identifies threats within hours instead of days
- **Pattern Recognition:** Spots subtle attack patterns humans might miss
- **Consistency:** Never misses scheduled security checks due to human factors

### Compliance Support
- **Audit Trail:** All analyses are logged with timestamps and data sources
- **Documentation:** Automated generation of security posture reports
- **Trend Analysis:** Historical data supports compliance reviews and security assessments

## Technical Architecture

```
Claude Security Agent
├── Authentication Layer (auth_handler.py)
│   ├── Certificate-based OAuth2 to Microsoft Graph
│   └── Token management and renewal
├── Data Collection (api_client.py)  
│   ├── Microsoft Defender alerts and incidents
│   ├── Entra ID sign-in logs and audit events
│   └── User risk assessments and device compliance
├── Analysis Engines
│   ├── Defender Analyzer - Alert prioritization and threat categorization
│   └── Sign-in Analyzer - Behavioral analysis and anomaly detection
├── Reporting & Integration
│   ├── Markdown reports for human review
│   ├── JSON reports for system integration
│   └── GitHub Issues for critical findings
└── Orchestrator (defender_agent.py)
    ├── Daily, weekly, and on-demand analysis modes
    ├── Configurable thresholds and risk parameters
    └── Automated scheduling and notifications
```

## Operational Integration

### Daily Workflow (Automated - 8:00 AM)
Aligns with **SECURITY_CHECKLIST.md** daily requirements:

1. **Defender Portal Review** → Agent analyzes last 24 hours of alerts
2. **Entra Risky Sign-ins** → Agent identifies suspicious authentication attempts  
3. **Backup Status Check** → Agent flags any critical alerts requiring immediate attention

**Output:** Daily security briefing with priority actions (5-minute human review)

### Weekly Workflow (Automated - Monday 9:00 AM)  
Aligns with **SECURITY_CHECKLIST.md** weekly requirements:

1. **Device Coverage Verification** → Agent reports Defender EDR enrollment gaps
2. **Conditional Access Analysis** → Agent identifies policy bypass attempts
3. **Guest User Review** → Agent flags unusual external access patterns
4. **Phishing Awareness Data** → Agent provides metrics for staff communications

**Output:** Comprehensive security posture report with strategic recommendations

### Critical Alert Response (Real-time)
When high-severity issues are detected:

1. **Immediate Assessment** → Agent categorizes threat level and affected assets
2. **Automated Issue Creation** → GitHub issue created with investigation checklist  
3. **Notification Dispatch** → Slack/Teams alert sent to security team
4. **Context Assembly** → Links to Azure portal with relevant search queries pre-built

## Detection Capabilities

### Sign-in Analysis
- **Brute Force Detection:** Multiple failed attempts from same user/IP
- **Password Spray Identification:** Multiple usernames from same IP  
- **Impossible Travel:** Geographically inconsistent sign-ins
- **Legacy Protocol Usage:** IMAP, POP3, SMTP authentication attempts
- **MFA Bypass Attempts:** Repeated MFA failures or suspicious approvals
- **Guest Account Anomalies:** Unusual access from external users

### Defender Alert Analysis  
- **Critical Alert Prioritization:** Ransomware, credential theft, lateral movement
- **MITRE ATT&CK Mapping:** Categorizes threats by attack framework
- **Asset Impact Assessment:** Identifies most-targeted devices and users
- **Trend Analysis:** Detects increasing threat volumes or new attack patterns
- **Incident Correlation:** Links related alerts into comprehensive threat stories

## Configuration and Customization

### Risk Thresholds (Configurable)
```json
"analysis_settings": {
  "signin_hours_back": 24,
  "defender_days_back": 7,  
  "failed_signin_threshold": 5,
  "trusted_countries": ["US", "United States"],
  "risk_threshold": "medium"
}
```

### Notification Settings
- **GitHub Integration:** Auto-creates issues for critical findings
- **Slack/Teams:** Real-time alerts for high-severity events  
- **Email Summaries:** Daily/weekly reports to security team
- **Scheduling:** Configurable run times and frequencies

## Report Samples

### Daily Report Structure
```markdown
# Daily Security Analysis Report
Generated: 2025-01-15T08:00:00Z

## Executive Summary  
✅ No critical security issues detected
- Total sign-ins: 1,247 (98.2% success rate)
- Defender alerts: 3 low-severity, 0 high-severity  
- Risky users: 0 new flags

## Priority Actions
1. ✅ All security checks passed
2. 📱 Review 2 users with repeated MFA failures
3. 🔍 Monitor elevated sign-in failures from 203.0.113.45

## Detailed Findings
[Comprehensive breakdown of all analysis results]
```

### Critical Alert Example
```markdown
🚨 CRITICAL ALERT: Potential Credential Compromise

**User:** jsmith@company.com
**Alert:** Multiple failed sign-ins followed by successful authentication from new location
**Timeline:** 07:45-08:15 GMT  
**Risk Factors:**
- 12 failed attempts from 198.51.100.23 (Ukraine)
- Successful sign-in from 203.0.113.67 (Ukraine) 15 minutes later
- First sign-in from this country  
- Legacy Exchange ActiveSync protocol used

**Recommended Actions:**
1. Immediately reset user password and revoke sessions
2. Enable additional MFA requirements  
3. Review recent email/file access for signs of compromise
4. Block source IP addresses if not legitimate business need
```

## Compliance and Audit Support

### Audit Trail
- All API calls logged with timestamps
- Analysis parameters and thresholds recorded  
- Report generation tracked for compliance reviews
- Configuration changes version-controlled in Git

### Data Retention
- Reports: 30 days (configurable)
- Logs: 90 days for investigation support
- Raw data: Not stored locally (pulled fresh from Microsoft APIs)
- PII redaction: Configurable for sensitive environments

## Troubleshooting Quick Reference

### Common Issues

**"Authentication Failed"**
- Check certificate hasn't expired
- Verify thumbprint matches Azure app registration  
- Confirm all API permissions granted with admin consent

**"No Data Returned"**  
- Verify Azure AD P1/P2 licensing for advanced sign-in logs
- Check Defender for Endpoint deployment status
- Confirm audit logs enabled in Azure AD settings

**"Permission Denied"**
- Wait 10 minutes for permission propagation after changes
- Verify app registration has correct Graph API permissions
- Test with PowerShell: `Get-MgSecurityAlert -Top 1`

### Performance Optimization
- API calls are rate-limited to avoid throttling
- Results cached for 15 minutes to improve response times
- Pagination handled automatically for large datasets
- Retry logic built-in for transient failures

## Security Considerations

### Read-Only Operations
- Agent has NO write permissions to any Microsoft services
- Cannot modify users, policies, or security settings
- Cannot delete or archive data
- Cannot respond to alerts automatically

### Data Security  
- Certificates stored in secure file system locations
- API responses logged without PII (when configured)
- Network traffic encrypted via HTTPS/TLS 1.2+
- Local report files protected by OS file permissions

### Access Control
- Service account has minimum required permissions
- Certificate-based authentication preferred over secrets
- Regular permission audits via built-in permission testing
- Break-glass admin accounts excluded from automation

## Future Enhancements

### Phase 2 Capabilities (Next 3 months)
- **DGX Spark Integration:** Local AI analysis of sensitive log data
- **Power Automate Workflows:** Automated ticket creation in service management
- **Custom Dashboards:** Real-time security metrics visualization  
- **Threat Intelligence:** Integration with external threat feeds

### Phase 3 Expansion (6+ months)
- **Intune Device Analysis:** Detailed compliance and security posture
- **SharePoint/OneDrive Security:** Data classification and access reviews
- **Email Security:** Advanced analysis of Exchange Online protection
- **Custom Detection Rules:** Organization-specific threat patterns

## Integration with Existing Workflows

### SECURITY_CHECKLIST.md Alignment
This agent automates approximately 70% of tasks in the security checklist:

| Cadence | Manual Tasks Remaining | Automated by Agent |
|---------|----------------------|-------------------|
| Daily | Backup dashboard spot-check | Defender alerts, Risky sign-ins |
| Weekly | Document updates | EDR coverage, CA logs, Guest review |  
| Monthly | Physical restore tests | Patch audit, Secure Score, Guest cleanup |
| Quarterly | Incident response drills | DLP audit, Key rotation tracking |

### AGENT.md Compliance
- ✅ **Human-in-the-loop:** All critical findings require manual review
- ✅ **Read-only operations:** No automatic remediation capabilities  
- ✅ **Clear audit trail:** All actions logged and traceable
- ✅ **Test environment first:** Configuration changes tested before production
- ✅ **Documentation maintained:** Reports auto-update security documentation

## Getting Started Checklist

### Initial Setup (One-time, ~2 hours)
- [ ] Complete Azure app registration (follow `defender-agent/SETUP_AZURE_APP.md`)
- [ ] Install Python dependencies (`pip install -r requirements.txt`)
- [ ] Configure `agent_config.json` with Azure credentials  
- [ ] Test connection (`python defender_agent.py --test`)
- [ ] Schedule automated runs (`.\setup_scheduler.ps1` on Windows)

### Daily Operations (5 minutes)
- [ ] Review daily report in `reports/` directory
- [ ] Address any critical findings flagged by agent
- [ ] Check GitHub Issues for new security items (if configured)  
- [ ] Verify agent logs for any errors or warnings

### Weekly Operations (15 minutes)  
- [ ] Review comprehensive weekly analysis report
- [ ] Update security team on trending threats and recommendations
- [ ] Plan remediation for identified security gaps
- [ ] Validate agent performance and adjust thresholds if needed

---

**Questions or Issues?**
- Technical problems: Check `defender-agent/README.md` troubleshooting section
- Configuration help: Review `defender-agent/SETUP_AZURE_APP.md`  
- Operational questions: Reference this document's troubleshooting section
- Agent improvements: Follow governance in `AGENT.md` for change requests

**This agent represents a significant force multiplier for cybersecurity operations, automating routine monitoring while ensuring human oversight of all critical security decisions.**