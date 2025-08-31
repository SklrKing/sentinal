"""
Microsoft Defender analyzer for security alerts and incidents
Processes and prioritizes Defender alerts for actionable insights
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class DefenderAnalyzer:
    """Analyzes Microsoft Defender alerts and incidents"""
    
    # Alert severity levels
    SEVERITY_PRIORITY = {
        'high': 1,
        'medium': 2,
        'low': 3,
        'informational': 4
    }
    
    # Categories requiring immediate attention
    CRITICAL_CATEGORIES = [
        'Ransomware',
        'Backdoor',
        'Trojan',
        'CredentialAccess',
        'Persistence',
        'PrivilegeEscalation',
        'DefenseEvasion',
        'CommandAndControl'
    ]
    
    def __init__(self, api_client):
        """
        Initialize analyzer
        
        Args:
            api_client: GraphAPIClient instance
        """
        self.client = api_client
    
    def analyze_security_alerts(self, days_back: int = 7) -> Dict[str, Any]:
        """
        Comprehensive analysis of security alerts
        
        Args:
            days_back: Number of days to analyze
        
        Returns:
            Analysis results dictionary
        """
        logger.info(f"Analyzing Defender alerts from last {days_back} days...")
        
        # Fetch security data
        alerts = self.client.get_security_alerts(top=200, days_back=days_back)
        incidents = self.client.get_security_incidents(top=50, days_back=days_back)
        
        # Analyze different aspects
        results = {
            'summary': self._generate_alert_summary(alerts),
            'critical_alerts': self._identify_critical_alerts(alerts),
            'alert_trends': self._analyze_alert_trends(alerts),
            'affected_assets': self._analyze_affected_assets(alerts),
            'threat_categories': self._categorize_threats(alerts),
            'incidents': self._analyze_incidents(incidents),
            'mitigation_status': self._check_mitigation_status(alerts),
            'recommendations': []
        }
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _generate_alert_summary(self, alerts: List[Dict]) -> Dict:
        """Generate summary statistics for alerts"""
        if not alerts:
            return {
                'total_alerts': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'new_alerts': 0,
                'in_progress': 0,
                'resolved': 0
            }
        
        severity_counts = Counter(alert.get('severity', 'unknown') for alert in alerts)
        status_counts = Counter(alert.get('status', 'unknown') for alert in alerts)
        
        # Count new alerts (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        new_alerts = sum(1 for alert in alerts 
                        if self._parse_datetime(alert.get('createdDateTime', '')) > yesterday)
        
        return {
            'total_alerts': len(alerts),
            'high_severity': severity_counts.get('high', 0),
            'medium_severity': severity_counts.get('medium', 0),
            'low_severity': severity_counts.get('low', 0),
            'new_alerts': new_alerts,
            'in_progress': status_counts.get('inProgress', 0),
            'resolved': status_counts.get('resolved', 0)
        }
    
    def _identify_critical_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Identify critical alerts requiring immediate attention"""
        critical = []
        
        for alert in alerts:
            is_critical = False
            reasons = []
            
            # Check severity
            if alert.get('severity') == 'high':
                is_critical = True
                reasons.append("High severity")
            
            # Check threat category
            categories = alert.get('category', '').split(',')
            for category in categories:
                if any(crit in category for crit in self.CRITICAL_CATEGORIES):
                    is_critical = True
                    reasons.append(f"Critical category: {category}")
            
            # Check if alert is active
            if alert.get('status') in ['new', 'inProgress']:
                if is_critical:
                    reasons.append("Alert is active")
            
            # Check for persistence or lateral movement
            title = alert.get('title', '').lower()
            if any(term in title for term in ['persistence', 'lateral movement', 'privilege escalation', 'ransomware']):
                is_critical = True
                reasons.append("High-risk activity detected")
            
            if is_critical and alert.get('status') != 'resolved':
                critical.append({
                    'id': alert.get('id', ''),
                    'title': alert.get('title', ''),
                    'severity': alert.get('severity', ''),
                    'category': alert.get('category', ''),
                    'created': alert.get('createdDateTime', ''),
                    'status': alert.get('status', ''),
                    'affected_devices': self._extract_affected_devices(alert),
                    'reasons': reasons,
                    'description': alert.get('description', '')[:200]  # First 200 chars
                })
        
        # Sort by severity and creation time
        critical.sort(key=lambda x: (
            self.SEVERITY_PRIORITY.get(x['severity'], 5),
            x['created']
        ))
        
        return critical[:10]  # Return top 10 critical alerts
    
    def _analyze_alert_trends(self, alerts: List[Dict]) -> Dict:
        """Analyze trends in alerts over time"""
        trends = {
            'daily_counts': defaultdict(int),
            'severity_trends': defaultdict(lambda: defaultdict(int)),
            'category_trends': defaultdict(int),
            'increasing_threats': []
        }
        
        for alert in alerts:
            # Get date
            created = self._parse_datetime(alert.get('createdDateTime', ''))
            if created:
                date_key = created.strftime('%Y-%m-%d')
                trends['daily_counts'][date_key] += 1
                
                severity = alert.get('severity', 'unknown')
                trends['severity_trends'][date_key][severity] += 1
                
                category = alert.get('category', 'unknown')
                trends['category_trends'][category] += 1
        
        # Convert defaultdicts to regular dicts
        trends['daily_counts'] = dict(trends['daily_counts'])
        trends['severity_trends'] = {k: dict(v) for k, v in trends['severity_trends'].items()}
        trends['category_trends'] = dict(sorted(
            trends['category_trends'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10])
        
        # Identify increasing threats
        if len(trends['daily_counts']) >= 3:
            dates = sorted(trends['daily_counts'].keys())
            recent_avg = sum(trends['daily_counts'][d] for d in dates[-3:]) / 3
            older_avg = sum(trends['daily_counts'][d] for d in dates[:-3]) / max(len(dates) - 3, 1)
            
            if recent_avg > older_avg * 1.5:
                trends['increasing_threats'].append({
                    'observation': 'Alert volume increased by 50% in last 3 days',
                    'recent_daily_average': round(recent_avg, 1),
                    'previous_daily_average': round(older_avg, 1)
                })
        
        return trends
    
    def _analyze_affected_assets(self, alerts: List[Dict]) -> Dict:
        """Analyze which assets are most affected"""
        assets = {
            'devices': defaultdict(list),
            'users': defaultdict(list),
            'most_targeted_devices': [],
            'most_targeted_users': []
        }
        
        for alert in alerts:
            # Extract device information
            devices = self._extract_affected_devices(alert)
            for device in devices:
                assets['devices'][device].append({
                    'alert_id': alert.get('id'),
                    'severity': alert.get('severity'),
                    'title': alert.get('title')
                })
            
            # Extract user information
            users = self._extract_affected_users(alert)
            for user in users:
                assets['users'][user].append({
                    'alert_id': alert.get('id'),
                    'severity': alert.get('severity'),
                    'title': alert.get('title')
                })
        
        # Identify most targeted assets
        if assets['devices']:
            device_counts = [(device, len(alerts)) for device, alerts in assets['devices'].items()]
            device_counts.sort(key=lambda x: x[1], reverse=True)
            assets['most_targeted_devices'] = [
                {'device': d, 'alert_count': c} for d, c in device_counts[:5]
            ]
        
        if assets['users']:
            user_counts = [(user, len(alerts)) for user, alerts in assets['users'].items()]
            user_counts.sort(key=lambda x: x[1], reverse=True)
            assets['most_targeted_users'] = [
                {'user': u, 'alert_count': c} for u, c in user_counts[:5]
            ]
        
        # Convert defaultdicts for serialization
        assets['devices'] = dict(assets['devices'])
        assets['users'] = dict(assets['users'])
        
        return assets
    
    def _categorize_threats(self, alerts: List[Dict]) -> Dict:
        """Categorize threats by type and tactics"""
        categories = {
            'by_category': Counter(),
            'by_provider': Counter(),
            'mitre_tactics': Counter(),
            'threat_families': []
        }
        
        for alert in alerts:
            # Count by category
            category = alert.get('category', 'unknown')
            categories['by_category'][category] += 1
            
            # Count by provider
            provider = alert.get('providerDisplayName', 'unknown')
            categories['by_provider'][provider] += 1
            
            # Extract MITRE ATT&CK tactics if available
            tactics = alert.get('mitreTechniques', [])
            for tactic in tactics:
                categories['mitre_tactics'][tactic] += 1
            
            # Look for threat families in title/description
            title = alert.get('title', '')
            if 'emotet' in title.lower():
                categories['threat_families'].append('Emotet')
            elif 'cobaltstrike' in title.lower():
                categories['threat_families'].append('CobaltStrike')
            elif 'mimikatz' in title.lower():
                categories['threat_families'].append('Mimikatz')
        
        # Convert Counters to dicts
        categories['by_category'] = dict(categories['by_category'].most_common(10))
        categories['by_provider'] = dict(categories['by_provider'])
        categories['mitre_tactics'] = dict(categories['mitre_tactics'].most_common(10))
        categories['threat_families'] = list(set(categories['threat_families']))
        
        return categories
    
    def _analyze_incidents(self, incidents: List[Dict]) -> Dict:
        """Analyze security incidents"""
        incident_analysis = {
            'total_incidents': len(incidents),
            'active_incidents': 0,
            'high_severity_incidents': 0,
            'incident_list': []
        }
        
        for incident in incidents:
            if incident.get('status') in ['active', 'inProgress']:
                incident_analysis['active_incidents'] += 1
            
            if incident.get('severity') == 'high':
                incident_analysis['high_severity_incidents'] += 1
            
            # Add incident details
            incident_analysis['incident_list'].append({
                'id': incident.get('id'),
                'title': incident.get('displayName', incident.get('title', '')),
                'severity': incident.get('severity'),
                'status': incident.get('status'),
                'created': incident.get('createdDateTime'),
                'alert_count': len(incident.get('alerts', [])),
                'assigned_to': incident.get('assignedTo', 'Unassigned')
            })
        
        # Sort by severity and creation time
        incident_analysis['incident_list'].sort(key=lambda x: (
            self.SEVERITY_PRIORITY.get(x['severity'], 5),
            x['created']
        ))
        
        return incident_analysis
    
    def _check_mitigation_status(self, alerts: List[Dict]) -> Dict:
        """Check mitigation and remediation status"""
        mitigation = {
            'automated_remediations': 0,
            'pending_remediations': 0,
            'manual_investigation_needed': 0,
            'resolved_automatically': 0
        }
        
        for alert in alerts:
            # Check remediation status
            if alert.get('status') == 'resolved':
                if 'automated' in alert.get('comments', '').lower():
                    mitigation['resolved_automatically'] += 1
            elif alert.get('status') in ['new', 'inProgress']:
                if alert.get('severity') == 'high':
                    mitigation['manual_investigation_needed'] += 1
                else:
                    mitigation['pending_remediations'] += 1
        
        return mitigation
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Check critical alerts
        critical_alerts = analysis.get('critical_alerts', [])
        if critical_alerts:
            recommendations.append(f"🚨 URGENT: {len(critical_alerts)} critical alerts require immediate investigation")
            for alert in critical_alerts[:3]:
                recommendations.append(f"  - Investigate: {alert['title']}")
        
        # Check incident status
        incidents = analysis.get('incidents', {})
        if incidents.get('active_incidents', 0) > 0:
            recommendations.append(f"📊 {incidents['active_incidents']} active incidents need attention")
        
        # Check affected assets
        assets = analysis.get('affected_assets', {})
        if assets.get('most_targeted_devices'):
            top_device = assets['most_targeted_devices'][0]
            recommendations.append(f"🖥️ Device '{top_device['device']}' has {top_device['alert_count']} alerts - consider isolation and investigation")
        
        # Check trends
        trends = analysis.get('alert_trends', {})
        if trends.get('increasing_threats'):
            recommendations.append("📈 Alert volume is increasing - review security posture and consider threat hunting")
        
        # Check threat categories
        categories = analysis.get('threat_categories', {})
        top_category = list(categories.get('by_category', {}).keys())[0] if categories.get('by_category') else None
        if top_category in self.CRITICAL_CATEGORIES:
            recommendations.append(f"⚠️ High number of '{top_category}' alerts - review defense strategies")
        
        # Check mitigation status
        mitigation = analysis.get('mitigation_status', {})
        if mitigation.get('manual_investigation_needed', 0) > 5:
            recommendations.append(f"🔍 {mitigation['manual_investigation_needed']} high-severity alerts need manual investigation")
        
        if not recommendations:
            recommendations.append("✅ Security posture appears stable - continue monitoring")
        
        return recommendations
    
    # Helper methods
    
    def _parse_datetime(self, date_string: str) -> Optional[datetime]:
        """Parse ISO datetime string"""
        if not date_string:
            return None
        try:
            return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        except:
            return None
    
    def _extract_affected_devices(self, alert: Dict) -> List[str]:
        """Extract affected device names from alert"""
        devices = []
        
        # Check evidence field
        evidence = alert.get('evidence', [])
        for item in evidence:
            if item.get('deviceDnsName'):
                devices.append(item['deviceDnsName'])
        
        # Check entities field
        entities = alert.get('entities', [])
        for entity in entities:
            if entity.get('entityType') == 'Device':
                device_name = entity.get('deviceDnsName', entity.get('deviceName', ''))
                if device_name:
                    devices.append(device_name)
        
        return list(set(devices))
    
    def _extract_affected_users(self, alert: Dict) -> List[str]:
        """Extract affected user names from alert"""
        users = []
        
        # Check evidence field
        evidence = alert.get('evidence', [])
        for item in evidence:
            if item.get('userPrincipalName'):
                users.append(item['userPrincipalName'])
        
        # Check entities field
        entities = alert.get('entities', [])
        for entity in entities:
            if entity.get('entityType') == 'User':
                user_name = entity.get('userPrincipalName', entity.get('accountName', ''))
                if user_name:
                    users.append(user_name)
        
        return list(set(users))
    
    def generate_report(self, analysis: Dict) -> str:
        """Generate markdown report from analysis"""
        report = []
        report.append("# Microsoft Defender Security Analysis Report")
        report.append(f"\nGenerated: {datetime.utcnow().isoformat()}Z\n")
        
        # Summary
        summary = analysis.get('summary', {})
        report.append("## Alert Summary")
        report.append(f"- Total alerts: {summary.get('total_alerts', 0)}")
        report.append(f"- High severity: {summary.get('high_severity', 0)}")
        report.append(f"- Medium severity: {summary.get('medium_severity', 0)}")
        report.append(f"- New alerts (24h): {summary.get('new_alerts', 0)}")
        report.append(f"- In progress: {summary.get('in_progress', 0)}\n")
        
        # Critical Alerts
        critical = analysis.get('critical_alerts', [])
        if critical:
            report.append("## 🚨 Critical Alerts")
            for alert in critical[:5]:
                report.append(f"\n**{alert['title']}**")
                report.append(f"- Severity: {alert['severity']}")
                report.append(f"- Status: {alert['status']}")
                report.append(f"- Category: {alert['category']}")
                report.append(f"- Created: {alert['created']}")
                if alert['affected_devices']:
                    report.append(f"- Devices: {', '.join(alert['affected_devices'])}")
        
        # Incidents
        incidents = analysis.get('incidents', {})
        if incidents.get('incident_list'):
            report.append("\n## 📊 Active Incidents")
            report.append(f"Total incidents: {incidents['total_incidents']}")
            report.append(f"Active incidents: {incidents['active_incidents']}")
            for incident in incidents['incident_list'][:3]:
                report.append(f"\n- **{incident['title']}**")
                report.append(f"  - Severity: {incident['severity']}, Status: {incident['status']}")
                report.append(f"  - Alerts: {incident['alert_count']}, Assigned to: {incident['assigned_to']}")
        
        # Most Affected Assets
        assets = analysis.get('affected_assets', {})
        if assets.get('most_targeted_devices'):
            report.append("\n## 🖥️ Most Targeted Devices")
            for device in assets['most_targeted_devices']:
                report.append(f"- {device['device']}: {device['alert_count']} alerts")
        
        # Recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            report.append("\n## 📋 Recommendations")
            for rec in recommendations:
                report.append(f"{rec}")
        
        return "\n".join(report)


if __name__ == "__main__":
    # Test analyzer
    logging.basicConfig(level=logging.INFO)
    print("Defender Analyzer module loaded successfully")