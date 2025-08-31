"""
Sign-in log analyzer for detecting anomalies and security issues
Analyzes Entra ID sign-in logs for suspicious patterns
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json

logger = logging.getLogger(__name__)


class SignInAnalyzer:
    """Analyzes sign-in logs for security insights"""
    
    def __init__(self, api_client):
        """
        Initialize analyzer
        
        Args:
            api_client: GraphAPIClient instance
        """
        self.client = api_client
        
        # Risk thresholds
        self.FAILED_SIGNIN_THRESHOLD = 5  # Alert if user has >5 failed sign-ins
        self.NEW_LOCATION_RISK = True     # Flag sign-ins from new locations
        self.LEGACY_AUTH_RISK = True      # Flag legacy authentication
        
        # Known good locations (customize for your organization)
        self.trusted_locations = []
        self.trusted_countries = ['US', 'United States']  # Add your countries
    
    def analyze_recent_signins(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Comprehensive analysis of recent sign-in activity
        
        Args:
            hours_back: Hours to analyze
        
        Returns:
            Analysis results dictionary
        """
        logger.info(f"Analyzing sign-ins from last {hours_back} hours...")
        
        # Fetch sign-in data
        all_signins = self.client.get_sign_in_logs(hours_back=hours_back)
        failed_signins = self.client.get_sign_in_logs(hours_back=hours_back, failed_only=True)
        ca_failures = self.client.get_conditional_access_failures(hours_back=hours_back)
        
        # Analyze different aspects
        results = {
            'summary': self._generate_summary(all_signins, failed_signins),
            'risky_signins': self._identify_risky_signins(all_signins),
            'failed_mfa': self._analyze_mfa_failures(all_signins),
            'suspicious_patterns': self._detect_suspicious_patterns(all_signins),
            'conditional_access': self._analyze_ca_failures(ca_failures),
            'legacy_auth': self._detect_legacy_auth(all_signins),
            'guest_activity': self._analyze_guest_activity(all_signins),
            'location_analysis': self._analyze_locations(all_signins),
            'recommendations': []
        }
        
        # Generate recommendations based on findings
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _generate_summary(self, all_signins: List[Dict], failed_signins: List[Dict]) -> Dict:
        """Generate summary statistics"""
        if not all_signins:
            return {
                'total_signins': 0,
                'unique_users': 0,
                'failed_signins': 0,
                'success_rate': 100.0
            }
        
        unique_users = len(set(s.get('userPrincipalName', '') for s in all_signins))
        
        return {
            'total_signins': len(all_signins),
            'unique_users': unique_users,
            'failed_signins': len(failed_signins),
            'success_rate': round(((len(all_signins) - len(failed_signins)) / len(all_signins)) * 100, 2)
        }
    
    def _identify_risky_signins(self, signins: List[Dict]) -> List[Dict]:
        """Identify potentially risky sign-ins"""
        risky = []
        
        for signin in signins:
            risk_factors = []
            
            # Check risk level from Identity Protection
            risk_level = signin.get('riskLevelDuringSignIn', '')
            if risk_level in ['medium', 'high']:
                risk_factors.append(f"Risk level: {risk_level}")
            
            # Check for anonymous IP
            if signin.get('ipAddress', '').startswith('10.') or signin.get('ipAddress', '').startswith('192.168.'):
                pass  # Internal IP, likely safe
            elif self._is_tor_or_vpn(signin.get('ipAddress', '')):
                risk_factors.append("TOR/VPN detected")
            
            # Check for impossible travel
            if self._check_impossible_travel(signin, signins):
                risk_factors.append("Impossible travel detected")
            
            # Check for unusual application
            client_app = signin.get('clientAppUsed', '')
            if client_app in ['IMAP4', 'POP3', 'SMTP Auth', 'Exchange ActiveSync']:
                risk_factors.append(f"Legacy protocol: {client_app}")
            
            if risk_factors:
                risky.append({
                    'user': signin.get('userPrincipalName', 'Unknown'),
                    'timestamp': signin.get('createdDateTime', ''),
                    'ip_address': signin.get('ipAddress', ''),
                    'location': self._get_location_string(signin),
                    'risk_factors': risk_factors,
                    'status': 'Success' if signin.get('status', {}).get('errorCode', 0) == 0 else 'Failed'
                })
        
        return risky
    
    def _analyze_mfa_failures(self, signins: List[Dict]) -> Dict:
        """Analyze MFA-related failures"""
        mfa_stats = {
            'total_mfa_prompts': 0,
            'mfa_failures': 0,
            'users_failing_mfa': defaultdict(int),
            'mfa_bypass_attempts': 0
        }
        
        for signin in signins:
            mfa_detail = signin.get('mfaDetail', {})
            if mfa_detail:
                mfa_stats['total_mfa_prompts'] += 1
                
                # Check if MFA failed
                auth_methods = mfa_detail.get('authMethod', '')
                if signin.get('status', {}).get('errorCode', 0) == 50074:  # MFA required but not completed
                    mfa_stats['mfa_failures'] += 1
                    user = signin.get('userPrincipalName', 'Unknown')
                    mfa_stats['users_failing_mfa'][user] += 1
        
        # Convert defaultdict to regular dict for JSON serialization
        mfa_stats['users_failing_mfa'] = dict(mfa_stats['users_failing_mfa'])
        
        return mfa_stats
    
    def _detect_suspicious_patterns(self, signins: List[Dict]) -> List[Dict]:
        """Detect suspicious patterns like brute force attempts"""
        patterns = []
        
        # Group by user and IP
        user_attempts = defaultdict(list)
        ip_attempts = defaultdict(list)
        
        for signin in signins:
            user = signin.get('userPrincipalName', '')
            ip = signin.get('ipAddress', '')
            
            if user:
                user_attempts[user].append(signin)
            if ip:
                ip_attempts[ip].append(signin)
        
        # Check for brute force by user
        for user, attempts in user_attempts.items():
            failed_count = sum(1 for a in attempts if a.get('status', {}).get('errorCode', 0) != 0)
            
            if failed_count >= self.FAILED_SIGNIN_THRESHOLD:
                patterns.append({
                    'type': 'Potential brute force',
                    'user': user,
                    'failed_attempts': failed_count,
                    'total_attempts': len(attempts),
                    'time_range': self._get_time_range(attempts)
                })
        
        # Check for password spray (multiple users from same IP)
        for ip, attempts in ip_attempts.items():
            unique_users = set(a.get('userPrincipalName', '') for a in attempts)
            failed_users = set(a.get('userPrincipalName', '') for a in attempts 
                              if a.get('status', {}).get('errorCode', 0) != 0)
            
            if len(failed_users) >= 5:  # 5+ different users failing from same IP
                patterns.append({
                    'type': 'Potential password spray',
                    'source_ip': ip,
                    'targeted_users': len(unique_users),
                    'failed_users': len(failed_users),
                    'location': self._get_location_from_ip(ip, attempts[0])
                })
        
        return patterns
    
    def _analyze_ca_failures(self, ca_failures: List[Dict]) -> Dict:
        """Analyze Conditional Access policy failures"""
        analysis = {
            'total_failures': len(ca_failures),
            'by_policy': defaultdict(int),
            'by_user': defaultdict(int),
            'top_failure_reasons': []
        }
        
        for failure in ca_failures:
            # Get CA policies that were evaluated
            ca_policies = failure.get('appliedConditionalAccessPolicies', [])
            for policy in ca_policies:
                if policy.get('result') == 'failure':
                    policy_name = policy.get('displayName', 'Unknown Policy')
                    analysis['by_policy'][policy_name] += 1
            
            user = failure.get('userPrincipalName', 'Unknown')
            analysis['by_user'][user] += 1
        
        # Convert defaultdicts and get top failures
        analysis['by_policy'] = dict(analysis['by_policy'])
        analysis['by_user'] = dict(analysis['by_user'])
        
        if analysis['by_policy']:
            top_policies = sorted(analysis['by_policy'].items(), key=lambda x: x[1], reverse=True)[:5]
            analysis['top_failure_reasons'] = [{'policy': p, 'count': c} for p, c in top_policies]
        
        return analysis
    
    def _detect_legacy_auth(self, signins: List[Dict]) -> List[Dict]:
        """Detect usage of legacy authentication protocols"""
        legacy_signins = []
        legacy_protocols = ['IMAP4', 'POP3', 'SMTP Auth', 'Exchange ActiveSync', 
                          'Authenticated SMTP', 'Outlook Anywhere (RPC over HTTP)']
        
        for signin in signins:
            client_app = signin.get('clientAppUsed', '')
            if client_app in legacy_protocols:
                legacy_signins.append({
                    'user': signin.get('userPrincipalName', 'Unknown'),
                    'protocol': client_app,
                    'timestamp': signin.get('createdDateTime', ''),
                    'ip_address': signin.get('ipAddress', ''),
                    'status': 'Success' if signin.get('status', {}).get('errorCode', 0) == 0 else 'Failed'
                })
        
        return legacy_signins
    
    def _analyze_guest_activity(self, signins: List[Dict]) -> Dict:
        """Analyze guest user sign-in activity"""
        guest_activity = {
            'total_guest_signins': 0,
            'unique_guests': set(),
            'guest_locations': [],
            'suspicious_guests': []
        }
        
        for signin in signins:
            user_type = signin.get('userType', '')
            if user_type == 'guest':
                guest_activity['total_guest_signins'] += 1
                guest_activity['unique_guests'].add(signin.get('userPrincipalName', ''))
                
                # Check for suspicious guest activity
                location = self._get_location_string(signin)
                if location and location not in self.trusted_countries:
                    guest_activity['suspicious_guests'].append({
                        'user': signin.get('userPrincipalName', ''),
                        'location': location,
                        'timestamp': signin.get('createdDateTime', '')
                    })
        
        # Convert set to list for JSON serialization
        guest_activity['unique_guests'] = list(guest_activity['unique_guests'])
        
        return guest_activity
    
    def _analyze_locations(self, signins: List[Dict]) -> Dict:
        """Analyze geographic distribution of sign-ins"""
        location_stats = {
            'countries': Counter(),
            'cities': Counter(),
            'unusual_locations': [],
            'foreign_signins': []
        }
        
        for signin in signins:
            location = signin.get('location', {})
            country = location.get('countryOrRegion', 'Unknown')
            city = location.get('city', 'Unknown')
            
            if country != 'Unknown':
                location_stats['countries'][country] += 1
            if city != 'Unknown':
                location_stats['cities'][city] += 1
            
            # Flag foreign sign-ins
            if country not in self.trusted_countries and country != 'Unknown':
                location_stats['foreign_signins'].append({
                    'user': signin.get('userPrincipalName', ''),
                    'country': country,
                    'city': city,
                    'timestamp': signin.get('createdDateTime', '')
                })
        
        # Convert Counters to dict for JSON serialization
        location_stats['countries'] = dict(location_stats['countries'].most_common(10))
        location_stats['cities'] = dict(location_stats['cities'].most_common(10))
        
        return location_stats
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Check for high-risk findings
        if analysis['risky_signins']:
            recommendations.append("⚠️ Review and investigate risky sign-ins immediately")
        
        if analysis['legacy_auth']:
            recommendations.append("🔒 Block legacy authentication protocols via Conditional Access")
        
        if analysis['suspicious_patterns']:
            for pattern in analysis['suspicious_patterns']:
                if pattern['type'] == 'Potential brute force':
                    recommendations.append(f"🚨 Investigate potential brute force against {pattern['user']}")
                elif pattern['type'] == 'Potential password spray':
                    recommendations.append(f"🚨 Investigate potential password spray from {pattern['source_ip']}")
        
        mfa_stats = analysis.get('failed_mfa', {})
        if mfa_stats.get('users_failing_mfa'):
            recommendations.append("📱 Review users repeatedly failing MFA - may need assistance or compromise")
        
        ca_analysis = analysis.get('conditional_access', {})
        if ca_analysis.get('total_failures', 0) > 10:
            recommendations.append("📋 Review Conditional Access policies - high failure rate detected")
        
        location_analysis = analysis.get('location_analysis', {})
        if location_analysis.get('foreign_signins'):
            recommendations.append("🌍 Review sign-ins from foreign countries - verify if legitimate")
        
        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")
        
        return recommendations
    
    # Helper methods
    
    def _get_location_string(self, signin: Dict) -> str:
        """Extract location string from sign-in"""
        location = signin.get('location', {})
        city = location.get('city', '')
        country = location.get('countryOrRegion', '')
        
        if city and country:
            return f"{city}, {country}"
        elif country:
            return country
        return 'Unknown'
    
    def _get_location_from_ip(self, ip: str, signin: Dict) -> str:
        """Get location for an IP address"""
        return self._get_location_string(signin)
    
    def _is_tor_or_vpn(self, ip: str) -> bool:
        """Check if IP is from TOR or known VPN (simplified check)"""
        # This would need a real threat intelligence feed
        # For now, just flag some suspicious patterns
        suspicious_patterns = ['104.28.', '104.27.', '172.67.']  # Cloudflare IPs often used by VPNs
        return any(ip.startswith(pattern) for pattern in suspicious_patterns)
    
    def _check_impossible_travel(self, signin: Dict, all_signins: List[Dict]) -> bool:
        """Check for impossible travel scenarios"""
        # Simplified check - would need more sophisticated logic in production
        user = signin.get('userPrincipalName', '')
        signin_time = signin.get('createdDateTime', '')
        signin_location = signin.get('location', {}).get('countryOrRegion', '')
        
        if not all([user, signin_time, signin_location]):
            return False
        
        # Look for other sign-ins from same user within 1 hour
        try:
            current_time = datetime.fromisoformat(signin_time.replace('Z', '+00:00'))
            
            for other in all_signins:
                if other.get('userPrincipalName', '') != user:
                    continue
                if other.get('id') == signin.get('id'):
                    continue
                
                other_time = other.get('createdDateTime', '')
                other_location = other.get('location', {}).get('countryOrRegion', '')
                
                if other_time and other_location:
                    other_dt = datetime.fromisoformat(other_time.replace('Z', '+00:00'))
                    time_diff = abs((current_time - other_dt).total_seconds() / 3600)
                    
                    # If different country within 2 hours, flag as impossible travel
                    if time_diff < 2 and other_location != signin_location:
                        return True
        except Exception as e:
            logger.warning(f"Error checking impossible travel: {e}")
        
        return False
    
    def _get_time_range(self, attempts: List[Dict]) -> str:
        """Get time range string for attempts"""
        if not attempts:
            return "Unknown"
        
        times = [a.get('createdDateTime', '') for a in attempts if a.get('createdDateTime')]
        if not times:
            return "Unknown"
        
        times.sort()
        return f"{times[0]} to {times[-1]}"
    
    def generate_report(self, analysis: Dict) -> str:
        """Generate markdown report from analysis"""
        report = []
        report.append("# Sign-in Security Analysis Report")
        report.append(f"\nGenerated: {datetime.utcnow().isoformat()}Z\n")
        
        # Summary
        summary = analysis.get('summary', {})
        report.append("## Summary Statistics")
        report.append(f"- Total sign-ins: {summary.get('total_signins', 0)}")
        report.append(f"- Unique users: {summary.get('unique_users', 0)}")
        report.append(f"- Failed sign-ins: {summary.get('failed_signins', 0)}")
        report.append(f"- Success rate: {summary.get('success_rate', 0)}%\n")
        
        # Risky Sign-ins
        risky = analysis.get('risky_signins', [])
        if risky:
            report.append("## ⚠️ Risky Sign-ins Detected")
            for item in risky[:5]:  # Show top 5
                report.append(f"\n**User:** {item['user']}")
                report.append(f"- Time: {item['timestamp']}")
                report.append(f"- Location: {item['location']}")
                report.append(f"- Risk factors: {', '.join(item['risk_factors'])}")
        
        # Suspicious Patterns
        patterns = analysis.get('suspicious_patterns', [])
        if patterns:
            report.append("\n## 🚨 Suspicious Patterns")
            for pattern in patterns:
                report.append(f"\n**{pattern['type']}**")
                for key, value in pattern.items():
                    if key != 'type':
                        report.append(f"- {key}: {value}")
        
        # Legacy Authentication
        legacy = analysis.get('legacy_auth', [])
        if legacy:
            report.append("\n## 🔓 Legacy Authentication Usage")
            report.append("The following users are using insecure legacy protocols:")
            for item in legacy[:5]:
                report.append(f"- {item['user']} using {item['protocol']} from {item['ip_address']}")
        
        # Recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            report.append("\n## 📋 Recommendations")
            for rec in recommendations:
                report.append(f"- {rec}")
        
        return "\n".join(report)


if __name__ == "__main__":
    # Test analyzer
    logging.basicConfig(level=logging.INFO)
    print("Sign-in Analyzer module loaded successfully")