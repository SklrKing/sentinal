#!/usr/bin/env python3
"""
Microsoft Defender & Entra Security Agent
Main orchestrator for automated security monitoring and reporting
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
import subprocess

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth_handler import AuthenticationHandler
from api_client import GraphAPIClient
from analyzers.signin_analyzer import SignInAnalyzer
from analyzers.defender_analyzer import DefenderAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('defender_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DefenderAgent:
    """Main orchestrator for security monitoring"""
    
    def __init__(self, config_path: str = "agent_config.json"):
        """
        Initialize the Defender Agent
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        logger.info("Initializing Defender Agent...")
        self.auth = AuthenticationHandler(config_path)
        self.client = GraphAPIClient(self.auth)
        self.signin_analyzer = SignInAnalyzer(self.client)
        self.defender_analyzer = DefenderAnalyzer(self.client)
        
        # Report settings
        self.report_dir = Path(self.config.get('report_directory', './reports'))
        self.report_dir.mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load agent configuration"""
        config_path = Path(self.config_path)
        
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        # Return default config if file doesn't exist
        return {
            'report_directory': './reports',
            'github_integration': False,
            'slack_webhook': None,
            'email_recipients': [],
            'analysis_settings': {
                'signin_hours_back': 24,
                'defender_days_back': 7,
                'risk_threshold': 'medium'
            }
        }
    
    def run_daily_analysis(self) -> Dict[str, Any]:
        """Run daily security analysis (per SECURITY_CHECKLIST.md)"""
        logger.info("Starting daily security analysis...")
        
        results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'analysis_type': 'daily',
            'components': {}
        }
        
        try:
            # 1. Review Microsoft Defender alerts
            logger.info("Analyzing Defender alerts...")
            defender_analysis = self.defender_analyzer.analyze_security_alerts(days_back=1)
            results['components']['defender'] = defender_analysis
            
            # 2. Check Entra risky sign-ins
            logger.info("Analyzing sign-in logs...")
            signin_analysis = self.signin_analyzer.analyze_recent_signins(hours_back=24)
            results['components']['signins'] = signin_analysis
            
            # 3. Get risky users
            logger.info("Checking risky users...")
            risky_users = self.client.get_risky_users()
            results['components']['risky_users'] = {
                'count': len(risky_users),
                'users': [{'user': u.get('userPrincipalName'), 
                          'risk_level': u.get('riskLevel'),
                          'risk_state': u.get('riskState')} for u in risky_users[:10]]
            }
            
            # Generate combined recommendations
            results['combined_recommendations'] = self._generate_combined_recommendations(results)
            
            # Save report
            self._save_report(results, 'daily')
            
            # Send notifications if configured
            self._send_notifications(results, 'daily')
            
            logger.info("Daily analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during daily analysis: {e}")
            results['error'] = str(e)
        
        return results
    
    def run_weekly_analysis(self) -> Dict[str, Any]:
        """Run weekly security analysis (per SECURITY_CHECKLIST.md)"""
        logger.info("Starting weekly security analysis...")
        
        results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'analysis_type': 'weekly',
            'components': {}
        }
        
        try:
            # 1. Comprehensive Defender analysis
            logger.info("Running comprehensive Defender analysis...")
            defender_analysis = self.defender_analyzer.analyze_security_alerts(days_back=7)
            results['components']['defender'] = defender_analysis
            
            # 2. Sign-in pattern analysis
            logger.info("Analyzing sign-in patterns...")
            signin_analysis = self.signin_analyzer.analyze_recent_signins(hours_back=168)  # 7 days
            results['components']['signins'] = signin_analysis
            
            # 3. Conditional Access effectiveness
            logger.info("Checking Conditional Access...")
            ca_failures = self.client.get_conditional_access_failures(hours_back=168)
            results['components']['conditional_access'] = {
                'total_failures': len(ca_failures),
                'top_failures': self._summarize_ca_failures(ca_failures)
            }
            
            # 4. Guest user review
            logger.info("Reviewing guest users...")
            guest_users = self.client.get_guest_users()
            results['components']['guest_users'] = {
                'total_guests': len(guest_users),
                'recent_guests': self._get_recent_guests(guest_users)
            }
            
            # 5. Device compliance
            logger.info("Checking device compliance...")
            non_compliant = self.client.get_non_compliant_devices()
            results['components']['device_compliance'] = {
                'non_compliant_count': len(non_compliant),
                'devices': [{'name': d.get('deviceName'), 
                           'user': d.get('userPrincipalName')} for d in non_compliant[:10]]
            }
            
            # Generate recommendations
            results['combined_recommendations'] = self._generate_combined_recommendations(results)
            
            # Save report
            self._save_report(results, 'weekly')
            
            # Send notifications
            self._send_notifications(results, 'weekly')
            
            logger.info("Weekly analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during weekly analysis: {e}")
            results['error'] = str(e)
        
        return results
    
    def run_security_check(self, check_type: str = 'quick') -> Dict[str, Any]:
        """
        Run a specific security check
        
        Args:
            check_type: Type of check ('quick', 'signin', 'defender', 'full')
        
        Returns:
            Analysis results
        """
        logger.info(f"Running {check_type} security check...")
        
        results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'check_type': check_type
        }
        
        try:
            if check_type == 'quick':
                # Quick check - last 4 hours
                results['defender'] = self.defender_analyzer.analyze_security_alerts(days_back=1)
                results['signins'] = self.signin_analyzer.analyze_recent_signins(hours_back=4)
                
            elif check_type == 'signin':
                # Detailed sign-in analysis
                results['signins'] = self.signin_analyzer.analyze_recent_signins(hours_back=24)
                
            elif check_type == 'defender':
                # Detailed Defender analysis
                results['defender'] = self.defender_analyzer.analyze_security_alerts(days_back=7)
                
            elif check_type == 'full':
                # Full analysis
                return self.run_weekly_analysis()
            
            else:
                raise ValueError(f"Unknown check type: {check_type}")
            
            logger.info(f"{check_type.capitalize()} check completed")
            
        except Exception as e:
            logger.error(f"Error during {check_type} check: {e}")
            results['error'] = str(e)
        
        return results
    
    def test_connection(self) -> bool:
        """Test API connection and permissions"""
        logger.info("Testing API connection and permissions...")
        
        try:
            # Test authentication
            if not self.auth.test_connection():
                logger.error("Authentication test failed")
                return False
            
            # Test API permissions
            permissions = self.client.test_permissions()
            
            # Report results
            logger.info("\nPermission Test Results:")
            for endpoint, available in permissions.items():
                status = "✅" if available else "❌"
                logger.info(f"{status} {endpoint}")
            
            # Check if minimum required permissions are available
            required = ['Security Alerts', 'Sign-in Logs', 'Users']
            missing = [p for p in required if not permissions.get(p, False)]
            
            if missing:
                logger.warning(f"Missing required permissions: {', '.join(missing)}")
                logger.warning("Please review Azure app permissions")
                return False
            
            logger.info("All required permissions are available")
            return True
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def _generate_combined_recommendations(self, results: Dict) -> list:
        """Generate combined recommendations from all analyses"""
        recommendations = []
        priority_order = []
        
        # Collect all recommendations
        for component, data in results.get('components', {}).items():
            if isinstance(data, dict) and 'recommendations' in data:
                for rec in data['recommendations']:
                    # Assign priority based on emoji indicators
                    if '🚨' in rec or 'URGENT' in rec:
                        priority = 1
                    elif '⚠️' in rec:
                        priority = 2
                    elif '📊' in rec or '🔍' in rec:
                        priority = 3
                    else:
                        priority = 4
                    
                    priority_order.append((priority, rec))
        
        # Sort by priority
        priority_order.sort(key=lambda x: x[0])
        
        # Return top recommendations
        recommendations = [rec for _, rec in priority_order[:10]]
        
        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")
        
        return recommendations
    
    def _save_report(self, results: Dict, report_type: str):
        """Save analysis report to file"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        # Save JSON report
        json_file = self.report_dir / f"{report_type}_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"JSON report saved to {json_file}")
        
        # Generate and save markdown report
        md_file = self.report_dir / f"{report_type}_report_{timestamp}.md"
        md_content = self._generate_markdown_report(results)
        with open(md_file, 'w') as f:
            f.write(md_content)
        logger.info(f"Markdown report saved to {md_file}")
    
    def _generate_markdown_report(self, results: Dict) -> str:
        """Generate comprehensive markdown report"""
        report = []
        
        # Header
        analysis_type = results.get('analysis_type', 'Security').title()
        report.append(f"# {analysis_type} Security Analysis Report")
        report.append(f"\nGenerated: {results.get('timestamp', datetime.utcnow().isoformat())}Z\n")
        
        # Executive Summary
        report.append("## Executive Summary\n")
        
        # Check for critical issues
        critical_count = 0
        components = results.get('components', {})
        
        if 'defender' in components:
            critical_count += len(components['defender'].get('critical_alerts', []))
        
        if 'signins' in components:
            critical_count += len(components['signins'].get('risky_signins', []))
        
        if critical_count > 0:
            report.append(f"⚠️ **{critical_count} critical security issues require immediate attention**\n")
        else:
            report.append("✅ No critical security issues detected\n")
        
        # Top Recommendations
        recommendations = results.get('combined_recommendations', [])
        if recommendations:
            report.append("## Priority Actions\n")
            for i, rec in enumerate(recommendations[:5], 1):
                report.append(f"{i}. {rec}")
            report.append("")
        
        # Component Reports
        if 'defender' in components:
            defender_data = components['defender']
            report.append("\n## Microsoft Defender Analysis\n")
            
            summary = defender_data.get('summary', {})
            report.append(f"- Total alerts: {summary.get('total_alerts', 0)}")
            report.append(f"- High severity: {summary.get('high_severity', 0)}")
            report.append(f"- New alerts (24h): {summary.get('new_alerts', 0)}\n")
            
            critical = defender_data.get('critical_alerts', [])
            if critical:
                report.append("### Critical Alerts\n")
                for alert in critical[:3]:
                    report.append(f"- **{alert['title']}**")
                    report.append(f"  - Severity: {alert['severity']}, Status: {alert['status']}")
        
        if 'signins' in components:
            signin_data = components['signins']
            report.append("\n## Sign-in Analysis\n")
            
            summary = signin_data.get('summary', {})
            report.append(f"- Total sign-ins: {summary.get('total_signins', 0)}")
            report.append(f"- Failed sign-ins: {summary.get('failed_signins', 0)}")
            report.append(f"- Success rate: {summary.get('success_rate', 0)}%\n")
            
            risky = signin_data.get('risky_signins', [])
            if risky:
                report.append("### Risky Sign-ins\n")
                for signin in risky[:3]:
                    report.append(f"- {signin['user']} from {signin['location']}")
                    report.append(f"  - Risk: {', '.join(signin['risk_factors'])}")
        
        # Footer
        report.append("\n---")
        report.append("\n*Report generated by Defender Security Agent*")
        report.append("*Review Azure portal for detailed information*")
        
        return "\n".join(report)
    
    def _send_notifications(self, results: Dict, report_type: str):
        """Send notifications based on configuration"""
        # Check for critical issues
        has_critical = False
        components = results.get('components', {})
        
        if 'defender' in components:
            if components['defender'].get('critical_alerts'):
                has_critical = True
        
        if 'signins' in components:
            if components['signins'].get('risky_signins'):
                has_critical = True
        
        # GitHub Issues integration
        if self.config.get('github_integration') and has_critical:
            self._create_github_issue(results, report_type)
        
        # Slack notification
        if self.config.get('slack_webhook'):
            self._send_slack_notification(results, report_type)
    
    def _create_github_issue(self, results: Dict, report_type: str):
        """Create GitHub issue for critical findings"""
        try:
            # This would integrate with your GitHub repo
            logger.info("GitHub issue creation would happen here")
            # Implementation would use GitHub API or gh CLI
        except Exception as e:
            logger.error(f"Failed to create GitHub issue: {e}")
    
    def _send_slack_notification(self, results: Dict, report_type: str):
        """Send Slack notification"""
        try:
            # This would send to Slack webhook
            logger.info("Slack notification would be sent here")
            # Implementation would use requests to post to webhook
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
    
    def _summarize_ca_failures(self, failures: list) -> list:
        """Summarize Conditional Access failures"""
        policy_counts = {}
        for failure in failures:
            policies = failure.get('appliedConditionalAccessPolicies', [])
            for policy in policies:
                if policy.get('result') == 'failure':
                    name = policy.get('displayName', 'Unknown')
                    policy_counts[name] = policy_counts.get(name, 0) + 1
        
        return [{'policy': k, 'count': v} for k, v in 
                sorted(policy_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    def _get_recent_guests(self, guests: list) -> list:
        """Get recently added guest users"""
        recent = []
        cutoff = datetime.utcnow() - timedelta(days=30)
        
        for guest in guests:
            created = guest.get('createdDateTime', '')
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    if created_dt > cutoff:
                        recent.append({
                            'user': guest.get('userPrincipalName'),
                            'created': created
                        })
                except:
                    pass
        
        return recent[:10]


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Microsoft Defender & Entra Security Agent')
    parser.add_argument('--config', default='agent_config.json', help='Path to configuration file')
    parser.add_argument('--test', action='store_true', help='Test connection and permissions')
    parser.add_argument('--daily', action='store_true', help='Run daily analysis')
    parser.add_argument('--weekly', action='store_true', help='Run weekly analysis')
    parser.add_argument('--check', choices=['quick', 'signin', 'defender', 'full'], 
                       help='Run specific security check')
    
    args = parser.parse_args()
    
    # Initialize agent
    try:
        agent = DefenderAgent(args.config)
    except Exception as e:
        logger.error(f"Failed to initialize agent: {e}")
        sys.exit(1)
    
    # Execute requested action
    if args.test:
        success = agent.test_connection()
        sys.exit(0 if success else 1)
    
    elif args.daily:
        results = agent.run_daily_analysis()
        if 'error' in results:
            sys.exit(1)
    
    elif args.weekly:
        results = agent.run_weekly_analysis()
        if 'error' in results:
            sys.exit(1)
    
    elif args.check:
        results = agent.run_security_check(args.check)
        if 'error' in results:
            sys.exit(1)
    
    else:
        # Default: run daily analysis
        results = agent.run_daily_analysis()
        if 'error' in results:
            sys.exit(1)
    
    logger.info("Agent execution completed")


if __name__ == "__main__":
    main()