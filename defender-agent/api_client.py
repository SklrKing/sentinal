"""
Microsoft Graph API client wrapper for security operations
Provides simplified methods for common security queries
"""

import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class GraphAPIClient:
    """Microsoft Graph API client for security operations"""
    
    BASE_URL = "https://graph.microsoft.com/v1.0"
    BETA_URL = "https://graph.microsoft.com/beta"
    
    def __init__(self, auth_handler):
        """
        Initialize API client
        
        Args:
            auth_handler: AuthenticationHandler instance
        """
        self.auth = auth_handler
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        return session
    
    def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Make API request with authentication and error handling
        
        Args:
            method: HTTP method
            url: Full URL or path relative to base URL
            **kwargs: Additional request parameters
        
        Returns:
            Response JSON
        """
        # Ensure full URL
        if not url.startswith('http'):
            url = f"{self.BASE_URL}{url}"
        
        # Add authentication headers
        headers = self.auth.get_headers()
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                return self._make_request(method, url, **kwargs)
            
            response.raise_for_status()
            
            # Return JSON if available
            if response.content:
                return response.json()
            return {}
        
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            logger.error(f"Response: {e.response.text if e.response else 'No response'}")
            raise
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise
    
    def _get_all_pages(self, url: str, params: Optional[Dict] = None) -> List[Dict]:
        """
        Get all pages of results from paginated endpoint
        
        Args:
            url: API endpoint URL
            params: Query parameters
        
        Returns:
            List of all results
        """
        all_results = []
        next_link = url
        
        while next_link:
            if next_link == url:
                # First request with parameters
                response = self._make_request('GET', next_link, params=params)
            else:
                # Follow pagination link
                response = self._make_request('GET', next_link)
            
            # Add results
            if 'value' in response:
                all_results.extend(response['value'])
            
            # Check for next page
            next_link = response.get('@odata.nextLink')
        
        return all_results
    
    # Security Alerts & Incidents
    
    def get_security_alerts(self, top: int = 100, days_back: int = 7) -> List[Dict]:
        """
        Get recent security alerts from Microsoft Defender
        
        Args:
            top: Maximum number of alerts to retrieve
            days_back: Number of days to look back
        
        Returns:
            List of security alerts
        """
        start_date = (datetime.utcnow() - timedelta(days=days_back)).isoformat() + 'Z'
        
        params = {
            '$top': top,
            '$filter': f"createdDateTime ge {start_date}",
            '$orderby': 'createdDateTime desc'
        }
        
        return self._get_all_pages('/security/alerts_v2', params)
    
    def get_security_incidents(self, top: int = 50, days_back: int = 7) -> List[Dict]:
        """Get security incidents"""
        start_date = (datetime.utcnow() - timedelta(days=days_back)).isoformat() + 'Z'
        
        params = {
            '$top': top,
            '$filter': f"createdDateTime ge {start_date}",
            '$orderby': 'createdDateTime desc'
        }
        
        return self._get_all_pages('/security/incidents', params)
    
    # Identity & Sign-ins
    
    def get_risky_users(self) -> List[Dict]:
        """Get users flagged as risky"""
        params = {
            '$filter': "riskState ne 'dismissed' and riskState ne 'remediated'",
            '$orderby': 'riskLastUpdatedDateTime desc'
        }
        
        return self._get_all_pages('/identityProtection/riskyUsers', params)
    
    def get_risk_detections(self, days_back: int = 7) -> List[Dict]:
        """Get risk detections (risky sign-ins)"""
        start_date = (datetime.utcnow() - timedelta(days=days_back)).isoformat() + 'Z'
        
        params = {
            '$filter': f"activityDateTime ge {start_date}",
            '$orderby': 'activityDateTime desc'
        }
        
        return self._get_all_pages('/identityProtection/riskDetections', params)
    
    def get_sign_in_logs(self, hours_back: int = 24, failed_only: bool = False) -> List[Dict]:
        """
        Get sign-in logs from Entra ID
        
        Args:
            hours_back: Number of hours to look back
            failed_only: Only return failed sign-ins
        
        Returns:
            List of sign-in events
        """
        start_date = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat() + 'Z'
        
        filter_query = f"createdDateTime ge {start_date}"
        if failed_only:
            filter_query += " and status/errorCode ne 0"
        
        params = {
            '$filter': filter_query,
            '$orderby': 'createdDateTime desc',
            '$top': 100
        }
        
        # Sign-in logs are in beta endpoint
        url = f"{self.BETA_URL}/auditLogs/signIns"
        return self._get_all_pages(url, params)
    
    def get_conditional_access_failures(self, hours_back: int = 24) -> List[Dict]:
        """Get sign-ins that failed conditional access"""
        start_date = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat() + 'Z'
        
        params = {
            '$filter': f"createdDateTime ge {start_date} and conditionalAccessStatus eq 'failure'",
            '$orderby': 'createdDateTime desc'
        }
        
        url = f"{self.BETA_URL}/auditLogs/signIns"
        return self._get_all_pages(url, params)
    
    # Audit Logs
    
    def get_audit_logs(self, hours_back: int = 24, category: Optional[str] = None) -> List[Dict]:
        """
        Get audit logs for administrative actions
        
        Args:
            hours_back: Number of hours to look back
            category: Filter by category (e.g., 'UserManagement', 'GroupManagement')
        
        Returns:
            List of audit events
        """
        start_date = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat() + 'Z'
        
        filter_query = f"activityDateTime ge {start_date}"
        if category:
            filter_query += f" and category eq '{category}'"
        
        params = {
            '$filter': filter_query,
            '$orderby': 'activityDateTime desc',
            '$top': 100
        }
        
        return self._get_all_pages('/auditLogs/directoryAudits', params)
    
    # Users & Groups
    
    def get_guest_users(self) -> List[Dict]:
        """Get all guest users in the tenant"""
        params = {
            '$filter': "userType eq 'Guest'",
            '$select': 'id,displayName,mail,userPrincipalName,createdDateTime,signInActivity',
            '$orderby': 'createdDateTime desc'
        }
        
        return self._get_all_pages('/users', params)
    
    def get_privileged_users(self) -> List[Dict]:
        """Get users with administrative roles"""
        # Get all directory roles
        roles = self._make_request('GET', '/directoryRoles')['value']
        
        privileged_users = []
        admin_roles = ['Global Administrator', 'Security Administrator', 
                      'Privileged Role Administrator', 'User Administrator']
        
        for role in roles:
            if role['displayName'] in admin_roles:
                # Get members of this role
                members = self._make_request(
                    'GET', 
                    f"/directoryRoles/{role['id']}/members"
                )['value']
                
                for member in members:
                    member['role'] = role['displayName']
                    privileged_users.append(member)
        
        return privileged_users
    
    # Reports & Analytics
    
    def get_secure_score(self) -> Dict[str, Any]:
        """Get Microsoft Secure Score"""
        response = self._make_request('GET', '/security/secureScores?$top=1')
        if response.get('value'):
            return response['value'][0]
        return {}
    
    def get_secure_score_profiles(self) -> List[Dict]:
        """Get Secure Score control profiles"""
        return self._get_all_pages('/security/secureScoreControlProfiles')
    
    def get_attack_simulation_results(self) -> List[Dict]:
        """Get phishing simulation results if available"""
        try:
            url = f"{self.BETA_URL}/security/attackSimulation/simulations"
            params = {'$orderby': 'createdDateTime desc', '$top': 10}
            return self._get_all_pages(url, params)
        except Exception as e:
            logger.warning(f"Attack simulation not available: {e}")
            return []
    
    # Device & Compliance
    
    def get_non_compliant_devices(self) -> List[Dict]:
        """Get non-compliant devices from Intune"""
        try:
            params = {
                '$filter': "complianceState eq 'noncompliant'",
                '$select': 'id,deviceName,userPrincipalName,complianceState,lastSyncDateTime'
            }
            return self._get_all_pages('/deviceManagement/managedDevices', params)
        except Exception as e:
            logger.warning(f"Intune data not available: {e}")
            return []
    
    # Helper Methods
    
    def test_permissions(self) -> Dict[str, bool]:
        """Test which API permissions are available"""
        permissions = {}
        
        test_endpoints = {
            'Security Alerts': '/security/alerts_v2?$top=1',
            'Sign-in Logs': f'{self.BETA_URL}/auditLogs/signIns?$top=1',
            'Risky Users': '/identityProtection/riskyUsers?$top=1',
            'Audit Logs': '/auditLogs/directoryAudits?$top=1',
            'Users': '/users?$top=1',
            'Secure Score': '/security/secureScores?$top=1',
            'Devices': '/deviceManagement/managedDevices?$top=1'
        }
        
        for name, endpoint in test_endpoints.items():
            try:
                self._make_request('GET', endpoint)
                permissions[name] = True
                logger.info(f"✅ {name}: Available")
            except Exception as e:
                permissions[name] = False
                logger.warning(f"❌ {name}: Not available - {e}")
        
        return permissions


if __name__ == "__main__":
    # Test API client
    logging.basicConfig(level=logging.INFO)
    
    from auth_handler import AuthenticationHandler
    
    try:
        auth = AuthenticationHandler()
        client = GraphAPIClient(auth)
        
        print("\nTesting API permissions...")
        permissions = client.test_permissions()
        
        print("\nPermission Summary:")
        for perm, available in permissions.items():
            status = "✅" if available else "❌"
            print(f"{status} {perm}")
        
    except Exception as e:
        print(f"❌ Error: {e}")