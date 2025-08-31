"""
Authentication handler for Microsoft Graph API using MSAL
Supports both certificate and client secret authentication
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

import msal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class AuthenticationHandler:
    """Handles OAuth2 authentication for Microsoft Graph API"""
    
    def __init__(self, config_path: str = "agent_config.json"):
        """
        Initialize authentication handler
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.app = None
        self.token_cache = {}
        self.token_expiry = None
        self._initialize_app()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file or environment variables"""
        config = {}
        
        # Try loading from file first
        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
        
        # Override with environment variables if present
        config['tenant_id'] = os.getenv('AZURE_TENANT_ID', config.get('tenant_id'))
        config['client_id'] = os.getenv('AZURE_CLIENT_ID', config.get('client_id'))
        config['client_secret'] = os.getenv('AZURE_CLIENT_SECRET', config.get('client_secret'))
        config['certificate_path'] = os.getenv('AZURE_CERT_PATH', config.get('certificate_path'))
        config['certificate_password'] = os.getenv('AZURE_CERT_PASSWORD', config.get('certificate_password'))
        config['certificate_thumbprint'] = os.getenv('AZURE_CERT_THUMBPRINT', config.get('certificate_thumbprint'))
        
        # Validate required fields
        if not config.get('tenant_id') or not config.get('client_id'):
            raise ValueError("tenant_id and client_id are required")
        
        # Ensure we have either certificate or secret
        has_cert = config.get('certificate_path') and config.get('certificate_thumbprint')
        has_secret = config.get('client_secret')
        
        if not has_cert and not has_secret:
            raise ValueError("Either certificate or client_secret is required")
        
        return config
    
    def _load_certificate(self) -> Optional[Dict[str, Any]]:
        """Load certificate for authentication"""
        cert_path = self.config.get('certificate_path')
        cert_password = self.config.get('certificate_password')
        thumbprint = self.config.get('certificate_thumbprint')
        
        if not cert_path or not Path(cert_path).exists():
            return None
        
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Handle both PFX and PEM formats
            if cert_path.endswith('.pfx') or cert_path.endswith('.p12'):
                # Load PFX certificate
                if cert_password:
                    cert_password = cert_password.encode()
                
                private_key, certificate, _ = pkcs12.load_key_and_certificates(
                    cert_data,
                    cert_password,
                    backend=default_backend()
                )
                
                # Convert to PEM format for MSAL
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                cert_pem = certificate.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode('utf-8')
                
                return {
                    "private_key": private_key_pem,
                    "thumbprint": thumbprint,
                    "public_certificate": cert_pem
                }
            else:
                # Assume PEM format
                return {
                    "private_key": cert_data.decode('utf-8'),
                    "thumbprint": thumbprint
                }
        
        except Exception as e:
            logger.error(f"Failed to load certificate: {e}")
            return None
    
    def _initialize_app(self):
        """Initialize MSAL application"""
        authority = f"https://login.microsoftonline.com/{self.config['tenant_id']}"
        
        # Try certificate authentication first
        cert_config = self._load_certificate()
        if cert_config:
            self.app = msal.ConfidentialClientApplication(
                self.config['client_id'],
                authority=authority,
                client_credential=cert_config
            )
            logger.info("Initialized with certificate authentication")
        elif self.config.get('client_secret'):
            # Fall back to client secret
            self.app = msal.ConfidentialClientApplication(
                self.config['client_id'],
                authority=authority,
                client_credential=self.config['client_secret']
            )
            logger.info("Initialized with client secret authentication")
        else:
            raise ValueError("No valid authentication method available")
    
    def get_token(self, scopes: Optional[list] = None) -> str:
        """
        Get access token for Microsoft Graph API
        
        Args:
            scopes: List of scopes to request (default: [".default"])
        
        Returns:
            Access token string
        """
        if scopes is None:
            scopes = ["https://graph.microsoft.com/.default"]
        
        # Check if we have a valid cached token
        if self.token_cache and self.token_expiry:
            if datetime.now() < self.token_expiry:
                return self.token_cache.get('access_token')
        
        # Request new token
        result = self.app.acquire_token_for_client(scopes=scopes)
        
        if "access_token" in result:
            self.token_cache = result
            # Set expiry with 5-minute buffer
            expires_in = result.get('expires_in', 3600)
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 300)
            logger.info("Successfully acquired new access token")
            return result['access_token']
        else:
            error_msg = result.get('error_description', result.get('error', 'Unknown error'))
            logger.error(f"Failed to acquire token: {error_msg}")
            raise Exception(f"Authentication failed: {error_msg}")
    
    def get_headers(self) -> Dict[str, str]:
        """
        Get headers for API requests including authentication
        
        Returns:
            Dictionary of headers
        """
        token = self.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    
    def test_connection(self) -> bool:
        """
        Test connection to Microsoft Graph API
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            import requests
            
            headers = self.get_headers()
            response = requests.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers=headers
            )
            
            if response.status_code == 200:
                org_data = response.json()
                if org_data.get('value'):
                    org_name = org_data['value'][0].get('displayName', 'Unknown')
                    logger.info(f"Successfully connected to organization: {org_name}")
                return True
            else:
                logger.error(f"Connection test failed with status {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False


if __name__ == "__main__":
    # Test authentication
    logging.basicConfig(level=logging.INFO)
    
    try:
        auth = AuthenticationHandler()
        if auth.test_connection():
            print("✅ Authentication successful!")
        else:
            print("❌ Authentication failed!")
    except Exception as e:
        print(f"❌ Error: {e}")