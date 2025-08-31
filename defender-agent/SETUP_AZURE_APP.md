# Azure App Registration Setup Guide

## Prerequisites
- Global Administrator or Application Administrator role in Azure AD
- Access to Azure Portal (https://portal.azure.com)

## Step 1: Create App Registration

1. Navigate to **Azure Active Directory** → **App registrations**
2. Click **New registration**
3. Configure:
   - Name: `Defender-Entra-Security-Agent`
   - Supported account types: **Accounts in this organizational directory only**
   - Redirect URI: Leave blank (we'll use client credentials flow)
4. Click **Register**

## Step 2: Configure API Permissions

1. In your app registration, go to **API permissions**
2. Click **Add a permission** → **Microsoft Graph**
3. Select **Application permissions** (not delegated)
4. Add these permissions:

### Security & Compliance
- `SecurityEvents.Read.All` - Read security events
- `ThreatIndicators.Read.All` - Read threat indicators
- `SecurityAlert.Read.All` - Read security alerts
- `SecurityIncident.Read.All` - Read security incidents

### Identity & Sign-ins
- `AuditLog.Read.All` - Read audit logs
- `Directory.Read.All` - Read directory data
- `IdentityRiskEvent.Read.All` - Read risk events
- `IdentityRiskyUser.Read.All` - Read risky users
- `SignIns.Read.All` - Read sign-in logs

### Reports & Analytics
- `Reports.Read.All` - Read usage reports
- `UserActivity.Read.All` - Read user activity

5. Click **Grant admin consent** for your organization
6. Confirm all permissions show green checkmarks

## Step 3: Create Client Certificate (Recommended)

### Option A: Self-Signed Certificate (PowerShell)
```powershell
# Generate certificate
$cert = New-SelfSignedCertificate `
    -Subject "CN=Defender-Agent-Cert" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# Export public key (.cer)
Export-Certificate -Cert $cert -FilePath ".\defender-agent-cert.cer"

# Export private key (.pfx) - KEEP SECURE!
$pwd = ConvertTo-SecureString -String "YourStrongPassword123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ".\defender-agent-cert.pfx" -Password $pwd

# Get thumbprint (save this!)
Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
```

### Option B: Client Secret (Less Secure)
1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Description: `Defender Agent Secret`
4. Expires: Choose appropriate duration
5. **COPY THE SECRET VALUE IMMEDIATELY** (won't be shown again)

## Step 4: Upload Certificate to Azure

1. In app registration, go to **Certificates & secrets**
2. Click **Upload certificate**
3. Select the `.cer` file you exported
4. Click **Add**

## Step 5: Note Important Values

Save these values for the agent configuration:

```json
{
  "tenant_id": "YOUR_TENANT_ID",
  "client_id": "YOUR_APPLICATION_CLIENT_ID",
  "certificate_path": "./defender-agent-cert.pfx",
  "certificate_password": "YourStrongPassword123!",
  "certificate_thumbprint": "YOUR_CERT_THUMBPRINT"
}
```

Find these values:
- **Tenant ID**: Azure AD → Overview → Tenant ID
- **Client ID**: App registration → Overview → Application (client) ID
- **Thumbprint**: From PowerShell output or Certificates & secrets page

## Step 6: Test Connection

Use this PowerShell script to verify setup:

```powershell
# Install MSAL module if needed
Install-Module -Name MSAL.PS -Force -AllowClobber

# Test authentication
$tenantId = "YOUR_TENANT_ID"
$clientId = "YOUR_CLIENT_ID"
$certThumbprint = "YOUR_CERT_THUMBPRINT"

$cert = Get-ChildItem -Path Cert:\CurrentUser\My\$certThumbprint

$token = Get-MsalToken `
    -ClientId $clientId `
    -TenantId $tenantId `
    -ClientCertificate $cert `
    -Scopes "https://graph.microsoft.com/.default"

if ($token.AccessToken) {
    Write-Host "✅ Authentication successful!" -ForegroundColor Green
    
    # Test API call
    $headers = @{
        "Authorization" = "Bearer $($token.AccessToken)"
        "Content-Type" = "application/json"
    }
    
    $response = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/security/alerts?`$top=1" `
        -Headers $headers `
        -Method Get
    
    Write-Host "✅ API access verified! Found $($response.'@odata.count') alerts" -ForegroundColor Green
} else {
    Write-Host "❌ Authentication failed" -ForegroundColor Red
}
```

## Security Best Practices

1. **Certificate Storage**:
   - Store `.pfx` file in secure location with restricted permissions
   - Never commit certificates to Git
   - Consider using Azure Key Vault for production

2. **Least Privilege**:
   - Only grant permissions actually needed
   - Review permissions quarterly
   - Remove unused permissions

3. **Monitoring**:
   - Enable audit logs for the app
   - Set up alerts for unusual API usage
   - Review sign-in logs regularly

4. **Rotation**:
   - Rotate certificates before expiry
   - Document rotation procedure
   - Test rotation in non-production first

## Troubleshooting

### Common Issues:

1. **"Insufficient privileges"**
   - Ensure admin consent was granted
   - Verify all permissions show green checkmarks

2. **"Invalid client"**
   - Check client ID is correct
   - Verify certificate thumbprint matches

3. **"Token request failed"**
   - Ensure certificate is in correct store
   - Verify tenant ID is correct
   - Check certificate hasn't expired

4. **API returns 403 Forbidden**
   - Permission might need time to propagate (wait 5-10 minutes)
   - Verify specific permission for endpoint exists

## Next Steps

Once Azure app is configured:
1. Update `agent_config.json` with your values
2. Install Python dependencies: `pip install -r requirements.txt`
3. Run initial test: `python defender_agent.py --test`
4. Schedule automated runs via Task Scheduler or cron