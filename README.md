# EntraHunt

**Microsoft Entra ID Threat Hunting tool with AI Triage**

EntraHunt is a PowerShell module designed for SOC analysts to identify suspicious and malicious behavior in Microsoft Entra ID. It leverages the Graph API to collect events and runs them through a multi-layered detection engine, which correlates findings to produce high-confidence alerts. It features optional integration with Anthropic Claude and Ollama for automated AI-driven triage and severity assessment.

## Features

- **Multi-signal correlation:** Correlates Entra ID sign-in logs, Inbox Rules, and OAuth2 permission grants.
- **AI Triage with Pseudonymization:** Analyzes findings with LLMs (Claude or local Ollama). Payload data is regex-pseudonymized before being sent to the LLM (emails and IPs are masked as `EMAIL_0001`, etc.) and mapped back locally.
- **Pure Function Detections:** The core detection rules are implemented as pure PowerShell functions, allowing deterministic execution and testing without needing a live tenant connection.
- **App-Only and Delegated Auth:** Connect using your own account, or use `New-EntraHuntApp.ps1` to provision a certificate-backed unattended app registration.

## Installation

```powershell
# Clone the repository
git clone https://github.com/DamianMacancela/EntraHunt.git
cd EntraHunt

# Import the module
Import-Module .\EntraHunt\EntraHunt.psd1
```

## Setup & Usage

### 1. Connecting to Graph

**Option A (Delegated / Interactive):**
```powershell
Connect-EntraHunt
```

**Option B (Unattended / Certificate-based):**
1. Run the provisioning script to create the app and generate a self-signed certificate:
   ```powershell
   .\scripts\New-EntraHuntApp.ps1 -AppName "EntraHunt-Audit"
   ```
2. Grant Admin Consent for `AuditLog.Read.All`, `Directory.Read.All`, and `MailboxSettings.Read` in the Azure Portal.
3. Connect using the generated credentials:
   ```powershell
   Connect-EntraHunt -TenantId "<tenant_id>" -ClientId "<client_id>" -CertificateThumbprint "<thumbprint>"
   ```

### 2. Running an Audit

**Standard Hunt (Last 24h):**
```powershell
$report = Invoke-EntraAudit -OrgDomain "contoso.com"
```

**Hunt with AI Triage (Claude):**
```powershell
$apiKey = ConvertTo-SecureString "sk-ant-api03-..." -AsPlainText -Force
$report = Invoke-EntraAudit -OrgDomain "contoso.com" -AI -AIProvider Anthropic -AIApiKey $apiKey
```

**Hunt on Demo Data:**
```powershell
$report = Invoke-EntraAudit -SampleDataPath ".\tests\data" -OrgDomain "contoso.example"
```

## Detections Included

| Rule | Severity | Name | ATT&CK |
|---|---|---|---|
| **SI001** | High/Med | Password Spray | T1110.003 |
| **SI002** | High | Brute Force | T1110.001 |
| **SI003** | High | Success After Failure | T1110 |
| **SI004** | High | Impossible Travel | T1078 |
| **SI005** | Low | Legacy Protocol Usage | T1078.004 |
| **SI006** | Critical | MFA Fatigue | T1621 |
| **IR001** | Critical | External Forwarding Rule | T1114.003 |
| **IR003** | High | Suspicious Destructive Rule | T1564.008 |
| **OC001** | Crit/High | Suspicious OAuth Consent | T1550.001 |
| **COR001** | Critical | Cross-Signal Correlation | T1078 |

## Limitations & Evading Detection

- **AI Regex Pseudonymization:** The data pseudonymization feature currently uses simple regexes for IPv4, emails, and GUIDs. IPv6 addresses, domain names, and user display names are not masked before reaching the AI.
- **Latency:** Graph API audit logs can have up to 15-30 minutes of latency. EntraHunt is intended for hunting, not real-time alerting.
- **App Names in OAuth:** App display names are not pseudonymized as they are necessary for AI to determine legitimacy.

## Security Considerations

If you find a security vulnerability, please do not disclose it publicly. Review `SECURITY.md` for guidelines.

## License

(c) DamianMacancela. All rights reserved.
