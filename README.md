EntraHunt
=========

*a PowerShell module for Microsoft Entra ID threat hunting and AI triage*

**EntraHunt** is a tool to collect events from Microsoft Entra ID via Graph API and identify suspicious behaviors (password spraying, MFA fatigue, malicious inbox rules). It includes an optional integration with LLMs (Claude/Ollama) to triage findings, using local pseudonymization to prevent PII leakage.

### Features
* **Multi-signal correlation:** Evaluates Sign-ins, Inbox Rules, and OAuth2 grants.
* **AI Triage:** Analyzes findings using Claude or Ollama. 
* **Data Privacy:** Regex-masks Emails and IPs before sending payloads to the AI.
* **Pure Functions:** Detection logic is separated from data collection for easy testing.

### Usage

```powershell
Import-Module .\EntraHunt\EntraHunt.psd1

# Interactive login
Connect-EntraHunt

# Standard Hunt (Last 24h)
$report = Invoke-EntraAudit -OrgDomain "contoso.com"

# Hunt with AI Triage
$apiKey = ConvertTo-SecureString "sk-ant-..." -AsPlainText -Force
$report = Invoke-EntraAudit -OrgDomain "contoso.com" -AI -AIProvider Anthropic -AIApiKey $apiKey
```

### Setup (App-Only Auth)
You can provision an unattended app registration using the included script:
```powershell
.\scripts\New-EntraHuntApp.ps1 -AppName "EntraHunt-Audit"
```
Then grant Admin Consent for `AuditLog.Read.All`, `Directory.Read.All`, and `MailboxSettings.Read`.

### License
MIT
