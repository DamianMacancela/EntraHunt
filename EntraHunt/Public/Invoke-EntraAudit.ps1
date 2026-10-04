function Invoke-EntraAudit {
    [CmdletBinding()]
    param(
        [datetime]$Since = (Get-Date).AddDays(-1),
        [string]$OrgDomain = '',
        [switch]$SkipInboxRules,
        [switch]$SkipOAuth,
        
        [switch]$AI,
        [ValidateSet('Anthropic', 'Ollama')]
        [string]$AIProvider = 'Anthropic',
        [string]$AIModel = 'claude-opus-4-5',
        [System.Security.SecureString]$AIApiKey = $null,
        
        [string]$SampleDataPath = '',
        [string]$OutputDirectory = ".\out"
    )

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $allFindings = [System.Collections.Generic.List[object]]::new()
    $signIns = @()
    $rules   = @()
    $grants  = @()

    if ($SampleDataPath -ne '') {
        Write-HuntLog "Using sample data from $SampleDataPath" -Level Info
        
        $siPath = Join-Path $SampleDataPath 'signins.json'
        if (Test-Path $siPath) {
            $raw = Get-Content $siPath -Raw | ConvertFrom-Json
            $signIns = @($raw | ConvertFrom-SignInEvent)
        }
        
        $irPath = Join-Path $SampleDataPath 'inboxrules.json'
        if (Test-Path $irPath) {
            $raw = Get-Content $irPath -Raw | ConvertFrom-Json
            foreach ($user in $raw) {
                foreach ($r in $user.rules) {
                    $rules += ConvertFrom-InboxRule -Rule $r -UserId $user.id -UPN $user.userPrincipalName
                }
            }
        }
        
        $oaPath = Join-Path $SampleDataPath 'oauthgrants.json'
        if (Test-Path $oaPath) {
            $raw = Get-Content $oaPath -Raw | ConvertFrom-Json
            $grants = @($raw | ConvertFrom-OAuthGrant)
        }
    }
    else {
        if (-not $script:HuntConnected) {
            throw "Not connected to Graph. Run Connect-EntraHunt first."
        }
        
        $signIns = @(Get-EntraSignIn -Since $Since)
        
        if (-not $SkipInboxRules) {
            # Get users to check rules
            $users = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName"
            $ids  = @($users | Select-Object -ExpandProperty id)
            $upns = @($users | Select-Object -ExpandProperty userPrincipalName)
            $rules = @(Get-EntraInboxRule -UserIds $ids -UPNs $upns)
        }
        
        if (-not $SkipOAuth) {
            $grants = @(Get-EntraOAuthGrant)
        }
    }

    Write-HuntLog "Running detections..." -Level Info
    $allFindings.AddRange(@(Invoke-SignInDetection -Events $signIns))
    $allFindings.AddRange(@(Invoke-InboxRuleDetection -Rules $rules -OrgDomain $OrgDomain))
    $allFindings.AddRange(@(Invoke-OAuthDetection -Grants $grants))
    $allFindings.AddRange(@(Invoke-CrossSignalDetection -Findings $allFindings.ToArray()))

    if ($AI -and $allFindings.Count -gt 0) {
        Write-HuntLog "Running AI Analysis..." -Level Info
        $allFindings = [System.Collections.Generic.List[object]]::new(
            [object[]](Invoke-EntraAIAnalysis -Finding $allFindings.ToArray() -Provider $AIProvider -Model $AIModel -ApiKey $AIApiKey)
        )
    }

    $outHtml = Join-Path $OutputDirectory 'report.html'
    Export-EntraReport -Findings $allFindings.ToArray() -OutputPath $outHtml

    return [pscustomobject]@{
        Findings = $allFindings.ToArray()
        Report   = $outHtml
    }
}
