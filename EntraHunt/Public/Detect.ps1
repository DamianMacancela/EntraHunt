function Invoke-SignInDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    if ($Events.Count -eq 0) { return @() }

    $findings.AddRange(@(Test-PasswordSpray -Events $Events))
    $findings.AddRange(@(Test-BruteForce -Events $Events))
    $findings.AddRange(@(Test-SuccessAfterFailure -Events $Events))
    $findings.AddRange(@(Test-ImpossibleTravel -Events $Events))
    $findings.AddRange(@(Test-LegacyProtocol -Events $Events))
    $findings.AddRange(@(Test-MFAFatigue -Events $Events))
    
    return $findings.ToArray()
}

function Invoke-InboxRuleDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rules,
        [string]$OrgDomain = ''
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    if ($Rules.Count -eq 0) { return @() }

    $kws     = $script:HuntConfig.InboxRule.FinancialKeywords
    $domains = $script:HuntConfig.InboxRule.AllowedForwardDomains

    $findings.AddRange(@(Test-ExternalForwarding -NormRules $Rules -OrgDomain $OrgDomain -AllowedDomains $domains))
    $findings.AddRange(@(Test-FinancialRule -NormRules $Rules -Keywords $kws))
    
    return $findings.ToArray()
}

function Invoke-OAuthDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Grants
    )
    if ($Grants.Count -eq 0) { return @() }
    return Test-SuspiciousOAuth -NormGrants $Grants
}

function Invoke-CrossSignalDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )
    if ($Findings.Count -eq 0) { return @() }
    return Test-CrossSignalCorrelation -AllFindings $Findings
}
