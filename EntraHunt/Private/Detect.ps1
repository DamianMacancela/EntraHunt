# All Test-* functions are PURE: they take normalized data arrays and return finding objects.
# No system access, no network calls. Fully testable via InModuleScope without a tenant.

function Test-PasswordSpray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    $huntCfg  = $script:HuntConfig
    $findings = [System.Collections.Generic.List[object]]::new()
    $failures = @($Events | Where-Object { -not $_.IsSuccess })
    if ($failures.Count -eq 0) { return @() }

    $byIp    = $failures | Group-Object IpAddress
    $winMin  = $huntCfg.SignIn.Spray.WindowMinutes
    $minU    = $huntCfg.SignIn.Spray.MinDistinctUsers
    $highThr = $huntCfg.SignIn.Spray.HighThreshold

    foreach ($ipGroup in $byIp) {
        $ip       = $ipGroup.Name
        $sorted   = @($ipGroup.Group | Sort-Object Timestamp)
        $detected = $false

        for ($i = 0; $i -lt $sorted.Count -and -not $detected; $i++) {
            $wStart  = $sorted[$i].Timestamp
            $wEnd    = $wStart.AddMinutes($winMin)
            $inWin   = @($sorted | Where-Object { $_.Timestamp -ge $wStart -and $_.Timestamp -le $wEnd })
            $distinct = @($inWin.UPN | Sort-Object -Unique).Count

            if ($distinct -ge $minU) {
                $sev = if ($distinct -ge $highThr) { 'High' } else { 'Medium' }
                $findings.Add((New-HuntFinding `
                    -Rule      'SI001' `
                    -Severity  $sev `
                    -Title     "Password spray from $ip ($distinct users in ${winMin}min)" `
                    -Principal $ip `
                    -Mitre     'T1110.003' `
                    -Evidence  @{ SourceIP = $ip; DistinctUsers = $distinct }
                ))
                $detected = $true
            }
        }
    }
    return $findings.ToArray()
}

function Test-BruteForce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    $huntCfg  = $script:HuntConfig
    $findings = [System.Collections.Generic.List[object]]::new()
    $failures = @($Events | Where-Object { -not $_.IsSuccess })
    if ($failures.Count -eq 0) { return @() }

    $byUserIp = $failures | Group-Object { "$($_.UPN)|$($_.IpAddress)" }
    $winMin   = $huntCfg.SignIn.BruteForce.WindowMinutes
    $minFail  = $huntCfg.SignIn.BruteForce.MinFailures

    foreach ($grp in $byUserIp) {
        $sorted   = @($grp.Group | Sort-Object Timestamp)
        $detected = $false

        for ($i = 0; $i -lt $sorted.Count -and -not $detected; $i++) {
            $wStart = $sorted[$i].Timestamp
            $wEnd   = $wStart.AddMinutes($winMin)
            $inWin  = @($sorted | Where-Object { $_.Timestamp -ge $wStart -and $_.Timestamp -le $wEnd })

            if ($inWin.Count -ge $minFail) {
                $parts = $grp.Name -split '\|', 2
                $upn   = $parts[0]
                $ip    = if ($parts.Count -gt 1) { $parts[1] } else { '' }
                $findings.Add((New-HuntFinding `
                    -Rule      'SI002' `
                    -Severity  'High' `
                    -Title     "Brute force on $upn from $ip ($($inWin.Count) failures in ${winMin}min)" `
                    -Principal $upn `
                    -Mitre     'T1110.001' `
                    -Evidence  @{ SourceIP = $ip; UPN = $upn; FailureCount = $inWin.Count }
                ))
                $detected = $true
            }
        }
    }
    return $findings.ToArray()
}

function Test-SuccessAfterFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    $huntCfg   = $script:HuntConfig
    $findings  = [System.Collections.Generic.List[object]]::new()
    # Exclude MFA fatigue error code -- covered by Test-MFAFatigue
    $mfaCode   = $huntCfg.SignIn.MFAFatigue.ErrorCode
    $failures  = @($Events | Where-Object { -not $_.IsSuccess -and $_.ErrorCode -ne $mfaCode })
    $successes = @($Events | Where-Object { $_.IsSuccess })
    if ($failures.Count -eq 0) { return @() }

    $threshold = $huntCfg.SignIn.SuccessAfterFailure.FailureThreshold
    $winMin    = $huntCfg.SignIn.SuccessAfterFailure.WindowMinutes
    $byUserIp  = $failures | Group-Object { "$($_.UPN)|$($_.IpAddress)" }

    foreach ($grp in $byUserIp) {
        $sorted   = @($grp.Group | Sort-Object Timestamp)
        $detected = $false
        $parts    = $grp.Name -split '\|', 2
        $upn      = $parts[0]
        $ip       = if ($parts.Count -gt 1) { $parts[1] } else { '' }

        for ($i = 0; $i -lt $sorted.Count -and -not $detected; $i++) {
            $wStart = $sorted[$i].Timestamp
            $wEnd   = $wStart.AddMinutes($winMin)
            $inWin  = @($sorted | Where-Object { $_.Timestamp -ge $wStart -and $_.Timestamp -le $wEnd })

            if ($inWin.Count -ge $threshold) {
                $hitSuccess = @($successes | Where-Object {
                    $_.UPN       -eq $upn -and
                    $_.IpAddress -eq $ip -and
                    $_.Timestamp -ge $wStart -and
                    $_.Timestamp -le $wEnd.AddMinutes($winMin)
                })
                if ($hitSuccess.Count -gt 0) {
                    $findings.Add((New-HuntFinding `
                        -Rule      'SI003' `
                        -Severity  'High' `
                        -Title     "Account compromise: $upn - success after $($inWin.Count) failures from $ip" `
                        -Principal $upn `
                        -Mitre     'T1110' `
                        -Evidence  @{ UPN = $upn; SourceIP = $ip; FailureCount = $inWin.Count }
                    ))
                    $detected = $true
                }
            }
        }
    }
    return $findings.ToArray()
}

function Test-ImpossibleTravel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    $huntCfg   = $script:HuntConfig
    $findings  = [System.Collections.Generic.List[object]]::new()
    $successes = @($Events | Where-Object { $_.IsSuccess -and $_.Country -ne '' })
    if ($successes.Count -lt 2) { return @() }

    $winH   = $huntCfg.SignIn.ImpossibleTravel.WindowHours
    $byUser = $successes | Group-Object UPN

    foreach ($grp in $byUser) {
        $sorted   = @($grp.Group | Sort-Object Timestamp)
        $detected = $false

        for ($i = 0; $i -lt ($sorted.Count - 1) -and -not $detected; $i++) {
            $ev1   = $sorted[$i]
            $ev2   = $sorted[$i + 1]
            $diffH = ($ev2.Timestamp - $ev1.Timestamp).TotalHours

            if ($diffH -le $winH -and $ev1.Country -ne $ev2.Country) {
                $disp = [Math]::Round($diffH, 1)
                $findings.Add((New-HuntFinding `
                    -Rule      'SI004' `
                    -Severity  'High' `
                    -Title     "Impossible travel: $($ev1.Country) to $($ev2.Country) in ${disp}h ($($grp.Name))" `
                    -Principal $grp.Name `
                    -Mitre     'T1078' `
                    -Evidence  @{
                        Country1  = $ev1.Country; IP1 = $ev1.IpAddress; Time1 = $ev1.Timestamp
                        Country2  = $ev2.Country; IP2 = $ev2.IpAddress; Time2 = $ev2.Timestamp
                    }
                ))
                $detected = $true
            }
        }
    }
    return $findings.ToArray()
}

function Test-LegacyProtocol {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    $huntCfg     = $script:HuntConfig
    $findings    = [System.Collections.Generic.List[object]]::new()
    $modernApps  = $huntCfg.ModernClientApps
    $legacyEvs   = @($Events | Where-Object { $_.ClientApp -ne '' -and $_.ClientApp -notin $modernApps })
    if ($legacyEvs.Count -eq 0) { return @() }

    $byUser = $legacyEvs | Group-Object UPN
    foreach ($grp in $byUser) {
        $apps = @($grp.Group.ClientApp | Sort-Object -Unique)
        $findings.Add((New-HuntFinding `
            -Rule      'SI005' `
            -Severity  'Low' `
            -Title     "Legacy auth protocol by $($grp.Name): $($apps -join ', ')" `
            -Principal $grp.Name `
            -Mitre     'T1078.004' `
            -Evidence  @{ UPN = $grp.Name; ClientApps = $apps }
        ))
    }
    return $findings.ToArray()
}

function Test-MFAFatigue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    $huntCfg   = $script:HuntConfig
    $findings  = [System.Collections.Generic.List[object]]::new()
    $mfaCode   = $huntCfg.SignIn.MFAFatigue.ErrorCode
    $threshold = $huntCfg.SignIn.MFAFatigue.Threshold
    $winMin    = $huntCfg.SignIn.MFAFatigue.WindowMinutes
    $aheadMin  = $huntCfg.SignIn.MFAFatigue.LookAheadMinutes
    $mfaEvs    = @($Events | Where-Object { $_.ErrorCode -eq $mfaCode })
    if ($mfaEvs.Count -eq 0) { return @() }

    $successes = @($Events | Where-Object { $_.IsSuccess })
    $byUser    = $mfaEvs | Group-Object UPN

    foreach ($grp in $byUser) {
        $sorted   = @($grp.Group | Sort-Object Timestamp)
        $detected = $false

        for ($i = 0; $i -lt $sorted.Count -and -not $detected; $i++) {
            $wStart = $sorted[$i].Timestamp
            $wEnd   = $wStart.AddMinutes($winMin)
            $inWin  = @($sorted | Where-Object { $_.Timestamp -ge $wStart -and $_.Timestamp -le $wEnd })

            if ($inWin.Count -ge $threshold) {
                $upn    = $grp.Name
                $hitOk  = @($successes | Where-Object {
                    $_.UPN -eq $upn -and
                    $_.Timestamp -ge $wStart -and
                    $_.Timestamp -le $wEnd.AddMinutes($aheadMin)
                })
                $approved = $hitOk.Count -gt 0
                $sev   = if ($approved) { 'Critical' } else { 'High' }
                $title = if ($approved) {
                    "MFA fatigue - APPROVED after $($inWin.Count) denials: $upn"
                } else {
                    "MFA fatigue - $($inWin.Count) denied pushes: $upn"
                }
                $findings.Add((New-HuntFinding `
                    -Rule      'SI006' `
                    -Severity  $sev `
                    -Title     $title `
                    -Principal $upn `
                    -Mitre     'T1621' `
                    -Evidence  @{ UPN = $upn; DeniedCount = $inWin.Count; ApprovedAfter = $approved }
                ))
                $detected = $true
            }
        }
    }
    return $findings.ToArray()
}

function Test-ExternalForwarding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$NormRules,
        [string]$OrgDomain      = '',
        [string[]]$AllowedDomains = @()
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in ($NormRules | Where-Object IsEnabled)) {
        $targets    = @($rule.ForwardTo + $rule.RedirectTo) | Where-Object { $_ }
        $extTargets = @($targets | Where-Object {
            $domain = ($_ -split '@')[-1].ToLower()
            $domain -ne $OrgDomain.ToLower() -and $domain -notin $AllowedDomains
        })
        if ($extTargets.Count -gt 0) {
            $findings.Add((New-HuntFinding `
                -Rule      'IR001' `
                -Severity  'Critical' `
                -Title     "External forwarding rule '$($rule.RuleName)' to: $($extTargets -join ', ')" `
                -Principal $rule.UPN `
                -Mitre     'T1114.003' `
                -Evidence  @{ RuleName = $rule.RuleName; ExternalTargets = $extTargets }
            ))
        }
    }
    return $findings.ToArray()
}

function Test-FinancialRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$NormRules,
        [string[]]$Keywords = @()
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in ($NormRules | Where-Object IsEnabled)) {
        $isDestructive = $rule.DeleteForever -or $rule.DeleteTemp
        $moveRead      = ($rule.MoveToFolder -ne '' -and $rule.MarkAsRead)
        if (-not ($isDestructive -or $moveRead)) { continue }

        $allConds = @($rule.SubjectContains + $rule.SenderContains + $rule.BodyContains) | Where-Object { $_ }
        $matched  = @($allConds | Where-Object {
            $cond = $_
            $Keywords | Where-Object { $cond -match [regex]::Escape($_) }
        })
        $noConds = ($allConds.Count -eq 0)

        if ($matched.Count -gt 0 -or $noConds) {
            $findings.Add((New-HuntFinding `
                -Rule      'IR003' `
                -Severity  'High' `
                -Title     "Suspicious destructive inbox rule '$($rule.RuleName)' ($($rule.UPN))" `
                -Principal $rule.UPN `
                -Mitre     'T1564.008' `
                -Evidence  @{ RuleName = $rule.RuleName; MatchedKeywords = $matched; NoConditions = $noConds }
            ))
        }
    }
    return $findings.ToArray()
}

function Test-SuspiciousOAuth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$NormGrants
    )
    $huntCfg    = $script:HuntConfig
    $findings   = [System.Collections.Generic.List[object]]::new()
    $highScopes = $huntCfg.OAuth.HighRiskScopes
    $medScopes  = $huntCfg.OAuth.MediumRiskScopes
    $newDays    = $huntCfg.OAuth.NewAppDays

    foreach ($grant in $NormGrants) {
        $matchHigh = @($grant.Scopes | Where-Object { $highScopes -contains $_ })
        $matchMed  = @($grant.Scopes | Where-Object { $medScopes  -contains $_ })
        $score     = 0

        if ($matchHigh.Count -gt 0)        { $score += 3 }
        elseif ($matchMed.Count -gt 0)     { $score += 1 }
        else                               { continue }

        if (-not $grant.PublisherVerified)  { $score += 2 }
        if ($grant.IsExternalApp)           { $score += 2 }
        if ($grant.CreatedAt -gt [datetime]::UtcNow.AddDays(-$newDays)) { $score += 1 }

        $sev = switch ($true) {
            { $score -ge 6 } { 'Critical'; break }
            { $score -ge 4 } { 'High';     break }
            { $score -ge 2 } { 'Medium';   break }
            default          { 'Low' }
        }
        $findings.Add((New-HuntFinding `
            -Rule      'OC001' `
            -Severity  $sev `
            -Title     "Suspicious OAuth: '$($grant.AppName)' (score $score, $($grant.PrincipalUPN))" `
            -Principal $grant.PrincipalUPN `
            -Mitre     'T1550.001' `
            -Evidence  @{
                AppName           = $grant.AppName
                Scopes            = $grant.Scopes
                PublisherVerified = $grant.PublisherVerified
                IsExternalApp     = $grant.IsExternalApp
                RiskScore         = $score
            }
        ))
    }
    return $findings.ToArray()
}

function Test-CrossSignalCorrelation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AllFindings
    )
    $corFindings = [System.Collections.Generic.List[object]]::new()
    if ($AllFindings.Count -eq 0) { return @() }

    $siPrincipals = @($AllFindings | Where-Object { $_.Rule -like 'SI*' } |
        Select-Object -ExpandProperty Principal -Unique)
    $irPrincipals = @($AllFindings | Where-Object { $_.Rule -like 'IR*' } |
        Select-Object -ExpandProperty Principal -Unique)
    $correlated   = @($siPrincipals | Where-Object { $irPrincipals -contains $_ })

    foreach ($principal in $correlated) {
        $related  = @($AllFindings | Where-Object { $_.Principal -eq $principal })
        $ruleList = ($related | Select-Object -ExpandProperty Rule | Sort-Object -Unique) -join ', '
        $corFindings.Add((New-HuntFinding `
            -Rule      'COR001' `
            -Severity  'Critical' `
            -Title     "Multi-signal correlation on $principal [$ruleList]" `
            -Principal $principal `
            -Mitre     'T1078' `
            -Evidence  @{ Rules = $related.Rule; RelatedFindingIds = $related.Id }
        ))
    }
    return $corFindings.ToArray()
}
