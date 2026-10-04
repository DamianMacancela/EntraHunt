function Get-EntraSignIn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$Since
    )
    $startIso = $Since.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter   = "createdDateTime ge $startIso"
    $uri      = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$([uri]::EscapeDataString($filter))"

    Write-HuntLog "Collecting sign-ins since $startIso" -Level Info
    $raw = Invoke-GraphPaged -Uri $uri
    Write-HuntLog "Found $($raw.Count) raw sign-in events" -Level Debug
    
    return $raw | ConvertFrom-SignInEvent
}

function Get-EntraInboxRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$UserIds,
        [Parameter(Mandatory)]
        [string[]]$UPNs
    )
    $allRules = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $UserIds.Count; $i++) {
        $id  = $UserIds[$i]
        $upn = $UPNs[$i]
        $uri = "https://graph.microsoft.com/v1.0/users/$id/mailFolders/inbox/messageRules"
        
        Write-HuntLog "Collecting inbox rules for $upn" -Level Debug
        try {
            $raw = Invoke-GraphPaged -Uri $uri
            foreach ($r in $raw) {
                $allRules.Add((ConvertFrom-InboxRule -Rule $r -UserId $id -UPN $upn))
            }
        }
        catch {
            Write-HuntLog "Could not fetch inbox rules for $upn (no mailbox or access denied)" -Level Debug
        }
    }
    return $allRules.ToArray()
}

function Get-EntraOAuthGrant {
    [CmdletBinding()]
    param()
    
    Write-HuntLog "Collecting OAuth2 Permission Grants" -Level Info
    $uri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants'
    $raw = Invoke-GraphPaged -Uri $uri
    Write-HuntLog "Found $($raw.Count) OAuth grants" -Level Debug
    return $raw | ConvertFrom-OAuthGrant
}
