function ConvertFrom-SignInEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Event
    )
    process {
        $errorCode = -1
        if ($null -ne $Event.status -and $null -ne $Event.status.errorCode) {
            $errorCode = [int]$Event.status.errorCode
        }
        $isSuccess = ($errorCode -eq 0)

        $country = ''
        if ($null -ne $Event.location -and -not [string]::IsNullOrEmpty($Event.location.countryOrRegion)) {
            $country = [string]$Event.location.countryOrRegion
        }

        $ts = [datetime]::UtcNow
        if (-not [string]::IsNullOrEmpty($Event.createdDateTime)) {
            $ts = [datetimeoffset]::Parse($Event.createdDateTime).UtcDateTime
        }

        $clientApp = ''
        if (-not [string]::IsNullOrEmpty($Event.clientAppUsed)) {
            $clientApp = [string]$Event.clientAppUsed
        }

        [pscustomobject]@{
            EventId   = [string]$Event.id
            Timestamp = $ts
            UPN       = ([string]$Event.userPrincipalName).ToLower()
            UserId    = [string]$Event.userId
            AppName   = [string]$Event.appDisplayName
            ClientApp = $clientApp
            IpAddress = [string]$Event.ipAddress
            Country   = $country
            ErrorCode = $errorCode
            IsSuccess = $isSuccess
        }
    }
}

function ConvertFrom-InboxRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Rule,
        [string]$UserId = '',
        [string]$UPN    = ''
    )
    $actions = if ($null -ne $Rule.actions) { $Rule.actions } else { [pscustomobject]@{} }

    $forwardTo = @()
    if ($null -ne $actions.forwardTo) {
        $forwardTo = @($actions.forwardTo | ForEach-Object {
            if ($null -ne $_.emailAddress) { [string]$_.emailAddress.address }
        } | Where-Object { $_ })
    }

    $redirectTo = @()
    if ($null -ne $actions.redirectTo) {
        $redirectTo = @($actions.redirectTo | ForEach-Object {
            if ($null -ne $_.emailAddress) { [string]$_.emailAddress.address }
        } | Where-Object { $_ })
    }

    $conditions     = if ($null -ne $Rule.conditions) { $Rule.conditions } else { [pscustomobject]@{} }
    $subjectContains = @()
    if ($null -ne $conditions.subjectContains) { $subjectContains = @($conditions.subjectContains) }
    $senderContains  = @()
    if ($null -ne $conditions.senderContains)  { $senderContains  = @($conditions.senderContains)  }
    $bodyContains    = @()
    if ($null -ne $conditions.bodyContains)    { $bodyContains    = @($conditions.bodyContains)    }

    $moveToFolder = ''
    if ($null -ne $actions.PSObject.Properties['moveToFolder'] -and
        $null -ne $actions.moveToFolder) {
        $moveToFolder = [string]$actions.moveToFolder
    }

    $markAsRead  = [bool]($null -ne $actions.PSObject.Properties['markAsRead']  -and $actions.markAsRead)
    $deletePerm  = [bool]($null -ne $actions.PSObject.Properties['permanentDelete'] -and $actions.permanentDelete)
    $deleteTemp  = [bool]($null -ne $actions.PSObject.Properties['delete'] -and $actions.delete)
    $isEnabled   = [bool]($null -ne $Rule.PSObject.Properties['isEnabled'] -and $Rule.isEnabled)

    [pscustomobject]@{
        RuleId           = [string]$Rule.id
        RuleName         = [string]$Rule.displayName
        UserId           = $UserId
        UPN              = $UPN.ToLower()
        IsEnabled        = $isEnabled
        ForwardTo        = $forwardTo
        RedirectTo       = $redirectTo
        DeleteForever    = $deletePerm
        DeleteTemp       = $deleteTemp
        MarkAsRead       = $markAsRead
        MoveToFolder     = $moveToFolder
        SubjectContains  = $subjectContains
        SenderContains   = $senderContains
        BodyContains     = $bodyContains
    }
}

function ConvertFrom-OAuthGrant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Grant
    )
    $scopes = @()
    if (-not [string]::IsNullOrEmpty($Grant.scope)) {
        $scopes = @($Grant.scope -split '\s+' | Where-Object { $_ })
    }

    $createdAt = [datetime]::MinValue
    if (-not [string]::IsNullOrEmpty($Grant.createdDateTime)) {
        $createdAt = [datetimeoffset]::Parse($Grant.createdDateTime).UtcDateTime
    }

    $isExternal = $false
    if ($null -ne $Grant.appTenantId -and [string]$Grant.appTenantId -ne '') {
        $isExternal = $true
    }

    [pscustomobject]@{
        GrantId           = [string]$Grant.id
        AppId             = [string]$Grant.clientId
        AppName           = [string]$Grant.clientDisplayName
        PrincipalId       = [string]$Grant.principalId
        PrincipalUPN      = ([string]$Grant.principalUPN).ToLower()
        ResourceName      = [string]$Grant.resourceDisplayName
        Scopes            = $scopes
        PublisherVerified = [bool]$Grant.publisherVerified
        CreatedAt         = $createdAt
        IsExternalApp     = $isExternal
    }
}
