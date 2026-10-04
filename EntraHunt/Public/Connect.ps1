function Connect-EntraHunt {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the permissions required by EntraHunt.
    .DESCRIPTION
        Delegated mode: Interactive browser prompt. Requires AuditLog.Read.All + Directory.Read.All.
        App-only mode:  Uses a certificate registered via scripts/New-EntraHuntApp.ps1.
    .EXAMPLE
        Connect-EntraHunt
    .EXAMPLE
        Connect-EntraHunt -TenantId 'xxxxxxxx-xxxx' -ClientId 'yyyyyyyy-yyyy' -CertificateThumbprint 'ABCD1234'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Delegated')]
    param(
        [Parameter(ParameterSetName = 'AppOnly', Mandatory)]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'AppOnly', Mandatory)]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'AppOnly', Mandatory)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Delegated')]
        [string[]]$Scopes = @(
            'AuditLog.Read.All',
            'Directory.Read.All',
            'MailboxSettings.Read'
        )
    )

    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        Connect-MgGraph `
            -TenantId             $TenantId `
            -ClientId             $ClientId `
            -CertificateThumbprint $CertificateThumbprint `
            -NoWelcome
        $script:HuntConnectionType = 'AppOnly'
    }
    else {
        Connect-MgGraph -Scopes $Scopes -NoWelcome
        $script:HuntConnectionType = 'Delegated'
    }

    $script:HuntConnected = $true
    Write-HuntLog "Connected to Microsoft Graph ($($script:HuntConnectionType))" -Level Info
}
