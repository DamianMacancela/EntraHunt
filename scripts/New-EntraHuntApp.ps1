<#
.SYNOPSIS
    Creates an Entra ID App Registration with a self-signed certificate for unattended access.
#>
[CmdletBinding()]
param(
    [string]$AppName = "EntraHunt-AuditApp-$((Get-Date).ToString('yyyyMMdd'))"
)

# [VERIFICAR] Requirements: Global Admin or Application Admin role

Write-Host "Creating Self-Signed Certificate..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Subject "CN=$AppName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy NonExportable
$thumbprint = $cert.Thumbprint
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

Write-Host "Connecting to Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -NoWelcome

Write-Host "Creating Application '$AppName'..." -ForegroundColor Cyan
$appParams = @{
    DisplayName = $AppName
    KeyCredentials = @(
        @{
            Type = "AsymmetricX509Cert"
            Usage = "Verify"
            Key = $certBytes
        }
    )
}
$app = New-MgApplication @appParams
$sp = New-MgServicePrincipal -AppId $app.AppId

# Assign permissions: AuditLog.Read.All, Directory.Read.All, MailboxSettings.Read
# We need to find the Microsoft Graph Service Principal
$graphSp = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

$rolesToGrant = @("AuditLog.Read.All", "Directory.Read.All", "MailboxSettings.Read")
foreach ($roleName in $rolesToGrant) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $roleName }
    if ($role) {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $role.Id | Out-Null
        Write-Host "Granted $roleName"
    }
}

Write-Host "`nApp Registration Complete!" -ForegroundColor Green
Write-Host "Tenant ID:      $((Get-MgOrganization).Id)"
Write-Host "Client ID:      $($app.AppId)"
Write-Host "Cert Thumb:     $thumbprint"
Write-Host "`nIMPORTANT: An administrator must still grant admin consent in the Entra portal!" -ForegroundColor Yellow
Write-Host "Run this to connect later:"
Write-Host "Connect-EntraHunt -TenantId '$((Get-MgOrganization).Id)' -ClientId '$($app.AppId)' -CertificateThumbprint '$thumbprint'"
