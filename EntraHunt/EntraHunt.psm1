# EntraHunt Module Loader
$public  = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)
$private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)

foreach ($import in @($private + $public)) {
    try {
        . $import.FullName
    } catch {
        Write-Error "Failed to load $($import.FullName): $_"
    }
}

$cfgPath = Join-Path $PSScriptRoot 'Data' 'detections.psd1'
if (Test-Path $cfgPath) {
    $script:HuntConfig = Import-PowerShellDataFile -Path $cfgPath
} else {
    Write-Warning "Configuration file missing at $cfgPath"
}

$script:HuntConnected = $false
$script:HuntConnectionType = 'None'

Export-ModuleMember -Function Connect-EntraHunt, Invoke-EntraAudit, Invoke-EntraAIAnalysis, Export-EntraReport
