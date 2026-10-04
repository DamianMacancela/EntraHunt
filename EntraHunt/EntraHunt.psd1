@{
    RootModule = 'EntraHunt.psm1'
    ModuleVersion = '0.1.0'
    CompatiblePSEditions = 'Desktop', 'Core'
    GUID = '12345678-1234-1234-1234-123456789012'
    Author = 'Damian Fabricio Macancela Caguana'
    CompanyName = 'DamianMacancela'
    Copyright = '(c) DamianMacancela. All rights reserved.'
    Description = 'Microsoft Entra ID Threat Hunting module with AI Triage'
    PowerShellVersion = '5.1'
    RequiredModules = @(
        @{ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0'}
    )
    FunctionsToExport = @(
        'Connect-EntraHunt',
        'Invoke-EntraAudit',
        'Invoke-EntraAIAnalysis',
        'Export-EntraReport'
    )
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'EntraID', 'ThreatHunting', 'AI')
            ProjectUri = 'https://github.com/DamianMacancela/EntraHunt'
        }
    }
}
