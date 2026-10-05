$ErrorActionPreference = 'Stop'

Describe 'EntraHunt Core Logic' {
    BeforeAll {
        . "$PSScriptRoot\..\EntraHunt\Private\Common.ps1"
        . "$PSScriptRoot\..\EntraHunt\Private\Normalize.ps1"
        . "$PSScriptRoot\..\EntraHunt\Private\Detect.ps1"
        . "$PSScriptRoot\..\EntraHunt\Private\AIHelpers.ps1"
        . "$PSScriptRoot\..\EntraHunt\Public\Detect.ps1"
        . "$PSScriptRoot\..\EntraHunt\Public\Export-EntraReport.ps1"
        $script:HuntConfig = Import-PowerShellDataFile "$PSScriptRoot\..\EntraHunt\Data\detections.psd1"
    }

    Context 'Normalizers' {
        It 'ConvertFrom-SignInEvent - processes success event' {
            $raw = [pscustomobject]@{
                id = '123'
                createdDateTime = '2023-10-01T10:00:00Z'
                userPrincipalName = 'TEST@CONTOSO.COM'
                status = [pscustomobject]@{ errorCode = 0 }
            }
            $evt = $raw | ConvertFrom-SignInEvent
            $evt.IsSuccess | Should -Be $true
            $evt.UPN | Should -Be 'test@contoso.com'
        }
    }

    Context 'Detections - PURE' {
        It 'SI003 - detects success after failure' {
            $events = @(
                [pscustomobject]@{ UPN='u1'; IpAddress='1.1.1.1'; IsSuccess=$false; ErrorCode=50126; Timestamp=[datetime]::UtcNow.AddMinutes(-5) }
                [pscustomobject]@{ UPN='u1'; IpAddress='1.1.1.1'; IsSuccess=$false; ErrorCode=50126; Timestamp=[datetime]::UtcNow.AddMinutes(-4) }
                [pscustomobject]@{ UPN='u1'; IpAddress='1.1.1.1'; IsSuccess=$false; ErrorCode=50126; Timestamp=[datetime]::UtcNow.AddMinutes(-3) }
                [pscustomobject]@{ UPN='u1'; IpAddress='1.1.1.1'; IsSuccess=$true;  ErrorCode=0;     Timestamp=[datetime]::UtcNow.AddMinutes(-2) }
            )
            $findings = Invoke-SignInDetection -Events $events
            $si3 = $findings | Where-Object { $_.Rule -eq 'SI003' }
            $si3 | Should -Not -BeNullOrEmpty
            $si3.Severity | Should -Be 'High'
        }

        It 'IR001 - detects external forwarding' {
            $rules = @(
                [pscustomobject]@{ RuleName='Fwd'; IsEnabled=$true; UPN='u1'; ForwardTo=@('bad@gmail.com'); RedirectTo=@() }
            )
            $findings = Invoke-InboxRuleDetection -Rules $rules -OrgDomain 'contoso.com'
            $ir1 = $findings | Where-Object { $_.Rule -eq 'IR001' }
            $ir1 | Should -Not -BeNullOrEmpty
            $ir1.Severity | Should -Be 'Critical'
        }
    }

    Context 'AI Integration' {
        It 'ConvertTo-PseudonymizedPayload - hides PII' {
            $f = [pscustomobject]@{ UPN = 'secret@company.com'; IP = '8.8.8.8' }
            $out = ConvertTo-PseudonymizedPayload -Finding @($f)
            $out.Payload[0].UPN | Should -Not -Match 'secret@company.com'
            $out.Payload[0].UPN | Should -Match 'EMAIL_0001'
            $out.Payload[0].IP | Should -Match 'IP_0001'
        }
    }

    Context 'Report Generation' {
        It 'Export-EntraReport - generates safe HTML' {
            $f = [pscustomobject]@{ Rule='XSS'; Severity='Low'; Title='<script>alert(1)</script>'; Principal='admin'; AIVerdict='N/A'; AIReasoning='' }
            $path = Join-Path $TestDrive 'report.html'
            Export-EntraReport -Findings @($f) -OutputPath $path
            $html = Get-Content $path -Raw
            $html | Should -Not -Match '<script>'
            $html | Should -Match '&lt;script&gt;'
        }
    }
}
