function Export-EntraReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>EntraHunt Report</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .sev-Critical { color: #fff; background-color: #d9534f; font-weight: bold; }
        .sev-High { background-color: #f0ad4e; font-weight: bold; }
        .sev-Medium { background-color: #5bc0de; }
        .sev-Low { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>EntraHunt Threat Report</h1>
    <p>Generated at: $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ssZ'))</p>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Title</th>
                <th>Principal</th>
                <th>MITRE</th>
                <th>AI Verdict</th>
                <th>AI Reason</th>
            </tr>
        </thead>
        <tbody>
"@
    
    foreach ($f in $Findings) {
        $sevClass = "sev-$($f.Severity)"
        $aiVerdict = if ($null -ne $f.PSObject.Properties['AIVerdict']) { ConvertTo-SafeHtml $f.AIVerdict } else { 'N/A' }
        $aiReason  = if ($null -ne $f.PSObject.Properties['AIReasoning']) { ConvertTo-SafeHtml $f.AIReasoning } else { '' }
        
        $html += @"
            <tr>
                <td class="$sevClass">$($f.Severity)</td>
                <td>$(ConvertTo-SafeHtml $f.Rule)</td>
                <td>$(ConvertTo-SafeHtml $f.Title)</td>
                <td>$(ConvertTo-SafeHtml $f.Principal)</td>
                <td>$(ConvertTo-SafeHtml $f.Mitre)</td>
                <td>$aiVerdict</td>
                <td>$aiReason</td>
            </tr>
"@
    }

    $html += @"
        </tbody>
    </table>
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding utf8
    Write-HuntLog "Report exported to $OutputPath" -Level Info
}
