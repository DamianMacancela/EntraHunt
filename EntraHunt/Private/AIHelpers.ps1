function ConvertTo-PseudonymizedPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Finding
    )
    $map      = [System.Collections.Generic.Dictionary[string,string]]::new(
        [System.StringComparer]::Ordinal
    )
    $ctrEmail = 0
    $ctrIp    = 0
    $ctrId    = 0

    $reEmail = [regex]'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    $reIpv4  = [regex]'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    $reGuid  = [regex]'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

    $pseudoData = foreach ($f in $Finding) {
        $json = $f | ConvertTo-Json -Depth 4 -Compress

        $json = $reEmail.Replace($json, {
            param($m)
            $v = $m.Value
            if (-not $map.ContainsKey($v)) {
                $ctrEmail++
                $map[$v] = 'EMAIL_{0:D4}' -f $ctrEmail
            }
            $map[$v]
        })

        $json = $reIpv4.Replace($json, {
            param($m)
            $v = $m.Value
            if (-not $map.ContainsKey($v)) {
                $ctrIp++
                $map[$v] = 'IP_{0:D4}' -f $ctrIp
            }
            $map[$v]
        })

        $json = $reGuid.Replace($json, {
            param($m)
            $v = $m.Value.ToLower()
            if (-not $map.ContainsKey($v)) {
                $ctrId++
                $map[$v] = 'ID_{0:D4}' -f $ctrId
            }
            $map[$v]
        })

        $json | ConvertFrom-Json
    }

    $mapHt = @{}
    foreach ($kvp in $map.GetEnumerator()) { $mapHt[$kvp.Key] = $kvp.Value }

    [pscustomobject]@{
        Payload = $pseudoData
        Map     = $mapHt
    }
}

function Restore-AIFindingTokens {
    [CmdletBinding()]
    param(
        [string]$Text,
        [hashtable]$Map
    )
    $reversed = @{}
    foreach ($k in $Map.Keys) { $reversed[$Map[$k]] = $k }
    $result = $Text
    # Sort by token length descending to avoid partial replacements
    foreach ($token in ($reversed.Keys | Sort-Object { $_.Length } -Descending)) {
        $result = $result.Replace($token, $reversed[$token])
    }
    return $result
}

function Invoke-AnthropicAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SystemPrompt,
        [Parameter(Mandatory)][string]$UserMessage,
        [Parameter(Mandatory)][System.Security.SecureString]$ApiKey,
        [string]$Model = 'claude-opus-4-5'
    )
    $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
    $plainKey = ''
    try {
        $plainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    $bodyObj = [ordered]@{
        model      = $Model
        max_tokens = 2048
        system     = $SystemPrompt
        messages   = @(@{ role = 'user'; content = $UserMessage })
    }
    $bodyJson = $bodyObj | ConvertTo-Json -Depth 5

    $response = Invoke-RestMethod `
        -Uri     'https://api.anthropic.com/v1/messages' `
        -Method  POST `
        -Headers @{
            'x-api-key'         = $plainKey
            'anthropic-version' = '2023-06-01'
            'content-type'      = 'application/json'
        } `
        -Body $bodyJson

    return $response.content[0].text
}

function Invoke-OllamaAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SystemPrompt,
        [Parameter(Mandatory)][string]$UserMessage,
        [string]$BaseUri = 'http://localhost:11434',
        [string]$Model   = 'llama3.1'
    )
    $bodyObj  = @{
        model  = $Model
        prompt = "$SystemPrompt`n`nUser: $UserMessage"
        stream = $false
        format = 'json'
    }
    $bodyJson = $bodyObj | ConvertTo-Json
    $response = Invoke-RestMethod `
        -Uri         "$BaseUri/api/generate" `
        -Method      POST `
        -Body        $bodyJson `
        -ContentType 'application/json'
    return $response.response
}

function Invoke-AIResponseValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RawJson,
        [Parameter(Mandatory)][string[]]$ValidIds
    )
    $validVerdicts = @('benign', 'suspicious', 'malicious', 'uncertain')
    $parsed = $null
    try {
        $parsed = $RawJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-HuntLog "AI returned non-JSON response: $_" -Level Warning
        return @()
    }
    if ($null -eq $parsed.analysis) {
        Write-HuntLog 'AI response missing .analysis array' -Level Warning
        return @()
    }
    $validated = @($parsed.analysis | Where-Object {
        $item = $_
        $idOk = $item.finding_id -in $ValidIds
        if (-not $idOk) {
            Write-HuntLog "AI unknown finding_id '$($item.finding_id)' - discarded" -Level Warning
        }
        $vOk = $item.verdict -in $validVerdicts
        if (-not $vOk) {
            Write-HuntLog "AI invalid verdict '$($item.verdict)' - discarded" -Level Warning
        }
        $idOk -and $vOk
    })
    foreach ($item in $validated) {
        $conf = [double]$item.confidence
        if ($conf -lt 0 -or $conf -gt 1) {
            $item.confidence = [Math]::Max(0.0, [Math]::Min(1.0, $conf))
        }
    }
    return $validated
}
