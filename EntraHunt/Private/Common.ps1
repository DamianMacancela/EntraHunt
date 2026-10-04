function Write-HuntLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    $ts   = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "[$ts][$Level] $Message"
    switch ($Level) {
        'Warning' { Write-Warning $line }
        'Error'   { Write-Error   $line }
        'Debug'   { Write-Debug   $line }
        default   { Write-Verbose $line }
    }
}

function Get-HuntId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputString
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return -join ($hash[0..7] | ForEach-Object { $_.ToString('x2') })
}

function ConvertTo-SafeHtml {
    [CmdletBinding()]
    param(
        [string]$Value
    )
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-HuntFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Rule,
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low')]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Principal,
        [Parameter(Mandatory)][string]$Mitre,
        [object]$Evidence = $null
    )
    $idKey = "$Rule|$Principal|$([datetime]::UtcNow.ToString('yyyyMMdd'))"
    [pscustomobject]@{
        Id         = Get-HuntId -InputString $idKey
        Rule       = $Rule
        Severity   = $Severity
        Title      = $Title
        Principal  = $Principal
        Mitre      = $Mitre
        Evidence   = $Evidence
        DetectedAt = [datetime]::UtcNow
    }
}
