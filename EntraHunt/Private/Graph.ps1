function Invoke-GraphPaged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [int]$MaxPages = 100
    )
    $all  = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0

    while ($null -ne $next -and $page -lt $MaxPages) {
        $retries  = 0
        $response = $null

        while ($retries -lt 4) {
            try {
                $response = Invoke-MgGraphRequest -Uri $next -Method GET -OutputType PSObject
                break
            }
            catch {
                $status = 0
                if ($null -ne $_.Exception.Response) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
                if ($status -in @(429, 503, 504) -and $retries -lt 3) {
                    $wait = [Math]::Pow(2, $retries + 1)
                    Write-HuntLog "HTTP $status on Graph - retrying in ${wait}s" -Level Warning
                    Start-Sleep -Seconds $wait
                    $retries++
                }
                else { throw }
            }
        }

        if ($null -ne $response) {
            if ($null -ne $response.value) {
                $all.AddRange([object[]]@($response.value))
            }
            elseif ($response.PSObject.Properties.Name -notcontains 'value') {
                $all.Add($response)
            }

            $next = $null
            if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                $next = $response.'@odata.nextLink'
            }
        }
        else {
            $next = $null
        }
        $page++
    }

    return $all.ToArray()
}
