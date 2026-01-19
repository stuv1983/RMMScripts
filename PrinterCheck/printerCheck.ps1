# RMM Printer Check - Display Output Table
# Lists: Printer Name, Driver Name, Port Name, Port/IP Address

[CmdletBinding()]
param(
    # Use "*" for all printers, or partial name e.g. "Kyocera*", "KM*"
    [Parameter()] [string]$PrinterName = "*",
    [Parameter()] [object]$AsJson
)

function Convert-ToBool {
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        if ($null -eq $Value) { return $false }
        if ($Value -is [bool]) { return $Value }
        if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
            return [bool]([int]$Value)
        }
        $v = "$Value".Trim().ToLowerInvariant()
        switch ($v) {
            'true'  { return $true }
            'false' { return $false }
            '1'     { return $true }
            '0'     { return $false }
            default { return $false }
        }
    }
}

$AsJson = Convert-ToBool $AsJson

try {
    # Get printers (filtered if name pattern set)
    $printers = Get-Printer -Name $PrinterName -ErrorAction Stop

    # Get all ports once and index by name for quick lookup
    $ports = Get-PrinterPort | Group-Object -Property Name -AsHashTable -AsString

    $results = foreach ($p in $printers) {
        $portObj = $null
        if ($ports.ContainsKey($p.PortName)) {
            $portObj = $ports[$p.PortName]
        }

        # Try to get IP/host address if available (TCP/IP or WSD with data)
        $portAddress = $null
        if ($portObj -and $portObj.PrinterHostAddress) {
            $portAddress = $portObj.PrinterHostAddress
        } elseif ($portObj -and $portObj.DeviceURL) {
            $portAddress = $portObj.DeviceURL
        } else {
            $portAddress = "(No IP / WSD / Local)"
        }

        [PSCustomObject]@{
            "Printer Name" = $p.Name
            "Driver Name"  = $p.DriverName
            "Port Name"    = $p.PortName
            "Port Address" = $portAddress
        }
    }

    if ($AsJson) {
        [pscustomobject]@{
            Count    = @($results).Count
            Filter   = $PrinterName
            Printers = $results
        } | ConvertTo-Json -Depth 4
        exit 0
    }

    if (-not $results) {
        Write-Output "No printers found matching filter '$PrinterName'."
        exit 1
    }

    # Nice table for RMM Display Output
    $table = $results |
        Sort-Object 'Printer Name' |
        Format-Table -AutoSize |
        Out-String

    Write-Output "PRINTER INVENTORY"
    Write-Output "=================="
    Write-Output $table

    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
