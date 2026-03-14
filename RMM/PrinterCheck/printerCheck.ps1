<#
.SYNOPSIS
    printerCheck.ps1 - RMM Printer Inventory / Health Check

.NOTES
    Name:       GP-PaperCutPrinter.ps1
    Author:     Stu Villanti (s.villanti@kenstra.com.au)
    Version:    1.0

.DESCRIPTION
    Enumerates installed printers on a Windows endpoint and outputs a tidy table suitable for
    N-able / RMM "Display Output" panes.

    For each printer, reports:
      - Printer Name
      - Driver Name
      - Port Name
      - Port Address (PrinterHostAddress or DeviceURL when available)

    Supports:
      - Wildcard filtering by printer name (default "*")
      - Optional JSON output for easier parsing by tooling

.PARAMETER PrinterName
    Wildcard filter for printer names. Examples:
      - "*" (default)        -> all printers
      - "Kyocera*"           -> printers starting with "Kyocera"
      - "*Reception*"        -> printers containing "Reception"

.PARAMETER AsJson
    When True/1, outputs structured JSON instead of a formatted table.

.OUTPUTS
    - Default: human-readable table (Write-Output)
    - JSON mode: JSON string

#>

[CmdletBinding()]
param(
    # Use "*" for all printers, or partial name e.g. "Kyocera*", "KM*"
    [Parameter()]
    [string]$PrinterName = "*",

    # RMM tasks often pass parameters as strings/objects; accept anything and convert to boolean.
    [Parameter()]
    [object]$AsJson
)

function Convert-ToBool {
    <#
    .SYNOPSIS
        Converts common truthy/falsey inputs to [bool].

    .DESCRIPTION
        RMM systems often pass parameters as strings (e.g. "True"/"False", "1"/"0").
        This helper normalises those values into a real boolean.
    #>
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object]$Value
    )
    process {
        if ($null -eq $Value) { return $false }
        if ($Value -is [bool]) { return $Value }

        # Numeric values: 0 -> False, non-zero -> True
        if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
            return [bool]([int]$Value)
        }

        # Strings: handle common cases
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

# Normalise AsJson to a real boolean
$AsJson = Convert-ToBool $AsJson

try {
    # ---------------------------------------------
    # 1) Collect printers (filtered by wildcard)
    # ---------------------------------------------
    $printers = Get-Printer -Name $PrinterName -ErrorAction Stop

    # ---------------------------------------------
    # 2) Collect ports once, index by port name
    #    (faster than calling Get-PrinterPort per printer)
    # ---------------------------------------------
    $ports = Get-PrinterPort -ErrorAction Stop | Group-Object -Property Name -AsHashTable -AsString

    # ---------------------------------------------
    # 3) Build result objects for output
    # ---------------------------------------------
    $results = foreach ($p in $printers) {
        # Attempt to find the port object for this printer
        $portObj = $null
        if ($ports.ContainsKey($p.PortName)) {
            $portObj = $ports[$p.PortName]
        }

        # Determine an "address" for the port:
        # - TCP/IP ports commonly populate PrinterHostAddress
        # - WSD ports may populate DeviceURL
        # - Local ports will not have either
        $portAddress = $null
        if ($portObj -and $portObj.PrinterHostAddress) {
            $portAddress = $portObj.PrinterHostAddress
        }
        elseif ($portObj -and $portObj.DeviceURL) {
            $portAddress = $portObj.DeviceURL
        }
        else {
            $portAddress = "(No IP / WSD / Local)"
        }

        # Output object (easy to sort / format / convert to JSON)
        [PSCustomObject]@{
            "Printer Name" = $p.Name
            "Driver Name"  = $p.DriverName
            "Port Name"    = $p.PortName
            "Port Address" = $portAddress
        }
    }

    # ---------------------------------------------
    # 4) JSON output mode (for parsing)
    # ---------------------------------------------
    if ($AsJson) {
        [pscustomobject]@{
            Count    = @($results).Count
            Filter   = $PrinterName
            Printers = $results
        } | ConvertTo-Json -Depth 4
        exit 0
    }

    # ---------------------------------------------
    # 5) Human-readable table output mode (RMM)
    # ---------------------------------------------
    if (-not $results) {
        Write-Output "No printers found matching filter '$PrinterName'."
        exit 1
    }

    # Format as a clean table for RMM Display Output
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
    # Fail safe: emit the exception message so it’s visible in the RMM output
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
