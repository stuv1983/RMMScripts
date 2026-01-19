# RMM Printer Check - Display Output Table
# Lists: Printer Name, Driver Name, Port Name, Port/IP Address

# -------------------------
# CONFIG (optional)
# -------------------------
# Use "*" for all printers, or partial name e.g. "Kyocera*", "KM*"
$PrinterName = "*"

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
