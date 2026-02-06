<#
.SYNOPSIS
    PaperCut Follow Me - Printer Connection Script (RMM Safe)


.NOTES
    Name:       OfficeVersionandUpdateChannelAudit.ps1
    Author:     Stu Villanti (s.villanti@kenstra.com.au)
    Version:    4.0

.DESCRIPTION
    Adds a PaperCut "Follow Me" shared printer connection from the nominated print server.

    Built for MSP/RMM execution where:
      - Output must be clear and ticket-note friendly
      - Re-runs must be safe (idempotent: won't re-add if already present)
      - Exit codes must be predictable (0/1)

    Behaviour:
      1) Build UNC printer connection: \\<PrintServer>\<PrinterShare>
      2) Check if that printer connection already exists
      3) Add printer if missing (or if -Force is used)
      4) Output result and exit

.PARAMETER PrintServer
    Print server hostname/FQDN (default: pc-print-01)

.PARAMETER PrinterShare
    Printer share name as published on the print server (default: "PaperCut Follow Me")

.PARAMETER Force
    If specified, attempts to add the printer even if it appears installed already.
    Useful if a stale/broken printer object exists locally.

.OUTPUTS
    Text output (Write-Output) suitable for N-able / RMM “Display Output”.

.EXITCODES
    0 = Printer already present OR successfully added
    1 = Failed to add printer
#>

[CmdletBinding()]
param(
    # Print server hosting the shared printer
    [Parameter()]
    [string]$PrintServer = "pc-print-01",

    # Share name of the Follow Me queue on the print server
    [Parameter()]
    [string]$PrinterShare = "PaperCut Follow Me",

    # Override idempotency checks
    [Parameter()]
    [switch]$Force
)

# ------------------------------------------------------------
# 1) Build printer connection UNC
# ------------------------------------------------------------
# Example: \\pc-print-01\PaperCut Follow Me
$Connection = "\\{0}\{1}" -f $PrintServer, $PrinterShare

try {
    # ------------------------------------------------------------
    # 2) Detect existing printer connection (idempotency)
    # ------------------------------------------------------------
    # Shared printers typically show the share UNC in ConnectionName.
    # We check that first because it’s the most reliable.
    $existing = Get-Printer -ErrorAction Stop |
        Where-Object { $_.ConnectionName -eq $Connection } |
        Select-Object -First 1

    if ($existing -and -not $Force) {
        Write-Output "Printer already installed: $Connection"
        exit 0
    }

    # ------------------------------------------------------------
    # 3) Add the printer connection
    # ------------------------------------------------------------
    # Note:
    # - In SYSTEM context (common for RMM), this often becomes machine-level.
    # - In user context, it becomes a per-user connection.
    Add-Printer -ConnectionName $Connection -ErrorAction Stop

    Write-Output "Printer successfully added: $Connection"
    exit 0
}
catch {
    # ------------------------------------------------------------
    # 4) Failure handling (RMM friendly)
    # ------------------------------------------------------------
    Write-Output "ERROR: Failed to add printer: $Connection"
    Write-Output ("ERROR: {0}" -f $_.Exception.Message)
    exit 1
}
