$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$Agent = Get-ItemProperty $RegPaths -ErrorAction SilentlyContinue |
Where-Object {
    $_.DisplayName -like "*Advanced Monitoring Agent*"
}

if ($Agent) {
    Write-Host "=== N-able Advanced Monitoring Agent Detected ==="

    foreach ($A in $Agent) {
        $InstallDateFormatted = $null

        if ($A.InstallDate -match '^\d{8}$') {
            $InstallDateFormatted = [datetime]::ParseExact($A.InstallDate, 'yyyyMMdd', $null)
        }

        $InstallLocationModified = $null
        if ($A.InstallLocation -and (Test-Path $A.InstallLocation)) {
            $InstallLocationModified = (Get-Item $A.InstallLocation).LastWriteTime
        }

        $WinAgentPaths = @(
            "C:\Program Files (x86)\Advanced Monitoring Agent\winagent.exe",
            "C:\Program Files\Advanced Monitoring Agent\winagent.exe"
        )

        $WinAgentFile = $WinAgentPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        $WinAgentModified = $null
        $WinAgentVersion = $null

        if ($WinAgentFile) {
            $WinAgentItem = Get-Item $WinAgentFile
            $WinAgentModified = $WinAgentItem.LastWriteTime
            $WinAgentVersion = $WinAgentItem.VersionInfo.ProductVersion
        }

        [PSCustomObject]@{
            DisplayName              = $A.DisplayName
            DisplayVersion           = $A.DisplayVersion
            Publisher                = $A.Publisher
            InstallDate              = $A.InstallDate
            InstallDateFormatted     = $InstallDateFormatted
            InstallLocation          = $A.InstallLocation
            InstallLocationModified  = $InstallLocationModified
            WinAgentPath             = $WinAgentFile
            WinAgentProductVersion   = $WinAgentVersion
            WinAgentLastModified     = $WinAgentModified
        } | Format-List
    }
}
else {
    Write-Host "Advanced Monitoring Agent not found in uninstall registry."
}