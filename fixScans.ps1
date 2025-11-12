# Adjust these to suit your environment
$UserName = 'svc_scanner'
$ScanPath = "C:\Users\$UserName\Scans"
$ShareName = 'Scans'
$Computer = $env:COMPUTERNAME

# 1) Create folder if missing
if (-not (Test-Path -LiteralPath $ScanPath)) {
    New-Item -Path $ScanPath -ItemType Directory -Force | Out-Null
    Write-Host "Created $ScanPath"
} else {
    Write-Host "Folder exists: $ScanPath"
}

# 2) NTFS permissions
# Give the scanner account Modify and the local Users group Read (change to Modify if you want users to delete/overwrite)
$scannerAccount = "$Computer\$UserName"
# grant Modify to scanner
icacls $ScanPath /grant "${scannerAccount}:(OI)(CI)M" /C | Out-Null
# grant Read & Execute for Users
icacls $ScanPath /grant "BUILTIN\Users:(OI)(CI)(M)" /C | Out-Null

Write-Host "Applied NTFS ACLs: $scannerAccount = Modify ; BUILTIN\Users = Read"

# 3) Create or update SMB share with Change access for Users (so they can copy files off)
if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $ShareName -Path $ScanPath -ChangeAccess 'Users' -FullAccess 'Administrators' | Out-Null
    Write-Host "Created SMB share \\$Computer\$ShareName"
} else {
    # Update access if exists
    Grant-SmbShareAccess -Name $ShareName -AccountName 'Users' -AccessRight Change -Force | Out-Null
    Write-Host "Updated SMB share permissions for \\$Computer\$ShareName"
}

# 4) Ensure File & Printer Sharing firewall rules are enabled
Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled True -ErrorAction SilentlyContinue | Out-Null
Write-Host "Enabled File & Printer Sharing firewall rules"

# 5) Summary and test hint
Write-Host ""
Write-Host "Done. Test by:"
Write-Host " - On the MFP use credentials: $UserName and the account password to scan to \\$Computer\$ShareName\$UserName (or just \\$Computer\$ShareName)"
Write-Host " - On the PC, open File Explorer: \\$Computer\$ShareName  (or open $ScanPath)"
