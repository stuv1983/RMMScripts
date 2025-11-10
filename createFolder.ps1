<#
.SYNOPSIS
  FINAL CONFIGURATION: Creates and secures a local share for Konica Minolta SMB scanning.

.DESCRIPTION
  This script is designed for Entra ID (Azure AD) environments where end-users are NOT local administrators.
  It creates the local service user (KBA_Scans) for the printer, sets the C:\KBA_Scans share,
  and grants explicit NTFS and Share access to both the service user and the currently logged-in
  Entra ID user (for file retrieval). It also includes necessary firewall adjustments.

.NOTES
  - Runs with Administrator/SYSTEM privileges (via RMM).
  - The final output provides the exact data needed for the Konica Minolta Address Book.
#>

# --- REQUIRED VARIABLES (EDIT THIS LINE) ---
$LocalScanUser = "KBA_Scans"
$PlainTextPassword = "Kenstra365#^%" # <--- Password for KBA_Scans (CRITICAL: CHANGE THIS!)
$FolderName = "KBA_Scans" # The name of the folder and the share (C:\KBA_Scans)
# ----------------------------------------------------

# --- CONFIGURATION SWITCHES ---
$EnableFirewall = $true
$TestConnectivity = $false # Set to false to avoid potential RMM errors (rely on copier's test)
$ExitCode = 99 # Default script failure code

# Function to ensure the script is running with elevated privileges
function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pri = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Script must run elevated (Administrator/SYSTEM)."
    }
}

# Function to reliably get the primary IPv4 address of the device
function Get-PrimaryIPv4 {
    try {
        $addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress -notmatch '^169\.254\.|^127\.0\.0\.1' -and $_.AddressState -ne 'Deprecated' } |
                 Sort-Object -Property SkipAsSource, PrefixLength |
                 Select-Object -First 1
        return $addr.IPAddress
    } catch { return $null }
}

try {
    Assert-Administrator
    
    $comp = $env:COMPUTERNAME
    $scanPath = "C:\$FolderName"
    $printerPrincipal = "$comp\$LocalScanUser" # Fully qualified local user name (PCNAME\KBA_Scans)
    $loggedInUserPrincipalName = $env:USERNAME # Local principal name of the Entra ID user (e.g., stuar)

    Write-Host "== Starting Scan Share Setup (Final Version) =="
    Write-Host " Printer User : $LocalScanUser"
    Write-Host " Reader User  : $loggedInUserPrincipalName (Entra ID Login)"
    Write-Host ""

    # 1) Create/Update new KBA_Scans user (THE PRINTER WRITER ACCOUNT)
    try {
        $sec = ConvertTo-SecureString $PlainTextPassword -AsPlainText -Force
        if (-not (Get-LocalUser -Name $LocalScanUser -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $LocalScanUser -Password $sec -Description "SMB Scan Account (Printer Writer)" -PasswordNeverExpires -UserMayNotChangePassword:$false | Out-Null
            Write-Host "Created new local user: $LocalScanUser"
        } else {
            Set-LocalUser -Name $LocalScanUser -Password $sec
            Write-Host "Updated password for existing user: $LocalScanUser"
        }
    } catch {
        Write-Error "Error 10: User create/update failed: $($_.Exception.Message)"; exit 10
    }

    # 2) Create folder
    try {
        if (-not (Test-Path -Path $scanPath)) { New-Item -Path $scanPath -ItemType Directory -Force | Out-Null }
        Write-Host "Folder confirmed at: $scanPath"
    } catch { Write-Error "Error 11: Folder create failed: $($_.Exception.Message)"; exit 11 }


    # 3) NTFS ACL Setup (For both the Writer and the Entra ID Reader)
    try {
        # Dynamically retrieve the local security principal name for the Entra ID user currently logged in
        $CurrentLoggedInUser = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        $ReaderPrincipalName = $CurrentLoggedInUser.Split('\')[-1] # Extracts just the local user name (e.g., 'stuar')

        $acl = Get-Acl -Path $scanPath
        # Disable inheritance & remove inherited rules for a clean slate
        $acl.SetAccessRuleProtection($true, $false) 
        
        # --- WRITER RULES (Permissions for the printer to write files) ---
        $ruleSystem  = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $ruleAdmins  = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $ruleScanner = New-Object System.Security.AccessControl.FileSystemAccessRule($printerPrincipal, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        
        $null = $acl.SetAccessRule($ruleSystem)
        $null = $acl.SetAccessRule($ruleAdmins)
        $null = $acl.SetAccessRule($ruleScanner)
        
        # --- READER RULE (Explicit access for the non-Admin Entra ID user) ---
        $ruleReader = New-Object System.Security.AccessControl.FileSystemAccessRule($ReaderPrincipalName, "Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
        $null = $acl.SetAccessRule($ruleReader)

        Set-Acl -Path $scanPath -AclObject $acl
        Write-Host "NTFS: Granted Full Control to $LocalScanUser and Modify to Reader $ReaderPrincipalName."
    } catch {
        Write-Error "Error 12: NTFS ACL failed: $($_.Exception.Message)"; exit 12
    }


    # 4) SMB share and Share ACL
    try {
        if (-not (Get-SmbShare -Name $FolderName -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name $FolderName -Path $scanPath -Description "Scan-to-Folder" | Out-Null
        }
        
        # --- Ensure the printer user (LocalScanUser) has Full Share access (WRITER) ---
        try { Revoke-SmbShareAccess -Name $FolderName -AccountName $printerPrincipal -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        Grant-SmbShareAccess -Name $FolderName -AccountName $printerPrincipal -AccessRight Full -Force | Out-Null
        
        # --- Ensure the Entra ID user also has access at the share level (READER) ---
        try { Revoke-SmbShareAccess -Name $FolderName -AccountName $loggedInUserPrincipalName -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        Grant-SmbShareAccess -Name $FolderName -AccountName $loggedInUserPrincipalName -AccessRight Change -Force | Out-Null
        
        Write-Host "Share ACL: Granted Full to $LocalScanUser and Change to $loggedInUserPrincipalName."

    } catch {
        Write-Error "Error 13: SMB share/ACL failed: $($_.Exception.Message)"; exit 13
    }

    # 5) Firewall and Network Profile Fix (Opens port 445 and ensures Private profile)
    if ($EnableFirewall) {
        try {
            # Safely find the active adapter name
            $ActiveProfile = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -ne 'Public' } | Select-Object -First 1
            
            if ($ActiveProfile -ne $null) {
                Set-NetConnectionProfile -InterfaceIndex $ActiveProfile.InterfaceIndex -NetworkCategory Private | Out-Null
                Write-Host "Firewall: Set profile to Private (Adapter: $($ActiveProfile.InterfaceAlias))."
            } else {
                Write-Warning "Could not reliably set network profile to 'Private'. Continuing anyway."
            }
            
            # Enable File and Printer Sharing group (this opens the necessary Port 445)
            Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Out-Null
            Write-Host "Firewall: Enabled File and Printer Sharing group."
            
        } catch {
            Write-Error "Error 14: Firewall enable/profile set failed: $($_.Exception.Message)"; exit 14
        }
    }

    $ip = Get-PrimaryIPv4
    Write-Host ""
    Write-Host "=================================================="
    Write-Host "SUCCESS: PC is ready for scanning."
    Write-Host "--- DATA FOR COPIER ADDRESS BOOK ---"
    Write-Host "Host Address: $ip"
    Write-Host "File Path: $FolderName"
    Write-Host "Login User ID: $LocalScanUser"
    Write-Host "Password: (The password entered)"
    Write-Host "=================================================="
    exit 0
}
catch {
    Write-Error "Error 99: Unexpected script failure: $($_.Exception.Message)"
    exit 99
}