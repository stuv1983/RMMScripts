
param()

# --- Config: local account the MFP will use and target paths/share ---
$ScannerUser   = 'svc_scanner'                                 # Local service account used Scan to Folder
$LocalAccount  = "$env:COMPUTERNAME\$ScannerUser"              # Fully-qualified local account
$UserProfile   = "C:\Users\$ScannerUser"                       # Forced profile path (we create the folder if missing)
$ScansPath     = Join-Path $UserProfile 'Scans'                # Actual scans landing folder
$ShareName     = 'Scans'                                       # Share name pointing to Scans
$changed = $false                                              # Tracks whether we made any changes (for exit code)

# --- Helpers for tidy output ---
function Write-Info($m){ Write-Host "[INFO] $m" }              # Informational message
function Write-Ok($m){ Write-Host "[Great success]   $m" }                # Success/ok message
function Write-Err($m){ Write-Error $m }                       # Error message to stderr

# Check the script is running as admin (required to adjust ACLs, shares, firewall)
function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

try {
  # Abort if not admin
  if (-not (Test-IsAdmin)) { Write-Err "Please run as Administrator."; exit 3 }

  # Ensure the local svc_scanner account exists
  try {
    $null = Get-LocalUser -Name $ScannerUser -ErrorAction Stop
    Write-Ok "Local account exists: $ScannerUser"
  } catch {
    Write-Err "Local account '$ScannerUser' not found."; exit 3
  }

  # --- Ensure C:\Users\svc_scanner and Scans exist ---
  if (-not (Test-Path $UserProfile)) {
    Write-Info "Creating $UserProfile ..."
    New-Item -Path $UserProfile -ItemType Directory -Force | Out-Null
    Write-Ok "Created: $UserProfile"
    $changed = $true
  } else {
    Write-Ok "Profile folder exists: $UserProfile"
  }

  if (-not (Test-Path $ScansPath)) {
    Write-Info "Creating $ScansPath ..."
    New-Item -Path $ScansPath -ItemType Directory -Force | Out-Null
    Write-Ok "Created: $ScansPath"
    $changed = $true
  } else {
    Write-Ok "Scans folder exists: $ScansPath"
  }

  # --- NTFS permissions ---
  # Entra ID users on the device are members of BUILTIN\Users, so granting that group covers them.
  $usersGroup = New-Object System.Security.Principal.NTAccount('BUILTIN','Users')  # All local users (covers Entra users on this PC)
  $svcAccount = New-Object System.Security.Principal.NTAccount($LocalAccount)      # COMPUTERNAME\svc_scanner NTAccount object
  $allow      = [System.Security.AccessControl.AccessControlType]::Allow           # Allow rule constant

  # Parent folder traverse: let users enter C:\Users\svc_scanner (this folder only)
  $parentAcl = Get-Acl -Path $UserProfile
  $parentRequired = [System.Security.AccessControl.FileSystemRights]'ReadAndExecute, Synchronize' # RX + sync bits
  $parentInherit  = [System.Security.AccessControl.InheritanceFlags]::None                         # This folder only
  $parentProp     = [System.Security.AccessControl.PropagationFlags]::None

  # Detect if BUILTIN\Users already has the specific "this folder only" RX rule
  $hasParentRX = $false
  foreach ($r in $parentAcl.Access) {
    if ($r.IdentityReference -eq $usersGroup -and
        $r.AccessControlType -eq $allow -and
        $r.InheritanceFlags -eq $parentInherit -and
        $r.PropagationFlags -eq $parentProp   -and
        (($r.FileSystemRights -band $parentRequired) -eq $parentRequired)) {
      $hasParentRX = $true; break
    }
  }

  # Add traverse permission on the parent if missing (prevents "Access denied" when entering another user's profile)
  if (-not $hasParentRX) {
    Write-Info "Granting BUILTIN\\Users Read/Execute on $UserProfile (this folder only)..."
    $ruleParent = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $usersGroup, $parentRequired, $parentInherit, $parentProp, $allow
    )
    $parentAcl.SetAccessRule($ruleParent)
    Set-Acl -Path $UserProfile -AclObject $parentAcl
    Write-Ok "Traverse/Read set on $UserProfile for BUILTIN\\Users."
    $changed = $true
  } else {
    Write-Ok "Parent traverse already present for BUILTIN\\Users."
  }

  # Modify permissions on Scans for both svc_scanner and BUILTIN\Users (propagate to subfolders/files)
  $scansAcl      = Get-Acl -Path $ScansPath
  $modifyRights  = [System.Security.AccessControl.FileSystemRights]::Modify
  $inheritFlags  = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'  # OI, CI
  $propFlags     = [System.Security.AccessControl.PropagationFlags]::None

  # Helper to check if an account has Modify with OI/CI
  function Test-HasModify([System.Security.AccessControl.AuthorizationRuleCollection] $rules, $acct){
    foreach ($r in $rules) {
      if ($r.IdentityReference -eq $acct -and
          $r.AccessControlType -eq $allow -and
          (($r.FileSystemRights -band $modifyRights) -eq $modifyRights) -and
          ($r.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -and
          ($r.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)) {
        return $true
      }
    }
    return $false
  }

  # Determine whether updates are required for svc_scanner and BUILTIN\Users
  $needSvc  = -not (Test-HasModify $scansAcl.Access $svcAccount)
  $needUser = -not (Test-HasModify $scansAcl.Access $usersGroup)

  # Apply missing Modify rules to Scans
  if ($needSvc) {
    Write-Info "Granting Modify (OI)(CI) to $LocalAccount on $ScansPath ..."
    $ruleSvc = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $svcAccount, $modifyRights, $inheritFlags, $propFlags, $allow
    )
    $scansAcl.SetAccessRule($ruleSvc)
    $changed = $true
  }
  if ($needUser) {
    Write-Info "Granting Modify (OI)(CI) to BUILTIN\\Users on $ScansPath ..."
    $ruleUsers = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $usersGroup, $modifyRights, $inheritFlags, $propFlags, $allow
    )
    $scansAcl.SetAccessRule($ruleUsers)
    $changed = $true
  }

  # Commit NTFS changes if we added any rules
  if ($needSvc -or $needUser) {
    Set-Acl -Path $ScansPath -AclObject $scansAcl
    Write-Ok "NTFS permissions applied to $ScansPath."
  } else {
    Write-Ok "NTFS permissions already compliant on $ScansPath."
  }

  # --- Create/ensure SMB share for the MFP: \\PCNAME\KBA_Scans -> C:\Users\svc_scanner\Scans ---
  $shareExists = $false
  try {
    $null = Get-SmbShare -Name $ShareName -ErrorAction Stop   # Will throw if not present
    $shareExists = $true
    Write-Ok "Share exists: $ShareName"
  } catch {
    # Not present -> create it
    try {
      New-SmbShare -Name $ShareName -Path $ScansPath -CachingMode None -ErrorAction Stop | Out-Null
      Write-Ok "Share created: \\$env:COMPUTERNAME\$ShareName"
      $changed = $true
    } catch {
      # Fall back to NET SHARE if SMB cmdlets unavailable (older/locked-down systems)
      Write-Info "SMB cmdlets failed; trying NET SHARE..."
      $net = & net share $ShareName="$ScansPath" 2>&1
      if ($LASTEXITCODE -ne 0 -and ($net -join "`n") -notmatch 'completed successfully') {
        Write-Err "Failed to create share: $($net -join ' ')"; exit 3
      } else {
        Write-Ok "Share created via NET SHARE: \\$env:COMPUTERNAME\$ShareName"
        $changed = $true
      }
    }
  }

  # Ensure share permissions: remove Everyone; grant Change to svc_scanner and BUILTIN\Users
  try {
    Revoke-SmbShareAccess -Name $ShareName -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue | Out-Null
    Grant-SmbShareAccess  -Name $ShareName -AccountName $LocalAccount  -AccessRight Change -Force -ErrorAction Stop | Out-Null
    Grant-SmbShareAccess  -Name $ShareName -AccountName 'BUILTIN\Users' -AccessRight Change -Force -ErrorAction Stop | Out-Null
    Write-Ok "Share permissions set (Change) for $LocalAccount and BUILTIN\\Users."
  } catch {
    # Fallback path for environments where Get/Grant/Revoke-SmbShareAccess aren’t allowed
    $net2 = & net share $ShareName "/GRANT:${LocalAccount},CHANGE" "/GRANT:Users,CHANGE" 2>&1
    if ($LASTEXITCODE -ne 0 -and ($net2 -join "`n") -notmatch 'completed successfully') {
      Write-Err "Failed to set share permissions: $($net2 -join ' ')"; exit 3
    } else {
      Write-Ok "Share permissions set via NET SHARE."
    }
  }

  # --- Enable File & Printer Sharing firewall group so the MFP can reach the share ---
  try {
    Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Out-Null
    Write-Ok "Firewall group enabled: File and Printer Sharing"
  } catch {
    Write-Info "Could not enable firewall group automatically. Check local policy."
  }

  # --- Optional: put a shortcut to \\PCNAME\KBA_Scans on the Public Desktop for convenience ---
  try {
    $PublicDesktop = "$env:PUBLIC\Desktop"                     # Visible to all users on the device
    if (Test-Path $PublicDesktop) {
      $ShortcutPath  = Join-Path $PublicDesktop 'Scans.lnk'
      if (-not (Test-Path $ShortcutPath)) {
        $Target = "\\$env:COMPUTERNAME\$ShareName"            # Shortcut target UNC
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $Target
        $Shortcut.IconLocation = 'explorer.exe,0'
        $Shortcut.Save()
        Write-Ok "Shortcut created on Public Desktop."
        $changed = $true
      } else {
        Write-Ok "Shortcut already present on Public Desktop."
      }
    }
  } catch {
    Write-Info "Could not create Public Desktop shortcut: $($_.Exception.Message)"
  }

  # Exit with remediated or compliant
  if ($changed) { exit 1 } else { exit 0 }

} catch {
  # Catch any unexpected exception and return error status
  Write-Err ("Unexpected error: " + $_.Exception.Message)
  exit 3
}
