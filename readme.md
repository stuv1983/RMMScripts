# NoC Script Collection

> ⚠️ **Disclaimer**  
> Run at your own risk. Test thoroughly in a lab first. The author is not responsible for any damage, data loss, or unexpected outcomes.

## Main Overview
A collection of **PowerShell scripts** for **NOC / MSP** environments to automate endpoint health checks, patching, and upgrade readiness.  
All scripts are **RMM‑friendly** (clear console output + exit codes) and safe for scheduled automation when properly tested.

---

## 📦 Scripts in this Repo
- **AVCheck.ps1** – Focused antivirus & Defender posture check (Defender + 3rd‑party aware).
- **SecurityCheck.ps1** – Endpoint security posture in one pass (AV/Firewall/Updates/Reboot).  
- **AutoWindowsUpdate.ps1** – *Basic* Windows Update checker/installer.  
- **Update-Chrome.ps1** – Updates Google Chrome via Winget with "Pending Reboot" detection.
- **HDDUsageCheck.ps1** – Lightweight script to check what is using data on C:
- **AutoDiskCleanup** is a production-ready PowerShell automation designed for MSP/RMM environments. It runs Windows Disk Cleanup (`cleanmgr.exe`) **silently**, without user-facing UI, and provides clear **before/after disk space reporting** directly to RMM output.

---

# AVCheck.ps1

## Overview
**AVCheck.ps1** performs a **dedicated antivirus posture check** optimised for MSP/NOC monitoring.  
It validates **installed AV products**, **real‑time protection state**, **Microsoft Defender health**, **signature currency**, and **Defender for Endpoint (MDE)** onboarding.

This script is intentionally narrower than `SecurityCheck.ps1` and is ideal for:
- Antivirus‑only monitors
- High‑frequency health checks
- Replacing unreliable built‑in RMM AV checks (e.g., Defender excluded/misclassified)

---

## What It Checks
| Area | Description |
|---|---|
| **Installed AV** | Enumerates AV products via Windows Security Center (WSC) |
| **Active / Real‑Time AV** | Confirms which AV engine has real‑time protection enabled |
| **Defender Health** | Service state, real‑time protection, engine & platform versions |
| **Signature Currency** | Flags stale Defender signatures (configurable threshold) |
| **MDE (Sense)** | Detects Defender for Endpoint onboarding via Sense service |
| **AV Conflicts** | Detects multiple real‑time AV engines enabled simultaneously |

---

## Parameters
| Parameter | Purpose |
|---|---|
| `-RequireRealTime` | Fail if **no real‑time AV** is enabled |
| `-RequireMDE` | Warn/Fail if **MDE is not onboarded** |
| `-SigFreshHours` | Max allowed Defender signature age (default: 48h) |
| `-Full` | Detailed multi‑line output (ticket notes) |
| `-AsJson` | Structured JSON output for ingestion |
| `-DebugMode` | Extra diagnostics for troubleshooting templates/parsing |

---

## Examples
```powershell
# Default (summary line for dashboards/monitors)
.\AVCheck.ps1

# Enforce real-time AV + MDE onboarding
.\AVCheck.ps1 -RequireRealTime -RequireMDE

# Detailed output for ticket notes
.\AVCheck.ps1 -Full

# Structured output for ingestion/parsing
.\AVCheck.ps1 -AsJson
```

---

## Exit Codes
| Code | Meaning |
|---|---|
| `0` | OK / Secure |
| `1` | Warning (stale signatures/scans, soft posture issues) |
| `2` | Critical (no real‑time AV, AV conflicts, required control missing) |
| `4` | Script error |

---

# SecurityCheck.ps1

### Overview
Performs a full endpoint security posture audit. Detects AV status, MDE onboarding, firewall health, patch currency, and pending reboots — all in one pass.

### Key Functions
| Check | Description |
|---|---|
| **Antivirus** | Detects Defender/Bitdefender/3rd‑party; checks service + signatures |
| **MDE** | Verifies Defender for Endpoint onboarding (Sense service) |
| **Firewall** | Confirms Windows Firewall state |
| **Windows Update** | Reports date of last installed update |
| **Pending Reboot / Uptime** | Shows reboot requirement and uptime |

### Example
```powershell
.\SecurityCheck.ps1          # summary line for dashboards
.\SecurityCheck.ps1 -Full    # detailed ticket notes
.\SecurityCheck.ps1 -AsJson  # structured output for ingestion
```

---

# AutoWindowsUpdate.ps1 (**Basic**)

### What it does
A lightweight script that **checks for pending Windows Updates** and can **install them**, optionally rebooting when required. Designed for **RMM tasks** and quick scheduled patch windows.

## Key Features
| Feature | Description |
|----------|-------------|
| ✅ **Portable** | No module or NuGet dependencies. Works on any supported Windows system. |
| ✅ **Silent Operation** | Non-interactive; outputs to console only (no file logging). |
| ✅ **Two Modes** | `-CheckOnly` for scans, `-Install` for full update runs. |
| ✅ **Auto Reboot Option** | `-AutoReboot` triggers restart if updates require it. |
| ✅ **RMM-Friendly** | Uses clear, parseable console output and standard exit codes. |
| ❌ **No Windows 10 to 11 upgrade** | This will NOT upgrade a device from Windows 10 to 11. |

### Parameters
| Parameter | Purpose |
|---|---|
| `-CheckOnly` | List pending updates but **do not install** (safe test mode) |
| `-Install` | **Install** all available updates from Windows Update |
| `-Reboot` | If a reboot is required after install, **restart automatically** |

> The script will automatically install **PSWindowsUpdate** if it’s missing, and it writes clear progress to the console for RMM visibility.

### Examples
```powershell
# 1) Dry‑run: only report what’s pending
.\AutoWindowsUpdate.ps1 -CheckOnly

# 2) Install all available updates (no reboot)
.\AutoWindowsUpdate.ps1 -Install

# 3) Install and reboot automatically if required
.\AutoWindowsUpdate.ps1 -Install -Reboot
```

---

# Update-Chrome.ps1

### Overview
Updates Google Chrome using **Winget** (Windows Package Manager).  
Crucially, it handles the "Pending Reboot" scenario where Chrome has staged an update but the user hasn't relaunched the browser yet.

### Key Features
| Feature | Description |
|---|---|
| ✅ **Smart Detection** | Checks if Chrome is running and skips the update to avoid disrupting the user. |
| ✅ **Pending Reboot Aware** | Compares the version in memory vs. the registry. If a reboot is pending, it reports the *staged* version. |
| ✅ **Exit Codes** | Returns `0` (Success) even if skipped, keeping RMM dashboards green. |
| ✅ **Force Mode** | Configurable variable to force-kill Chrome if aggressive patching is required. |

### Logic Flow
1. **Process Check:** Is `chrome.exe` running?
   - **No:** Run `winget upgrade Google.Chrome`.
   - **Yes:** Check Registry for pending update flag.
2. **Pending Reboot Check:**
   - If Registry Version > Running Version → **Report "Pending Relaunch"** (Skip update).
3. **Winget Check:**
   - If no reboot pending, check Winget for new download.
   - If available version > running version → **Report "Update Available"** (Skip update to save session).

### Example Output (Log)
```text
 [!] PENDING REBOOT DETECTED
     Running Version:   120.0.6099.109
     Staged Version:    120.0.6099.130
     Action: Skipped. Chrome needs a relaunch to finish update to 120.0.6099.130.
```

---

# HDDUsageCheck.ps1

## Overview
**HDDUsageCheck.ps1** is a PowerShell script designed to audit system disk usage, including drive-level statistics, per-user profile space, and detection of large folders or files.  
It is ideal for use in managed environments (e.g., NOC/RMM) to identify space-heavy users or files such as OSTs.

---

## Key Features
| Feature | Description |
|----------|-------------|
| ✅ **Drive Analysis** | Reports total, used, and free space per fixed drive. |
| ✅ **Per-User Scan** | Calculates space usage for each user profile under `C:\Users`. |
| ✅ **Large Folder Detection** | Lists subfolders ≥ 5 GB within each profile (recursive). |
| ✅ **Large File Detection** | Lists files ≥ 5 GB (including OST files) with full path and modification time. |
| ✅ **RMM Safe** | Outputs to console only, no file writes or prompts. |

---

## Parameters
- **$LowSpaceThreshold** — Minimum free space percentage to trigger a warning (default: 10%).  
- **$LargeThresholdGB** — File or folder size in GB to report as large (default: 5).  
- **$UserRoot** — Root path for user profiles (default: `C:\Users`).

---

## Example Output
```
=== Hard Drive Usage Report ===
Drive C:: Total=475.68 GB | Used=420.12 GB | Free=55.56 GB (11.7% free)

=== User Profile Space Usage (C:\Users) ===
User        Path                 SizeGB
----        ----                 ------
stuar       C:\Users\stuar       45.12
WsiAccount C:\Users\WsiAccount 0
cordw       C:\Users\cordw       0

--- stuar (C:\Users\stuar) ---
Large items (≥ 5 GB):
Folder Downloads 7.82 GB C:\Users\stuar\Downloads
File Outlook.ost 12.34 GB C:\Users\stuar\AppData\Local\Microsoft\Outlook\Outlook.ost
```

---

## Summary: What It Reports
| Category | Included | Notes |
|-----------|-----------|-------|
| **Drive capacity** | ✅ | All fixed drives, with free space alerts. |
| **User profile size** | ✅ | Recursive per-user folder measurement. |
| **Folders ≥ 5 GB** | ✅ | Scans top-level folders in each profile. |
| **Files ≥ 5 GB** | ✅ | All large files, including OSTs. |
| **Exit codes** | ❌ | Console output only (optional future feature). |

## Versioning and Maintenance
```bash
git add .
git commit -m "Update README; add Chrome Update documentation"
git push
```

## Author
Developed and maintained by **Stu Villanti** for NOC/MSP automation and patch lifecycle management.



# AutoDiskCleanup (CleanMgr) – RMM-Safe, Silent Disk Cleanup

## Overview
**AutoDiskCleanup** is a production-ready PowerShell automation designed for MSP/RMM environments.  
It runs Windows Disk Cleanup (`cleanmgr.exe`) **silently**, without user-facing UI, and provides clear
**before/after disk space reporting** directly to RMM output.

Key goals:
- No end-user disruption
- Safe to run via RMM / Automation Manager
- Clear audit output (what ran, when, and what changed)
- No log files written to the endpoint

---

## Key Features
- 🔇 Fully hidden execution (runs as SYSTEM via a temporary Scheduled Task)
- 🧪 Test / Dry-run mode (no changes made)
- 📊 Disk space BEFORE / AFTER / Delta
- 🧹 Configurable cleanup categories
- 🧠 Automatic cleanup of stale scheduled tasks
- 🧵 RunId correlation for multi-run debugging
- 🚫 No on-disk logs (stdout only – ideal for RMM capture)
- 🛡 64-bit safe (avoids WOW6432Node registry redirection)

---

## How It Works
1. Capture disk free space (BEFORE)
2. Configure CleanMgr registry StateFlags
3. Execute `cleanmgr.exe /SAGERUN:<ProfileId>` via hidden SYSTEM task
4. Wait with heartbeat output
5. Remove temporary scheduled task
6. Capture disk free space (AFTER) and report delta

---

## Requirements
- Windows 10 / 11
- Windows Server 2016+
- PowerShell 5.1+

> `cleanmgr.exe` must exist on the OS.

---

## Usage

### Live Run
```powershell
.\DiskCleanup.ps1
```

### Test / Dry-Run
```powershell
.\DiskCleanup.ps1 -Mode test
```

Valid test values: `test`, `check`, `dryrun`

---

## Example Output
```text
Disk free space BEFORE:
  C:: 250.08GB free of 443.53GB (56.4% free)
[TEST] Would ENABLE category: Temporary Files
[TEST] Would execute (hidden via task): cleanmgr.exe /SAGERUN:191
Disk free space AFTER:
  C:: 250.08GB free of 443.53GB (56.4% free)
Disk free space delta:
  C:: +0.00B
```

---

## Cleanup Categories
Configured in the `$Categories` array:

- Temporary Files
- Temporary Setup Files
- Recycle Bin
- Windows Error Reporting Files
- System error memory dump files
- System error minidump files
- Update Cleanup
- Device Driver Packages
- Old ChkDsk Files
- Setup Log Files
- Thumbnail Cache

Missing categories on a given OS are safely skipped.

---

## Safety Notes
- Runs as SYSTEM
- No user profile data touched
- Safe to re-run
- Mutex prevents concurrent execution

---

## Troubleshooting

Check if cleanup is running:
```powershell
Get-Process cleanmgr
Get-ScheduledTask | Where-Object TaskName -like "DiskCleanup-RMM-*"
```

Stop cleanup safely:
```powershell
Stop-Process -Name cleanmgr -Force
```

---

## Scheduling Recommendations
- Weekly: lightweight categories
- Monthly: include Update Cleanup

---

## License
Internal / MSP use. Modify as required.

---

## 🔄 Update-Only Scripts (Paired with Check Scripts)

The repository now includes **update-only scripts** designed to be paired with the existing
check/audit scripts. This keeps monitoring and remediation **explicitly separated**, which
works far better with N-able templates and avoids accidental changes during audits.

### Design Principles
- **Checks** = detect & report only  
- **Updates** = perform updates only  
- **Shared output schema** = same key names between check and update scripts  
- **No forced app closures by default** (user-safe during business hours)

---

### Google Chrome
- **Check:** `chromeCheckUpdate.ps1`
- **Update:** `UpdateChrome.ps1`

Behaviour:
- Uses **Chrome Enterprise MSI**
- Does **not** force-close Chrome
- Update may stage; new version becomes active after Chrome restart

Key output fields (unchanged between check/update):
```
Chrome_Installed
Chrome_Version
Chrome_Source
```

---

### Mozilla Firefox
- **Check:** `firefoxCheckUpdate.ps1`
- **Update:** `UpdateFirefox.ps1`

Behaviour:
- Uses official Mozilla latest installer (win64)
- Does **not** force-close Firefox
- Update may stage or apply after restart depending on locks / maintenance service

Key output fields:
```
Firefox_Installed
Firefox_Version
Firefox_Source
```

---

### Microsoft Office (Click-to-Run)
- **Check:** `officeCheckUpdate.ps1`
- **Update:** `UpdateOfficeC2R.ps1`

Behaviour:
- Triggers update via `OfficeC2RClient.exe`
- **Never force-closes Office apps by default**
- Updates typically **stage** and apply when apps close or on reboot

Key output fields:
```
Office_ClickToRun_Installed
Office_VersionToReport
Office_UpdateChannel
Office_CDNBaseUrl
Office_Platform
```

> ℹ️ Update scripts may emit additional informational fields
> (e.g. `*_Version_Before`, `*_UpdateResult`) which are safe to ignore in N-able parsing.

---

## Recommended Workflow (N-able)
1. Run **check scripts** on schedule (hourly/daily)
2. Alert only on **non-compliant states**
3. Trigger **update scripts** as a remediation action
4. Re-check on next monitor run

This keeps dashboards clean and avoids false positives during active user sessions.
