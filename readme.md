# NoC Script Collection

> ⚠️ **Disclaimer**  
> Run at your own risk. Test thoroughly in a lab first. The author is not responsible for any damage, data loss, or unexpected outcomes.

## Main Overview
A collection of **PowerShell scripts** for **NOC / MSP** environments to automate endpoint health checks, patching, and upgrade readiness.  
All scripts are **RMM‑friendly** (clear console output + exit codes) and safe for scheduled automation when properly tested.

---

## 📦 Scripts in this Repo
- **SecurityCheck.ps1** – Endpoint security posture in one pass (AV/Firewall/Updates/Reboot).  
- **AutoWindowsUpdate.ps1** – *Basic* Windows Update checker/installer (this section expanded below).  
- **HDDUsageCheck.ps1** – Ligh weight script to check what is using data on C: 

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
---


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

### Sample Output
```
=== Starting Windows Update Script ===
PSWindowsUpdate module not found — attempting to install...
✅ PSWindowsUpdate module installed successfully.

=== Checking for available updates... ===
Title                                                     KBArticleIDs   Size
-----                                                     ------------   ----
2025-11 Cumulative Update for Windows 11 Version 24H2     KB5067036      645 MB
Microsoft .NET Framework 4.8.1 Security Update            KB5031183      125 MB

⚙️  Updates are available.

=== Installing available updates... ===
... (download/install progress) ...
✅ Update installation completed.

=== Checking if reboot is required... ===
🔁 Reboot required. Restarting system now...
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
User       Path                SizeGB
----       ----                ------
stuar      C:\Users\stuar     45.12
WsiAccount C:\Users\WsiAccount 0
cordw      C:\Users\cordw      0

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
git commit -m "Update README; document basic AutoWindowsUpdate.ps1 usage and output"
git push
```

## Author
Developed and maintained by **Stu Villanti** for NOC/MSP automation and patch lifecycle management.
