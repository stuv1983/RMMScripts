@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: ============================================================================
:: RemoveRMM.bat - N-able/N-central (Advanced Monitoring Agent) cleanup helper
::
:: Purpose
::   - Stop common N-able / Take Control services & processes
::   - Rename settings.ini to settings.old.ini (forces agent re-provision / breaks link)
::
:: What this script DOES
::   1) Self-elevates to Administrator (UAC prompt)
::   2) Stops related services (best-effort; tries multiple likely service names)
::   3) Kills leftover agent processes (best-effort)
::   4) Takes ownership + grants Administrators full control on settings.ini
::   5) Renames settings.ini -> settings.old.ini
::
:: What this script does NOT do
::   - Fully uninstall the agent
::   - Remove all files, scheduled tasks, registry entries, etc.
::
:: RMM/Helpdesk Notes
::   - Service names differ between versions/agents; this script is intentionally
::     "best effort" and will not fail hard if a service/process doesn't exist.
::   - Renaming settings.ini may fail if locked by a running agent process.
::     That's why we stop services and kill processes first.
:: ============================================================================

:: ---------------------------------------------------------------------------
:: 0) Admin check + self-elevate
:: ---------------------------------------------------------------------------
:: net session requires admin; if it fails, re-launch elevated.
>nul 2>&1 net session
if not "%errorlevel%"=="0" (
    echo Requesting administrator access...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: ---------------------------------------------------------------------------
:: 1) Variables (paths)
:: ---------------------------------------------------------------------------
set "AGENTDIR=C:\Program Files (x86)\Advanced Monitoring Agent"
set "OLDFILE=%AGENTDIR%\settings.ini"
set "NEWFILE=%AGENTDIR%\settings.old.ini"

echo.
echo ============================================================
echo N-able RMM settings reset (rename settings.ini)
echo AgentDir : "%AGENTDIR%"
echo Target   : "%OLDFILE%"
echo ============================================================
echo.

:: ---------------------------------------------------------------------------
:: 2) Stop related services (best effort)
:: ---------------------------------------------------------------------------
:: NOTE: sc stop expects the *service name* (not always the friendly display name).
:: Different agents/versions use different names, so we try several common ones.
echo Stopping related services (best effort)...

call :StopSvc "Advanced Monitoring Agent"
call :StopSvc "Advanced Monitoring Agent Network"
call :StopSvc "N-able Windows Agent"
call :StopSvc "Take Control Agent"
call :StopSvc "Take Control Agent (x86)"

:: Common service-name variants (these often differ from display names)
call :StopSvc "AdvancedMonitoringAgent"
call :StopSvc "AdvancedMonitoringAgentNetwork"
call :StopSvc "WindowsAgent"
call :StopSvc "TakeControlAgent"
call :StopSvc "TakeControlAgentx86"

echo.

:: ---------------------------------------------------------------------------
:: 3) Kill leftover processes (best effort)
:: ---------------------------------------------------------------------------
:: We do this after stopping services to clear locks on settings.ini
echo Terminating leftover processes (best effort)...
taskkill /F /IM "AdvancedMonitoringAgent.exe" >nul 2>&1
taskkill /F /IM "WindowsAgent.exe"            >nul 2>&1
taskkill /F /IM "TakeControlAgent.exe"        >nul 2>&1

:: Optional: some versions spawn helper processes; ignore if missing
taskkill /F /IM "BASupSrvc.exe"               >nul 2>&1
taskkill /F /IM "BASupSrvcCnfg.exe"           >nul 2>&1

echo.

:: ---------------------------------------------------------------------------
:: 4) Rename settings.ini -> settings.old.ini
:: ---------------------------------------------------------------------------
if not exist "%OLDFILE%" (
    echo [!] settings.ini not found at:
    echo     "%OLDFILE%"
    echo     Nothing to rename.
    goto :End
)

:: Take ownership + permissions to avoid ACL blocks
echo Taking ownership / setting permissions on settings.ini...
takeown /F "%OLDFILE%" >nul 2>&1
icacls "%OLDFILE%" /grant administrators:F >nul 2>&1

:: Rename (move) the file
echo Renaming settings.ini to settings.old.ini...
ren "%OLDFILE%" "settings.old.ini" >nul 2>&1

:: Verify result
if exist "%NEWFILE%" (
    echo [✓] Success: settings.ini renamed to settings.old.ini
) else (
    echo [!] Rename failed.
    echo     Common causes:
    echo       - File is still locked (agent/process still running)
    echo       - Antivirus/EDR protection
    echo       - Permissions still blocked
)

:: ---------------------------------------------------------------------------
:: End
:: ---------------------------------------------------------------------------
:End
echo.
pause
exit /b 0

:: ============================================================================
:: Functions
:: ============================================================================

:StopSvc
:: Stops a service by name (best effort). Doesn't error if missing.
:: Usage: call :StopSvc "ServiceName"
set "SVC=%~1"

:: Query first to avoid noisy "does not exist" output
sc query "%SVC%" >nul 2>&1
if "%errorlevel%"=="0" (
    sc stop "%SVC%" >nul 2>&1
)
exit /b 0
