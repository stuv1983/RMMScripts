# Simple Browser Audit Script
# Scans system-wide and per-user locations for Edge, Firefox, and Chrome installs.
# Reports detected installation path, version, and 32-bit / 64-bit architecture.

function Get-PEArchitecture {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }

    try {
        $fs = [System.IO.File]::OpenRead($Path)
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $br.ReadInt32()
        $fs.Seek($peOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        $machine = $br.ReadUInt16()
        $br.Close()
        $fs.Close()

        switch ($machine) {
            0x014c { return '32-bit' }
            0x8664 { return '64-bit' }
            0x0200 { return 'IA64' }
            default { return 'Unknown' }
        }
    } catch {
        return 'Unknown'
    }
}

function Get-BrowserInstallInfo {
    param(
        [string]$Browser,
        [string[]]$Paths,
        [string]$Scope = 'System'
    )

    $results = @()
    foreach ($path in $Paths) {
        if (Test-Path $path) {
            $item = Get-Item $path -ErrorAction SilentlyContinue
            $version = if ($item) { $item.VersionInfo.ProductVersion } else { $null }
            $arch = Get-PEArchitecture -Path $path
            $installScope = if ($path -match '\\Users\\[^\\]+\\') { 'Per-User' } else { $Scope }

            $results += [PSCustomObject]@{
                Browser       = $Browser
                Path          = $path
                Version       = if ($version) { $version } else { 'Unknown' }
                Architecture  = if ($arch -match '32-bit|64-bit|IA64') { $arch } else {
                                   if ($path -match '\\Program Files \(x86\)\\') { '32-bit' }
                                   elseif ($path -match '\\Program Files\\') { '64-bit' }
                                   else { 'Unknown' }
                               }
                InstallScope  = $installScope
            }
        }
    }
    return $results
}

function Get-UserProfilePaths {
    $userRoot = Join-Path $env:SystemDrive 'Users'
    if (-not (Test-Path $userRoot)) { return @() }

    $exclude = 'Default','Default User','All Users','Public','desktop.ini'
    Get-ChildItem -Path $userRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
        $exclude -notcontains $_.Name
    }
}

function Get-BrowserAuditReport {
    $programFiles64 = $env:ProgramW6432
    if (-not $programFiles64) {
        $programFiles64 = $env:ProgramFiles
    }

    $programFilesX86 = ${env:ProgramFiles(x86)}
    if (-not $programFilesX86) {
        if ($programFiles64 -and $programFiles64 -match '\\Program Files$') {
            $programFilesX86 = $programFiles64 -replace '\\Program Files$', '\\Program Files (x86)'
        } else {
            $programFilesX86 = $programFiles64
        }
    }

    $userProfiles = Get-UserProfilePaths
    $userPaths = @()
    foreach ($profile in $userProfiles) {
        $root = $profile.FullName
        $userPaths += [PSCustomObject]@{ Profile = $profile.Name; AppDataLocal = Join-Path $root 'AppData\Local' }
    }

    $browserCandidates = @(
        [PSCustomObject]@{
            Browser = 'Google Chrome'
            Paths = @(
                Join-Path $programFiles64 'Google\Chrome\Application\chrome.exe')
        },
        [PSCustomObject]@{
            Browser = 'Mozilla Firefox'
            Paths = @(
                Join-Path $programFiles64 'Mozilla Firefox\firefox.exe')
        },
        [PSCustomObject]@{
            Browser = 'Microsoft Edge'
            Paths = @(
                Join-Path $programFiles64 'Microsoft\Edge\Application\msedge.exe')
        }
    )

    if ($programFilesX86 -and $programFilesX86 -ne $programFiles64) {
        $browserCandidates[0].Paths += Join-Path $programFilesX86 'Google\Chrome\Application\chrome.exe'
        $browserCandidates[1].Paths += Join-Path $programFilesX86 'Mozilla Firefox\firefox.exe'
        $browserCandidates[2].Paths += Join-Path $programFilesX86 'Microsoft\Edge\Application\msedge.exe'
    }

    $results = @()

    foreach ($browser in $browserCandidates) {
        $browserPaths = @($browser.Paths)

        foreach ($user in $userPaths) {
            switch ($browser.Browser) {
                'Google Chrome' {
                    $browserPaths += Join-Path $user.AppDataLocal 'Google\Chrome\Application\chrome.exe'
                }
                'Mozilla Firefox' {
                    $browserPaths += Join-Path $user.AppDataLocal 'Mozilla Firefox\firefox.exe'
                }
                'Microsoft Edge' {
                    $browserPaths += Join-Path $user.AppDataLocal 'Microsoft\Edge\Application\msedge.exe'
                }
            }
        }

        $results += Get-BrowserInstallInfo -Browser $browser.Browser -Paths $browserPaths
    }

    if (-not $results) {
        Write-Output 'No supported browser installs were found.'
        return
    }

    $results | Sort-Object Browser, InstallScope, Path
}

function Get-FirefoxLastUsed {
    $userProfiles = Get-UserProfilePaths
    $results = @()

    foreach ($profile in $userProfiles) {
        $userName = $profile.Name
        $profilePath = Join-Path $profile.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"

        if (Test-Path $profilePath) {
            $profileDirs = Get-ChildItem $profilePath -Directory -ErrorAction SilentlyContinue

            foreach ($profileDir in $profileDirs) {
                $placesPath = Join-Path $profileDir.FullName "places.sqlite"

                if (Test-Path $placesPath) {
                    $lastUsed = (Get-Item $placesPath -ErrorAction SilentlyContinue).LastWriteTime
                    $results += [PSCustomObject]@{
                        User     = $userName
                        Profile  = $profileDir.Name
                        LastUsed = $lastUsed
                    }
                }
            }
        }
    }

    return $results
}

# Run audit and display in table format
Get-BrowserAuditReport | Format-Table -AutoSize

Write-Output "`nFirefox Usage Report:"
Get-FirefoxLastUsed | Sort-Object LastUsed -Descending | Format-Table -AutoSize
