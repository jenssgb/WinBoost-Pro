<#
.SYNOPSIS
    WinBoost Pro v1.0 - Windows Performance & Cleanup Toolkit
.DESCRIPTION
    Consolidated system management script for Windows:
    - Close foreground/background/systray applications
    - Resource analysis and performance issue detection
    - Disk cleanup (temp files, caches, recycle bin)
    - Uninstall programs (registry scan, sorted by size)
    - System performance optimization (safe/moderate/advanced tiers)
    - Interactive menu-driven interface
.AUTHOR
    WinBoost Pro v1.0
.DATE
    2026-02-14
#>

#Requires -Version 5.1

# ============================================
# CONFIGURATION
# ============================================
$Script:Config = @{
    ProtectedProcesses = @(
        'explorer', 'dwm', 'csrss', 'wininit', 'winlogon', 'services',
        'lsass', 'svchost', 'System', 'smss', 'RuntimeBroker',
        'SecurityHealthService', 'MsMpEng', 'powershell', 'pwsh',
        'conhost', 'sihost', 'fontdrvhost', 'WUDFHost', 'SearchHost',
        'StartMenuExperienceHost', 'ShellExperienceHost', 'TextInputHost',
        'taskhostw', 'dllhost', 'ctfmon', 'ApplicationFrameHost',
        'Widgets', 'WidgetService', 'SystemSettings', 'LockApp'
    )
    TeamsProcesses = @('Teams', 'ms-teams', 'msteams')
    CommonApps = @{
        'Browser' = @('chrome', 'firefox', 'msedge', 'opera', 'brave', 'vivaldi')
        'Office' = @('WINWORD', 'EXCEL', 'POWERPNT', 'OUTLOOK', 'ONENOTE', 'Teams')
        'Development' = @('Code', 'devenv', 'idea64', 'pycharm64', 'studio64', 'rider64')
        'Communication' = @('Discord', 'Slack', 'Zoom', 'Telegram', 'WhatsApp', 'Signal')
        'Media' = @('Spotify', 'vlc', 'iTunes', 'Netflix', 'Audacity')
        'Tools' = @('notepad++', '7zFM', 'WinRAR', 'Everything', 'Greenshot')
    }
    OptimizationServices = @('SysMain', 'DiagTrack', 'dmwappushservice')
    BloatwareApps = @(
        'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.GamingApp',
        'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.BingNews',
        'Microsoft.BingWeather',
        'Microsoft.BingFinance',
        'Microsoft.BingSports',
        'Microsoft.GetHelp',
        'Microsoft.Getstarted',
        'Microsoft.MixedReality.Portal',
        'Microsoft.People',
        'Microsoft.ZuneMusic'
    )
}

# ============================================
# HELPER FUNCTIONS
# ============================================

function Write-ColorText {
    param(
        [string]$Text,
        [ConsoleColor]$Color = 'White',
        [switch]$NoNewLine
    )
    if ($NoNewLine) {
        Write-Host $Text -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Write-Banner {
    Clear-Host
    $banner = @"
+=====================================================================+
|                                                                     |
|   W   W IIIII N   N BBBB   OOO   OOO   SSSS TTTTT                  |
|   W   W   I   NN  N B   B O   O O   O S       T                    |
|   W W W   I   N N N BBBB  O   O O   O  SSS    T                    |
|   WW WW   I   N  NN B   B O   O O   O     S   T                    |
|   W   W IIIII N   N BBBB   OOO   OOO  SSSS    T                    |
|                                                                     |
|          ### PRO v1.0 - PERFORMANCE & CLEANUP TOOLKIT ###           |
|                                                                     |
|   Close | Processes | Cleanup | Uninstall | Optimize              |
+=====================================================================+
"@
    Write-ColorText $banner -Color Cyan
    Write-Host ""
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-ColorText "================================================================" -Color DarkCyan
    Write-ColorText "  $Title" -Color Yellow
    Write-ColorText "================================================================" -Color DarkCyan
    Write-Host ""
}

function Get-UserConfirmation {
    param([string]$Message)
    Write-ColorText "$Message (Y/N): " -Color Yellow -NoNewLine
    $response = Read-Host
    return $response -match '^[YyJj]'
}

function Test-IsProtectedProcess {
    param([string]$ProcessName)
    return $Script:Config.ProtectedProcesses -contains $ProcessName
}

function Test-IsTeamsProcess {
    param([string]$ProcessName)
    foreach ($teams in $Script:Config.TeamsProcesses) {
        if ($ProcessName -like "*$teams*") { return $true }
    }
    return $false
}

function Get-ColorForValue {
    param(
        [double]$Value,
        [double]$HighThreshold,
        [double]$MediumThreshold
    )
    if ($Value -gt $HighThreshold) { return 'Red' }
    elseif ($Value -gt $MediumThreshold) { return 'Yellow' }
    else { return 'Green' }
}

function Format-FileSize {
    param([long]$Size)
    if ($Size -gt 1GB) { return "{0:N2} GB" -f ($Size / 1GB) }
    elseif ($Size -gt 1MB) { return "{0:N2} MB" -f ($Size / 1MB) }
    elseif ($Size -gt 1KB) { return "{0:N2} KB" -f ($Size / 1KB) }
    else { return "$Size Bytes" }
}

function Get-FolderSize {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        $size = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                 Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        return [long]$size
    } catch { return 0 }
}

function Test-AdminRights {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================
# PROCESS FUNCTIONS
# ============================================

function Get-ForegroundProcesses {
    $processes = Get-Process | Where-Object {
        $_.MainWindowHandle -ne 0 -and
        $_.MainWindowTitle -ne '' -and
        -not (Test-IsProtectedProcess $_.ProcessName)
    } | Select-Object Id, ProcessName, MainWindowTitle,
        @{N='CPU_Seconds';E={[math]::Round($_.CPU, 2)}},
        @{N='Memory_MB';E={[math]::Round($_.WorkingSet64 / 1MB, 2)}},
        @{N='StartTime';E={$_.StartTime}}
    return $processes
}

function Get-SystrayProcesses {
    $knownTrayApps = @(
        'Discord', 'Spotify', 'Steam', 'EpicGamesLauncher', 'Origin',
        'OneDrive', 'Dropbox', 'GoogleDrive', 'iCloudDrive',
        'Slack', 'Telegram', 'WhatsApp', 'Signal',
        'NordVPN', 'ExpressVPN', 'Windscribe',
        'Razer*', 'LogiOptions*', 'Corsair*', 'NZXT*',
        'ShareX', 'Greenshot', 'LightShot',
        '1Password', 'Bitwarden', 'KeePass', 'LastPass',
        'f.lux', 'Flux', 'NightOwl',
        'MSI*', 'ASUS*', 'Armoury*',
        'Nvidia*', 'AMD*', 'Radeon*',
        'Synology*', 'QNAP*',
        'Zoom', 'Webex', 'GoToMeeting',
        'Snagit*', 'Camtasia*',
        'Logitech*', 'Corsair*', 'SteelSeries*',
        'Nahimic*', 'Realtek*',
        'Creative*', 'Voicemeeter*',
        'PowerToys*', 'EarTrumpet',
        'hwinfo*', 'HWMonitor', 'CoreTemp', 'CPUID*',
        'DisplayFusion', 'Wallpaper*',
        'GHub', 'LGHub'
    )

    $trayProcesses = @()

    foreach ($pattern in $knownTrayApps) {
        $procs = Get-Process -Name $pattern -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            if (-not (Test-IsProtectedProcess $proc.ProcessName)) {
                $trayProcesses += [PSCustomObject]@{
                    Id = $proc.Id
                    ProcessName = $proc.ProcessName
                    Memory_MB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                    CPU_Seconds = [math]::Round($proc.CPU, 2)
                    Description = $proc.Description
                    Path = $proc.Path
                }
            }
        }
    }

    # Hidden processes using significant RAM
    $hiddenProcesses = Get-Process | Where-Object {
        $_.MainWindowHandle -eq 0 -and
        $_.WorkingSet64 -gt 50MB -and
        -not (Test-IsProtectedProcess $_.ProcessName) -and
        $_.ProcessName -notmatch '^(svchost|RuntimeBroker|backgroundTaskHost|SearchIndexer|WmiPrvSE)$'
    } | ForEach-Object {
        [PSCustomObject]@{
            Id = $_.Id
            ProcessName = $_.ProcessName
            Memory_MB = [math]::Round($_.WorkingSet64 / 1MB, 2)
            CPU_Seconds = [math]::Round($_.CPU, 2)
            Description = $_.Description
            Path = $_.Path
        }
    }

    $allTray = $trayProcesses + $hiddenProcesses |
               Sort-Object Id -Unique |
               Sort-Object Memory_MB -Descending

    return $allTray
}

function Get-BackgroundProcesses {
    $processes = Get-Process | Where-Object {
        ($_.MainWindowHandle -eq 0 -or $_.MainWindowTitle -eq '') -and
        -not (Test-IsProtectedProcess $_.ProcessName) -and
        $_.ProcessName -notmatch '^(svchost|RuntimeBroker|backgroundTaskHost)$'
    } | Select-Object Id, ProcessName,
        @{N='CPU_Seconds';E={[math]::Round($_.CPU, 2)}},
        @{N='Memory_MB';E={[math]::Round($_.WorkingSet64 / 1MB, 2)}}
    return $processes
}

function Close-ForegroundApps {
    param(
        [switch]$KeepTeams,
        [switch]$Force,
        [string[]]$ExcludeProcesses = @()
    )

    Write-SectionHeader "CLOSE FOREGROUND APPS"

    $processes = Get-ForegroundProcesses

    if ($KeepTeams) {
        $processes = $processes | Where-Object { -not (Test-IsTeamsProcess $_.ProcessName) }
        Write-ColorText "[+] Teams will NOT be closed" -Color Green
    }

    if ($ExcludeProcesses.Count -gt 0) {
        $processes = $processes | Where-Object { $_.ProcessName -notin $ExcludeProcesses }
        Write-ColorText "[+] Excluded: $($ExcludeProcesses -join ', ')" -Color Green
    }

    if (-not $processes -or $processes.Count -eq 0) {
        Write-ColorText "[OK] No foreground apps to close." -Color Green
        return
    }

    Write-ColorText "The following apps will be closed:" -Color Yellow
    $processes | Format-Table ProcessName, MainWindowTitle, Memory_MB -AutoSize

    if (-not $Force) {
        if (-not (Get-UserConfirmation "Do you want to continue?")) {
            Write-ColorText "[X] Cancelled." -Color Red
            return
        }
    }

    $closed = 0
    $failed = 0

    foreach ($proc in $processes) {
        try {
            $process = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
            if ($process) {
                $process.CloseMainWindow() | Out-Null
                Start-Sleep -Milliseconds 500

                if (-not $process.HasExited) {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                }

                Write-ColorText "  [OK] $($proc.ProcessName) closed" -Color Green
                $closed++
            }
        } catch {
            Write-ColorText "  [X] $($proc.ProcessName) could not be closed" -Color Red
            $failed++
        }
    }

    Write-Host ""
    Write-ColorText "Result: $closed closed, $failed failed" -Color Cyan
}

function Close-AllApps {
    param(
        [switch]$IncludeTeams,
        [switch]$IncludeBackground,
        [switch]$IncludeSystray
    )

    Write-SectionHeader "TURBO MODE: Close All Apps"

    Write-ColorText "Mode: " -Color White -NoNewLine
    if ($IncludeTeams) {
        Write-ColorText "Close EVERYTHING (including Teams)" -Color Red
    } else {
        Write-ColorText "Close everything EXCEPT Teams" -Color Yellow
    }

    if ($IncludeBackground) {
        Write-ColorText "   + Background processes will also be terminated" -Color Magenta
    }
    if ($IncludeSystray) {
        Write-ColorText "   + Systray apps will also be terminated" -Color Magenta
    }

    if (-not (Get-UserConfirmation "`nWARNING: This will close all applications! Continue?")) {
        Write-ColorText "[X] Cancelled." -Color Red
        return
    }

    if ($IncludeTeams) {
        Close-ForegroundApps -Force
    } else {
        Close-ForegroundApps -KeepTeams -Force
    }

    if ($IncludeSystray) {
        Write-Host ""
        Write-ColorText "Terminating systray apps..." -Color Magenta
        $trayProcs = Get-SystrayProcesses

        foreach ($proc in $trayProcs) {
            if ($IncludeTeams -or -not (Test-IsTeamsProcess $proc.ProcessName)) {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-ColorText "  [OK] $($proc.ProcessName) terminated" -Color Green
                } catch {
                    # Ignore
                }
            }
        }
    }

    if ($IncludeBackground) {
        Write-Host ""
        Write-ColorText "Terminating background processes..." -Color Magenta
        $bgProcesses = Get-BackgroundProcesses | Where-Object { $_.Memory_MB -gt 50 }

        foreach ($proc in $bgProcesses) {
            if ($IncludeTeams -or -not (Test-IsTeamsProcess $proc.ProcessName)) {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-ColorText "  [OK] $($proc.ProcessName) terminated" -Color Green
                } catch {
                    # Ignore
                }
            }
        }
    }

    Write-ColorText "`n[OK] Turbo mode completed!" -Color Green
}

function Close-ProcessesByCategory {
    Write-SectionHeader "CLOSE BY CATEGORY"

    Write-ColorText "Available categories:" -Color Yellow
    $i = 1
    $categories = @{}
    foreach ($cat in $Script:Config.CommonApps.Keys) {
        $categories[$i] = $cat
        $apps = $Script:Config.CommonApps[$cat] -join ', '
        Write-ColorText "  [$i] $cat" -Color Cyan -NoNewLine
        Write-ColorText " ($apps)" -Color Gray
        $i++
    }

    Write-Host ""
    Write-ColorText "Select category(s) (e.g. 1,2) or 'q' to cancel: " -Color Yellow -NoNewLine
    $userInput = Read-Host

    if ($userInput -eq 'q') { return }

    $numbers = $userInput -split ',' | ForEach-Object { $_.Trim() }
    $processesToKill = @()

    foreach ($num in $numbers) {
        $numInt = 0
        if ([int]::TryParse($num, [ref]$numInt) -and $categories.ContainsKey($numInt)) {
            $catName = $categories[$numInt]
            $processesToKill += $Script:Config.CommonApps[$catName]
        }
    }

    if ($processesToKill.Count -eq 0) { return }

    # Find running processes matching selected categories
    $found = @()
    foreach ($procName in $processesToKill) {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($procs) { $found += $procs }
    }

    if ($found.Count -eq 0) {
        Write-ColorText "[OK] No running processes found in selected categories." -Color Green
        return
    }

    Write-ColorText "Found $($found.Count) process(es) to close:" -Color Yellow
    $found | ForEach-Object {
        Write-ColorText "  - $($_.ProcessName) (PID $($_.Id))" -Color White
    }
    Write-Host ""

    if (-not (Get-UserConfirmation "Close these processes?")) {
        Write-ColorText "[X] Cancelled." -Color Red
        return
    }

    $closed = 0
    foreach ($proc in $found) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-ColorText "  [OK] $($proc.ProcessName) terminated" -Color Green
            $closed++
        } catch {
            Write-ColorText "  [X] $($proc.ProcessName) could not be terminated" -Color Red
        }
    }

    Write-Host ""
    Write-ColorText "Result: $closed process(es) closed." -Color Cyan
}

function Show-SystrayManager {
    Write-SectionHeader "SYSTRAY / BACKGROUND APPS MANAGER"

    $trayProcs = @(Get-SystrayProcesses)

    if ($trayProcs.Count -eq 0) {
        Write-ColorText "[OK] No systray processes found." -Color Green
        return
    }

    Write-ColorText "Found systray/background applications:" -Color Yellow
    Write-Host ""

    $i = 1
    $procList = @{}
    foreach ($proc in $trayProcs) {
        $procList[$i] = $proc
        $memColor = Get-ColorForValue -Value $proc.Memory_MB -HighThreshold 300 -MediumThreshold 100

        $procName = $proc.ProcessName
        if ($procName.Length -gt 22) { $procName = $procName.Substring(0, 19) + "..." }

        $desc = if ($proc.Description) { $proc.Description } else { "-" }
        if ($desc.Length -gt 30) { $desc = $desc.Substring(0, 27) + "..." }

        Write-ColorText "  [$($i.ToString().PadLeft(2))] " -Color Cyan -NoNewLine
        Write-ColorText "$($procName.PadRight(22))" -Color White -NoNewLine
        Write-ColorText "$($proc.Memory_MB.ToString().PadLeft(8)) MB  " -Color $memColor -NoNewLine
        Write-ColorText "$desc" -Color Gray

        $i++
        if ($i -gt 40) {
            Write-ColorText "      ... and $($trayProcs.Count - 40) more" -Color DarkGray
            break
        }
    }

    Write-Host ""
    Write-ColorText "[A] " -Color Magenta -NoNewLine
    Write-ColorText "Kill ALL systray apps" -Color White
    Write-ColorText "[S] " -Color Magenta -NoNewLine
    Write-ColorText "Select to kill (e.g. 1,3,5)" -Color White
    Write-ColorText "[Q] " -Color Magenta -NoNewLine
    Write-ColorText "Back" -Color White

    Write-Host ""
    Write-ColorText "Choice: " -Color Yellow -NoNewLine
    $userInput = Read-Host

    if ($userInput -match '^[Qq]$') { return }

    if ($userInput -match '^[Aa]$') {
        if (Get-UserConfirmation "Really kill ALL systray apps?") {
            foreach ($proc in $trayProcs) {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-ColorText "  [OK] $($proc.ProcessName) terminated" -Color Green
                } catch {
                    Write-ColorText "  [X] $($proc.ProcessName) error" -Color Red
                }
            }
        }
        return
    }

    if ($userInput -match '^[Ss]$') {
        Write-ColorText "Enter numbers (e.g. 1,3,5): " -Color Yellow -NoNewLine
        $userInput = Read-Host
    }

    $numbers = $userInput -split ',' | ForEach-Object { $_.Trim() }
    foreach ($num in $numbers) {
        $numInt = 0
        if ([int]::TryParse($num, [ref]$numInt) -and $procList.ContainsKey($numInt)) {
            $proc = $procList[$numInt]
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-ColorText "  [OK] $($proc.ProcessName) terminated" -Color Green
            } catch {
                Write-ColorText "  [X] $($proc.ProcessName) error" -Color Red
            }
        }
    }
}

function Get-ResourceHungryProcesses {
    param([int]$TopCount = 15)

    Write-SectionHeader "RESOURCE ANALYSIS"

    $processes = Get-Process | Where-Object {
        -not (Test-IsProtectedProcess $_.ProcessName)
    } | Select-Object Id, ProcessName,
        @{N='CPU_Seconds';E={[math]::Round($_.CPU, 2)}},
        @{N='Memory_MB';E={[math]::Round($_.WorkingSet64 / 1MB, 2)}},
        @{N='Threads';E={$_.Threads.Count}},
        @{N='Handles';E={$_.HandleCount}}

    Write-ColorText "Top $TopCount by MEMORY usage:" -Color Magenta
    $processes | Sort-Object Memory_MB -Descending |
        Select-Object -First $TopCount |
        Format-Table -AutoSize

    Write-ColorText "Top $TopCount by CPU time:" -Color Magenta
    $processes | Sort-Object CPU_Seconds -Descending |
        Select-Object -First $TopCount |
        Format-Table -AutoSize

    $highMemory = $processes | Where-Object { $_.Memory_MB -gt 500 }
    $highCpu = $processes | Where-Object { $_.CPU_Seconds -gt 1000 }

    if ($highMemory) {
        Write-ColorText "WARNING: The following processes use over 500 MB RAM:" -Color Red
        $highMemory | ForEach-Object {
            Write-ColorText "   - $($_.ProcessName) - $($_.Memory_MB) MB" -Color Yellow
        }
    }

    if ($highCpu) {
        Write-ColorText "WARNING: The following processes have high CPU time:" -Color Red
        $highCpu | ForEach-Object {
            Write-ColorText "   - $($_.ProcessName) - $($_.CPU_Seconds) seconds" -Color Yellow
        }
    }

    return $processes
}

function Find-SlowProcesses {
    Write-SectionHeader "PERFORMANCE ANALYSIS"

    Write-ColorText "Analyzing system..." -Color Yellow

    $issues = @()

    # High RAM usage
    $highMemProcs = Get-Process | Where-Object {
        $_.WorkingSet64 -gt 1GB -and
        -not (Test-IsProtectedProcess $_.ProcessName)
    }

    foreach ($proc in $highMemProcs) {
        $issues += [PSCustomObject]@{
            Type = "High RAM"
            Process = $proc.ProcessName
            Value = "$([math]::Round($proc.WorkingSet64 / 1GB, 2)) GB"
            Priority = "High"
            PID = $proc.Id
        }
    }

    # High CPU usage
    Write-ColorText "Measuring CPU usage (2 seconds)..." -Color Gray
    $cpuSnapshot1 = Get-Process | Select-Object Id, CPU
    Start-Sleep -Seconds 2
    $cpuSnapshot2 = Get-Process | Select-Object Id, CPU

    foreach ($proc2 in $cpuSnapshot2) {
        $proc1 = $cpuSnapshot1 | Where-Object { $_.Id -eq $proc2.Id }
        if ($proc1 -and $null -ne $proc2.CPU -and $null -ne $proc1.CPU) {
            $cpuDiff = $proc2.CPU - $proc1.CPU
            if ($cpuDiff -gt 3) {
                $process = Get-Process -Id $proc2.Id -ErrorAction SilentlyContinue
                if ($process -and -not (Test-IsProtectedProcess $process.ProcessName)) {
                    $issues += [PSCustomObject]@{
                        Type = "High CPU"
                        Process = $process.ProcessName
                        Value = "$([math]::Round($cpuDiff, 1))s / 2s"
                        Priority = "High"
                        PID = $proc2.Id
                    }
                }
            }
        }
    }

    # Many handles
    $highHandles = Get-Process | Where-Object {
        $_.HandleCount -gt 5000 -and
        -not (Test-IsProtectedProcess $_.ProcessName)
    }

    foreach ($proc in $highHandles) {
        $issues += [PSCustomObject]@{
            Type = "Many Handles"
            Process = $proc.ProcessName
            Value = "$($proc.HandleCount) handles"
            Priority = "Medium"
            PID = $proc.Id
        }
    }

    if ($issues.Count -eq 0) {
        Write-ColorText "[OK] No performance issues found!" -Color Green
        return
    }

    Write-ColorText "Potential issues found:" -Color Red
    Write-Host ""
    $issues | Format-Table -AutoSize

    if (Get-UserConfirmation "Would you like to terminate one or more of these processes?") {
        $i = 1
        $procList = @{}
        foreach ($issue in $issues) {
            $procList[$i] = $issue
            Write-ColorText "  [$i] $($issue.Process) ($($issue.Type))" -Color Yellow
            $i++
        }

        Write-ColorText "Input (e.g. 1,2) or 'q': " -Color Yellow -NoNewLine
        $userInput = Read-Host

        if ($userInput -ne 'q') {
            $numbers = $userInput -split ',' | ForEach-Object { $_.Trim() }
            foreach ($num in $numbers) {
                $numInt = 0
                if ([int]::TryParse($num, [ref]$numInt) -and $procList.ContainsKey($numInt)) {
                    try {
                        Stop-Process -Id $procList[$numInt].PID -Force -ErrorAction Stop
                        Write-ColorText "  [OK] $($procList[$numInt].Process) terminated" -Color Green
                    } catch {
                        Write-ColorText "  [X] Error terminating" -Color Red
                    }
                }
            }
        }
    }
}

function Show-ProcessManager {
    Write-SectionHeader "INTERACTIVE PROCESS MANAGER"

    $fgProcesses = @(Get-ForegroundProcesses)
    $bgProcesses = @(Get-BackgroundProcesses | Where-Object { $_.Memory_MB -gt 30 })

    $allProcesses = $fgProcesses + $bgProcesses
    $processes = $allProcesses | Sort-Object Memory_MB -Descending

    if (-not $processes -or $processes.Count -eq 0) {
        Write-ColorText "[OK] No processes found." -Color Green
        return
    }

    Write-ColorText "All active processes (sorted by memory):" -Color Yellow

    $i = 1
    $procList = @{}
    foreach ($proc in $processes) {
        $procList[$i] = $proc
        $memColor = Get-ColorForValue -Value $proc.Memory_MB -HighThreshold 500 -MediumThreshold 200

        $procName = $proc.ProcessName
        if ($procName.Length -gt 25) { $procName = $procName.Substring(0, 22) + "..." }

        Write-ColorText "  [$i] " -Color Cyan -NoNewLine
        Write-ColorText "$($procName.PadRight(25))" -Color White -NoNewLine
        Write-ColorText "$($proc.Memory_MB.ToString().PadLeft(8)) MB" -Color $memColor
        $i++
        if ($i -gt 30) { break }
    }

    Write-Host ""
    Write-ColorText "Input: Number(s) to kill (e.g. 1,3,5) or 'q' to cancel: " -Color Yellow -NoNewLine
    $userInput = Read-Host

    if ($userInput -eq 'q') { return }

    $numbers = $userInput -split ',' | ForEach-Object { $_.Trim() }

    foreach ($num in $numbers) {
        $numInt = 0
        if ([int]::TryParse($num, [ref]$numInt) -and $procList.ContainsKey($numInt)) {
            $proc = $procList[$numInt]
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-ColorText "  [OK] $($proc.ProcessName) terminated" -Color Green
            } catch {
                Write-ColorText "  [X] $($proc.ProcessName) error" -Color Red
            }
        }
    }
}

function Start-AutoCleanup {
    Write-SectionHeader "AUTO-CLEANUP MODE"

    Write-ColorText "This mode automatically closes:" -Color Yellow
    Write-ColorText "  - All browsers" -Color White
    Write-ColorText "  - All Office apps (except Teams if selected)" -Color White
    Write-ColorText "  - All media apps" -Color White
    Write-ColorText "  - Development tools" -Color White
    Write-ColorText "  - Systray apps (optional)" -Color White

    Write-Host ""
    Write-ColorText "[1] " -Color Cyan -NoNewLine
    Write-ColorText "Auto-Cleanup WITHOUT Teams" -Color White
    Write-ColorText "[2] " -Color Cyan -NoNewLine
    Write-ColorText "Auto-Cleanup WITH Teams" -Color White
    Write-ColorText "[3] " -Color Cyan -NoNewLine
    Write-ColorText "Auto-Cleanup + close systray" -Color Yellow
    Write-ColorText "[4] " -Color Cyan -NoNewLine
    Write-ColorText "Preview only (close nothing)" -Color White
    Write-ColorText "[q] " -Color Cyan -NoNewLine
    Write-ColorText "Cancel" -Color White

    Write-Host ""
    Write-ColorText "Choice: " -Color Yellow -NoNewLine
    $choice = Read-Host

    if ($choice -eq 'q') { return }

    $includeTeams = ($choice -eq '2' -or $choice -eq '3')
    $includeSystray = ($choice -eq '3')

    $allApps = @()
    foreach ($category in $Script:Config.CommonApps.Values) {
        $allApps += $category
    }

    $toClose = @()
    foreach ($appName in $allApps) {
        if (-not $includeTeams -and (Test-IsTeamsProcess $appName)) { continue }
        $procs = Get-Process -Name $appName -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            $toClose += $proc
        }
    }

    if ($includeSystray) {
        $toClose += Get-SystrayProcesses | ForEach-Object {
            Get-Process -Id $_.Id -ErrorAction SilentlyContinue
        }
    }

    if ($toClose.Count -eq 0) {
        Write-ColorText "[OK] No matching apps found." -Color Green
        return
    }

    Write-Host ""
    Write-ColorText "Found apps:" -Color Yellow
    $toClose | Select-Object ProcessName, @{N='Memory_MB';E={[math]::Round($_.WorkingSet64 / 1MB, 2)}} |
        Sort-Object ProcessName -Unique |
        Format-Table -AutoSize

    if ($choice -eq '4') {
        Write-ColorText "Preview only - nothing was closed." -Color Cyan
        return
    }

    if ($choice -match '^[123]$') {
        foreach ($proc in $toClose) {
            try {
                $proc.CloseMainWindow() | Out-Null
                Start-Sleep -Milliseconds 200
                if (-not $proc.HasExited) {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                }
                Write-ColorText "  [OK] $($proc.ProcessName)" -Color Green
            } catch {
                # Ignore
            }
        }
        Write-ColorText "`n[OK] Auto-Cleanup completed!" -Color Green
    }
}

# ============================================
# DISK CLEANUP FUNCTIONS
# ============================================

function Get-DiskSpaceInfo {
    Write-SectionHeader "DISK OVERVIEW"

    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"

    foreach ($drive in $drives) {
        $usedSpace = $drive.Size - $drive.FreeSpace
        $usedPercent = [math]::Round(($usedSpace / $drive.Size) * 100, 1)
        $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($drive.Size / 1GB, 2)

        $color = Get-ColorForValue -Value $usedPercent -HighThreshold 90 -MediumThreshold 75

        $barLength = 30
        $filledLength = [math]::Round(($usedPercent / 100) * $barLength)
        $bar = ('#' * $filledLength) + ('-' * ($barLength - $filledLength))

        Write-ColorText "  $($drive.DeviceID) " -Color Cyan -NoNewLine
        Write-ColorText "[$bar]" -Color $color -NoNewLine
        Write-ColorText " $usedPercent% used ($freeGB GB free of $totalGB GB)" -Color $color
    }
}

function Get-CleanupAnalysis {
    Write-SectionHeader "CLEANUP ANALYSIS"

    Write-ColorText "Analyzing disk space usage..." -Color Yellow
    Write-Host ""

    $cleanupItems = @()
    $totalSavings = 0

    # Windows Temp
    $tempSize = Get-FolderSize $env:TEMP
    if ($tempSize -gt 0) {
        $cleanupItems += [PSCustomObject]@{
            Category = "Windows Temp"
            Path = $env:TEMP
            Size = $tempSize
            SizeFormatted = Format-FileSize $tempSize
            Safe = $true
        }
        $totalSavings += $tempSize
    }

    # Windows Temp (System)
    $winTemp = "$env:WINDIR\Temp"
    $winTempSize = Get-FolderSize $winTemp
    if ($winTempSize -gt 0) {
        $cleanupItems += [PSCustomObject]@{
            Category = "System Temp"
            Path = $winTemp
            Size = $winTempSize
            SizeFormatted = Format-FileSize $winTempSize
            Safe = $true
        }
        $totalSavings += $winTempSize
    }

    # Browser Caches
    $browserCaches = @{
        "Chrome Cache" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
        "Chrome Code Cache" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache"
        "Edge Cache" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
        "Edge Code Cache" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache"
    }

    foreach ($cache in $browserCaches.GetEnumerator()) {
        if (Test-Path $cache.Value) {
            $size = Get-FolderSize $cache.Value
            if ($size -gt 10MB) {
                $cleanupItems += [PSCustomObject]@{
                    Category = $cache.Key
                    Path = $cache.Value
                    Size = $size
                    SizeFormatted = Format-FileSize $size
                    Safe = $true
                }
                $totalSavings += $size
            }
        }
    }

    # Discord Cache
    $discordCache = "$env:LOCALAPPDATA\Discord\Cache"
    if (Test-Path $discordCache) {
        $size = Get-FolderSize $discordCache
        if ($size -gt 10MB) {
            $cleanupItems += [PSCustomObject]@{
                Category = "Discord Cache"
                Path = $discordCache
                Size = $size
                SizeFormatted = Format-FileSize $size
                Safe = $true
            }
            $totalSavings += $size
        }
    }

    # Teams Cache
    $teamsPath = "$env:APPDATA\Microsoft\Teams"
    $teamsCacheFolders = @('Cache', 'blob_storage', 'databases', 'GPUCache', 'IndexedDB', 'Local Storage', 'tmp')
    $teamsTotal = 0
    foreach ($folder in $teamsCacheFolders) {
        $path = Join-Path $teamsPath $folder
        if (Test-Path $path) {
            $teamsTotal += Get-FolderSize $path
        }
    }
    if ($teamsTotal -gt 10MB) {
        $cleanupItems += [PSCustomObject]@{
            Category = "Teams Cache"
            Path = $teamsPath
            Size = $teamsTotal
            SizeFormatted = Format-FileSize $teamsTotal
            Safe = $true
        }
        $totalSavings += $teamsTotal
    }

    # Crash Dumps
    $crashDumps = "$env:LOCALAPPDATA\CrashDumps"
    if (Test-Path $crashDumps) {
        $size = Get-FolderSize $crashDumps
        if ($size -gt 1MB) {
            $cleanupItems += [PSCustomObject]@{
                Category = "Crash Dumps"
                Path = $crashDumps
                Size = $size
                SizeFormatted = Format-FileSize $size
                Safe = $true
            }
            $totalSavings += $size
        }
    }

    # Windows Update Cache
    $wuCache = "$env:WINDIR\SoftwareDistribution\Download"
    if (Test-Path $wuCache) {
        $size = Get-FolderSize $wuCache
        if ($size -gt 50MB) {
            $cleanupItems += [PSCustomObject]@{
                Category = "Windows Update Cache"
                Path = $wuCache
                Size = $size
                SizeFormatted = Format-FileSize $size
                Safe = $false
            }
            $totalSavings += $size
        }
    }

    # Recycle Bin
    try {
        $rbSize = (Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |
                   Measure-Object -Property Length -Sum).Sum
        if ($rbSize -gt 1MB) {
            $cleanupItems += [PSCustomObject]@{
                Category = "Recycle Bin"
                Path = "Recycle Bin"
                Size = $rbSize
                SizeFormatted = Format-FileSize $rbSize
                Safe = $true
            }
            $totalSavings += $rbSize
        }
    } catch {}

    # Thumbnails
    $thumbCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    $thumbSize = (Get-ChildItem -Path $thumbCache -Filter "thumbcache*.db" -Force -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum).Sum
    if ($thumbSize -gt 10MB) {
        $cleanupItems += [PSCustomObject]@{
            Category = "Thumbnail Cache"
            Path = $thumbCache
            Size = $thumbSize
            SizeFormatted = Format-FileSize $thumbSize
            Safe = $true
        }
        $totalSavings += $thumbSize
    }

    return @{
        Items = $cleanupItems | Sort-Object Size -Descending
        TotalSavings = $totalSavings
    }
}

function Start-DiskCleanup {
    Write-SectionHeader "DISK CLEANUP"

    Get-DiskSpaceInfo
    Write-Host ""

    $analysis = Get-CleanupAnalysis
    $items = $analysis.Items
    $totalSavings = $analysis.TotalSavings

    if ($items.Count -eq 0) {
        Write-ColorText "[OK] No significant cleanup opportunities found!" -Color Green
        return
    }

    Write-ColorText "Found cleanup opportunities:" -Color Yellow
    Write-Host ""

    $i = 1
    $itemList = @{}
    foreach ($item in $items) {
        $itemList[$i] = $item
        $safety = if ($item.Safe) { "[SAFE]" } else { "[ADMIN]" }
        $sColor = if ($item.Safe) { "Green" } else { "Yellow" }

        Write-ColorText "  [$i] " -Color Cyan -NoNewLine
        Write-ColorText "$($item.Category.PadRight(25))" -Color White -NoNewLine
        Write-ColorText "$($item.SizeFormatted.PadLeft(12))" -Color Magenta -NoNewLine
        Write-ColorText "  $safety" -Color $sColor
        $i++
    }

    Write-Host ""
    Write-ColorText "  TOTAL possible: " -Color White -NoNewLine
    Write-ColorText (Format-FileSize $totalSavings) -Color Green

    Write-Host ""
    Write-ColorText "[A] " -Color Magenta -NoNewLine
    Write-ColorText "Clean ALL" -Color White
    Write-ColorText "[S] " -Color Magenta -NoNewLine
    Write-ColorText "Select to clean (e.g. 1,3,5)" -Color White
    Write-ColorText "[W] " -Color Magenta -NoNewLine
    Write-ColorText "Start Windows Disk Cleanup" -Color White
    Write-ColorText "[Q] " -Color Magenta -NoNewLine
    Write-ColorText "Back" -Color White

    Write-Host ""
    Write-ColorText "Choice: " -Color Yellow -NoNewLine
    $userInput = Read-Host

    if ($userInput -match '^[Qq]$') { return }

    if ($userInput -match '^[Ww]$') {
        Write-ColorText "Starting Windows Disk Cleanup..." -Color Yellow
        Start-Process "cleanmgr.exe" -ArgumentList "/d C:" -Wait
        return
    }

    $itemsToClean = @()

    if ($userInput -match '^[Aa]$') {
        if (Get-UserConfirmation "Really clean ALL?") {
            $itemsToClean = $items
        }
    } else {
        if ($userInput -match '^[Ss]$') {
            Write-ColorText "Enter numbers (e.g. 1,3,5): " -Color Yellow -NoNewLine
            $userInput = Read-Host
        }

        $numbers = $userInput -split ',' | ForEach-Object { $_.Trim() }
        foreach ($num in $numbers) {
            $numInt = 0
            if ([int]::TryParse($num, [ref]$numInt) -and $itemList.ContainsKey($numInt)) {
                $itemsToClean += $itemList[$numInt]
            }
        }
    }

    $freedSpace = 0

    foreach ($item in $itemsToClean) {
        Write-ColorText "  Cleaning: $($item.Category)..." -Color Yellow

        try {
            if ($item.Path -eq "Recycle Bin") {
                Clear-RecycleBin -Force -ErrorAction SilentlyContinue
                Write-ColorText "    [OK] Recycle Bin emptied" -Color Green
                $freedSpace += $item.Size
            }
            elseif ($item.Category -eq "Thumbnail Cache") {
                Get-ChildItem -Path $item.Path -Filter "thumbcache*.db" -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Force -ErrorAction SilentlyContinue
                Write-ColorText "    [OK] Thumbnails deleted" -Color Green
                $freedSpace += $item.Size
            }
            elseif ($item.Category -eq "Teams Cache") {
                $teamsCacheFolders = @('Cache', 'blob_storage', 'databases', 'GPUCache', 'IndexedDB', 'Local Storage', 'tmp')
                foreach ($folder in $teamsCacheFolders) {
                    $path = Join-Path $item.Path $folder
                    if (Test-Path $path) {
                        Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                Write-ColorText "    [OK] Teams Cache deleted" -Color Green
                $freedSpace += $item.Size
            }
            elseif (Test-Path $item.Path) {
                Remove-Item -Path "$($item.Path)\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-ColorText "    [OK] $($item.Category) deleted" -Color Green
                $freedSpace += $item.Size
            }
        } catch {
            Write-ColorText "    [X] Error with $($item.Category): $($_.Exception.Message)" -Color Red
        }
    }

    Write-Host ""
    Write-ColorText "RESULT: Approximately $(Format-FileSize $freedSpace) freed!" -Color Green
}

# ============================================
# UNINSTALL FUNCTIONS
# ============================================

function Get-InstalledPrograms {
    Write-SectionHeader "INSTALLED PROGRAMS"

    Write-ColorText "Loading installed programs..." -Color Yellow

    $programs = @()

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $regPaths) {
        $items = Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.UninstallString } |
            Select-Object @{N='Name';E={$_.DisplayName}},
                         @{N='Version';E={$_.DisplayVersion}},
                         @{N='Publisher';E={$_.Publisher}},
                         @{N='Size_MB';E={[math]::Round($_.EstimatedSize / 1024, 2)}},
                         @{N='UninstallString';E={$_.UninstallString}},
                         @{N='InstallDate';E={$_.InstallDate}}

        $programs += $items
    }

    $programs = $programs | Sort-Object Name -Unique | Sort-Object Size_MB -Descending

    return $programs
}

function Show-UninstallManager {
    $programs = Get-InstalledPrograms

    if ($programs.Count -eq 0) {
        Write-ColorText "[OK] No programs found." -Color Green
        return
    }

    Write-ColorText "Installed programs (sorted by size):" -Color Yellow
    Write-Host ""

    $i = 1
    $progList = @{}
    $pageSize = 25
    $currentPage = 0
    $totalPages = [math]::Ceiling($programs.Count / $pageSize)

    function Show-ProgramPage {
        param($page)

        $start = $page * $pageSize
        $end = [math]::Min($start + $pageSize, $programs.Count)

        for ($j = $start; $j -lt $end; $j++) {
            $prog = $programs[$j]
            $num = $j + 1
            $progList[$num] = $prog

            $name = $prog.Name
            if ($name.Length -gt 40) { $name = $name.Substring(0, 37) + "..." }

            $size = if ($prog.Size_MB -and $prog.Size_MB -gt 0) {
                "$($prog.Size_MB) MB"
            } else {
                "N/A"
            }

            Write-ColorText "  [$($num.ToString().PadLeft(3))] " -Color Cyan -NoNewLine
            Write-ColorText "$($name.PadRight(42))" -Color White -NoNewLine
            Write-ColorText "$($size.PadLeft(10))" -Color Magenta
        }

        Write-Host ""
        Write-ColorText "  Page $($page + 1) of $totalPages  (Total: $($programs.Count) programs)" -Color DarkGray
    }

    Show-ProgramPage -page $currentPage

    while ($true) {
        Write-Host ""
        Write-ColorText "[N] " -Color Magenta -NoNewLine
        Write-ColorText "Next page" -Color White
        Write-ColorText "[P] " -Color Magenta -NoNewLine
        Write-ColorText "Previous page" -Color White
        Write-ColorText "[S] " -Color Magenta -NoNewLine
        Write-ColorText "Search" -Color White
        Write-ColorText "[W] " -Color Magenta -NoNewLine
        Write-ColorText "Open Windows Settings (Apps)" -Color White
        Write-ColorText "[#] " -Color Magenta -NoNewLine
        Write-ColorText "Enter number to uninstall" -Color White
        Write-ColorText "[Q] " -Color Magenta -NoNewLine
        Write-ColorText "Back" -Color White

        Write-Host ""
        Write-ColorText "Choice: " -Color Yellow -NoNewLine
        $userInput = Read-Host

        if ($userInput -match '^[Qq]$') { return }

        if ($userInput -match '^[Ww]$') {
            Write-ColorText "Opening Windows Settings > Apps..." -Color Yellow
            Start-Process "ms-settings:appsfeatures"
            continue
        }

        if ($userInput -match '^[Nn]$') {
            if ($currentPage -lt $totalPages - 1) {
                $currentPage++
                Clear-Host
                Write-Banner
                Write-SectionHeader "INSTALLED PROGRAMS"
                Show-ProgramPage -page $currentPage
            }
            continue
        }

        if ($userInput -match '^[Pp]$') {
            if ($currentPage -gt 0) {
                $currentPage--
                Clear-Host
                Write-Banner
                Write-SectionHeader "INSTALLED PROGRAMS"
                Show-ProgramPage -page $currentPage
            }
            continue
        }

        if ($userInput -match '^[Ss]$') {
            Write-ColorText "Search term: " -Color Yellow -NoNewLine
            $searchTerm = Read-Host

            $found = $programs | Where-Object { $_.Name -like "*$searchTerm*" }

            if ($found.Count -eq 0) {
                Write-ColorText "No results for '$searchTerm'" -Color Red
                continue
            }

            Write-Host ""
            Write-ColorText "Search results:" -Color Yellow
            $searchList = @{}
            $si = 1
            foreach ($prog in $found) {
                $searchList[$si] = $prog
                $name = $prog.Name
                if ($name.Length -gt 40) { $name = $name.Substring(0, 37) + "..." }

                Write-ColorText "  [$si] " -Color Cyan -NoNewLine
                Write-ColorText "$name" -Color White
                $si++
                if ($si -gt 20) { break }
            }

            Write-ColorText "`nNumber to uninstall (or Q): " -Color Yellow -NoNewLine
            $choice = Read-Host

            if ($choice -match '^\d+$') {
                $choiceInt = [int]$choice
                if ($searchList.ContainsKey($choiceInt)) {
                    $selectedProg = $searchList[$choiceInt]
                    if (Get-UserConfirmation "Really uninstall '$($selectedProg.Name)'?") {
                        Start-Uninstall -Program $selectedProg
                    }
                }
            }
            continue
        }

        # Number entered
        $numInt = 0
        if ([int]::TryParse($userInput, [ref]$numInt) -and $progList.ContainsKey($numInt)) {
            $selectedProg = $progList[$numInt]
            Write-Host ""
            Write-ColorText "Selected: $($selectedProg.Name)" -Color Cyan
            Write-ColorText "Publisher: $($selectedProg.Publisher)" -Color Gray
            Write-ColorText "Version:   $($selectedProg.Version)" -Color Gray

            if (Get-UserConfirmation "`nReally uninstall?") {
                Start-Uninstall -Program $selectedProg
            }
        }
    }
}

function Start-Uninstall {
    param($Program)

    Write-ColorText "Starting uninstallation of '$($Program.Name)'..." -Color Yellow

    try {
        $uninstall = $Program.UninstallString

        if ($uninstall -match 'msiexec') {
            if ($uninstall -notmatch '/[xX]') {
                $uninstall = $uninstall -replace '/[iI]', '/X'
            }
            $uninstall = "$uninstall /qb"
            Start-Process cmd -ArgumentList "/c $uninstall" -Wait -NoNewWindow
        }
        else {
            $uninstall = $uninstall -replace '"', ''

            if ($uninstall -match '\.exe') {
                $exePath = $uninstall -replace '\s+/.*$', ''
                $uninstallArgs = $uninstall -replace '^.*?\.exe\s*', ''

                if (Test-Path $exePath) {
                    Start-Process $exePath -ArgumentList $uninstallArgs -Wait
                } else {
                    Start-Process cmd -ArgumentList "/c `"$uninstall`"" -Wait
                }
            } else {
                Start-Process cmd -ArgumentList "/c `"$uninstall`"" -Wait
            }
        }

        Write-ColorText "[OK] Uninstallation started" -Color Green
    } catch {
        Write-ColorText "[X] Error: $($_.Exception.Message)" -Color Red
        Write-ColorText "    Try uninstalling manually through Windows Settings." -Color Yellow
    }
}

# ============================================
# PERFORMANCE OPTIMIZER
# ============================================

function Show-PerformanceOptimizer {
    Write-SectionHeader "SYSTEM OPTIMIZATION"

    $isAdmin = Test-AdminRights

    if (-not $isAdmin) {
        Write-ColorText "[!] Running without admin rights. Some operations will be skipped." -Color Yellow
        Write-Host ""
    }

    Write-ColorText "  --- TIER 1: SAFE (cache cleanup, fully reversible) ---" -Color Green
    Write-ColorText "  [1] Clear DNS cache" -Color White
    Write-ColorText "  [2] Clear Prefetch cache" -Color White
    Write-ColorText "  [3] Clear Thumbnail cache" -Color White
    Write-ColorText "  [4] Clear Windows Update cache" -Color White
    Write-ColorText "  [5] Run ALL Safe optimizations" -Color Green

    Write-Host ""
    Write-ColorText "  --- TIER 2: MODERATE (system settings, easily reversible) ---" -Color Yellow
    Write-ColorText "  [6] Set power plan to Ultimate Performance" -Color White
    Write-ColorText "  [7] Set visual effects to Best Performance" -Color White
    Write-ColorText "  [8] DISM component cleanup" -Color White
    Write-ColorText "  [9] Run ALL Moderate optimizations" -Color Yellow

    Write-Host ""
    Write-ColorText "  --- TIER 3: ADVANCED (admin required, bigger changes) ---" -Color Red
    Write-ColorText "  [A] Disable telemetry/tracking services" -Color White
    Write-ColorText "  [B] Remove Windows bloatware apps" -Color White
    Write-ColorText "  [C] Disable hibernation (reclaims 2-4 GB)" -Color White
    Write-ColorText "  [D] Run ALL Advanced optimizations" -Color Red

    Write-Host ""
    Write-ColorText "  [F] " -Color Magenta -NoNewLine
    Write-ColorText "FULL optimization (Tier 1 + 2 + 3)" -Color Magenta
    Write-ColorText "  [Q] " -Color Magenta -NoNewLine
    Write-ColorText "Back" -Color White

    Write-Host ""
    Write-ColorText "Choice: " -Color Yellow -NoNewLine
    $choice = Read-Host

    switch ($choice.ToUpper()) {
        '1' { Invoke-ClearDnsCache }
        '2' { Invoke-ClearPrefetchCache -IsAdmin $isAdmin }
        '3' { Invoke-ClearThumbnailCache }
        '4' { Invoke-ClearWindowsUpdateCache -IsAdmin $isAdmin }
        '5' {
            Invoke-ClearDnsCache
            Invoke-ClearPrefetchCache -IsAdmin $isAdmin
            Invoke-ClearThumbnailCache
            Invoke-ClearWindowsUpdateCache -IsAdmin $isAdmin
            Write-ColorText "`n[OK] All Safe optimizations completed!" -Color Green
        }
        '6' { Invoke-UltimatePerformancePlan }
        '7' { Invoke-BestPerformanceVisuals }
        '8' { Invoke-DismCleanup -IsAdmin $isAdmin }
        '9' {
            Invoke-UltimatePerformancePlan
            Invoke-BestPerformanceVisuals
            Invoke-DismCleanup -IsAdmin $isAdmin
            Write-ColorText "`n[OK] All Moderate optimizations completed!" -Color Green
        }
        'A' { Invoke-DisableTrackingServices -IsAdmin $isAdmin }
        'B' { Invoke-RemoveBloatware }
        'C' { Invoke-DisableHibernation -IsAdmin $isAdmin }
        'D' {
            Invoke-DisableTrackingServices -IsAdmin $isAdmin
            Invoke-RemoveBloatware
            Invoke-DisableHibernation -IsAdmin $isAdmin
            Write-ColorText "`n[OK] All Advanced optimizations completed!" -Color Green
        }
        'F' {
            if (Get-UserConfirmation "Run FULL optimization (all 3 tiers)?") {
                Write-ColorText "`n=== TIER 1: SAFE ===" -Color Green
                Invoke-ClearDnsCache
                Invoke-ClearPrefetchCache -IsAdmin $isAdmin
                Invoke-ClearThumbnailCache
                Invoke-ClearWindowsUpdateCache -IsAdmin $isAdmin

                Write-ColorText "`n=== TIER 2: MODERATE ===" -Color Yellow
                Invoke-UltimatePerformancePlan
                Invoke-BestPerformanceVisuals
                Invoke-DismCleanup -IsAdmin $isAdmin

                Write-ColorText "`n=== TIER 3: ADVANCED ===" -Color Red
                Invoke-DisableTrackingServices -IsAdmin $isAdmin
                Invoke-RemoveBloatware
                Invoke-DisableHibernation -IsAdmin $isAdmin

                Write-ColorText "`n[OK] FULL optimization completed!" -Color Green
            }
        }
        'Q' { return }
        default { Write-ColorText "Invalid choice." -Color Red }
    }
}

# --- Tier 1: Safe ---

function Invoke-ClearDnsCache {
    Write-Host ""
    Write-ColorText "  DNS Cache: Flushes cached DNS entries to fix stale lookups." -Color Gray
    if (Get-UserConfirmation "  Clear DNS cache?") {
        try {
            Clear-DnsClientCache
            Write-ColorText "  [OK] DNS cache cleared." -Color Green
        } catch {
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

function Invoke-ClearPrefetchCache {
    param([bool]$IsAdmin)
    Write-Host ""
    Write-ColorText "  Prefetch Cache: Removes preload data. Windows rebuilds it automatically." -Color Gray
    if (-not $IsAdmin) {
        Write-ColorText "  [SKIP] Requires admin rights." -Color Yellow
        return
    }
    if (Get-UserConfirmation "  Clear Prefetch cache?") {
        try {
            $prefetchPath = "$env:WINDIR\Prefetch"
            $count = (Get-ChildItem -Path $prefetchPath -ErrorAction SilentlyContinue).Count
            Remove-Item -Path "$prefetchPath\*" -Force -ErrorAction SilentlyContinue
            Write-ColorText "  [OK] Prefetch cache cleared ($count files)." -Color Green
        } catch {
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

function Invoke-ClearThumbnailCache {
    Write-Host ""
    Write-ColorText "  Thumbnail Cache: Removes cached image previews. Rebuilt on demand." -Color Gray
    if (Get-UserConfirmation "  Clear thumbnail cache?") {
        try {
            $thumbPath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
            $files = Get-ChildItem -Path $thumbPath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue
            $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
            $files | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-ColorText "  [OK] Thumbnail cache cleared ($(Format-FileSize $totalSize))." -Color Green
        } catch {
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

function Invoke-ClearWindowsUpdateCache {
    param([bool]$IsAdmin)
    Write-Host ""
    Write-ColorText "  Windows Update Cache: Removes downloaded update files." -Color Gray
    if (-not $IsAdmin) {
        Write-ColorText "  [SKIP] Requires admin rights." -Color Yellow
        return
    }
    if (Get-UserConfirmation "  Clear Windows Update cache?") {
        try {
            Write-ColorText "  Stopping Windows Update service..." -Color Gray
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue

            $wuPath = "$env:WINDIR\SoftwareDistribution\Download"
            $size = Get-FolderSize $wuPath
            Remove-Item -Path "$wuPath\*" -Recurse -Force -ErrorAction SilentlyContinue

            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Write-ColorText "  [OK] Windows Update cache cleared ($(Format-FileSize $size))." -Color Green
        } catch {
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

# --- Tier 2: Moderate ---

function Invoke-UltimatePerformancePlan {
    Write-Host ""
    Write-ColorText "  Power Plan: Switches to Ultimate Performance for maximum speed." -Color Gray
    Write-ColorText "  (Reversible via Settings > Power & battery)" -Color DarkGray
    if (Get-UserConfirmation "  Set power plan to Ultimate Performance?") {
        try {
            $result = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>&1
            if ($result -match '([0-9a-f\-]{36})') {
                $guid = $Matches[1]
                powercfg -setactive $guid
                Write-ColorText "  [OK] Ultimate Performance power plan activated." -Color Green
            } else {
                # Plan may already exist, try to activate directly
                powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-ColorText "  [OK] Ultimate Performance power plan activated." -Color Green
                } else {
                    Write-ColorText "  [!] Could not activate Ultimate Performance plan. Using High Performance instead." -Color Yellow
                    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
                    Write-ColorText "  [OK] High Performance power plan activated." -Color Green
                }
            }
        } catch {
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

function Invoke-BestPerformanceVisuals {
    Write-Host ""
    Write-ColorText "  Visual Effects: Disables animations and transparency for speed." -Color Gray
    Write-ColorText "  (Reversible via System > Advanced > Performance Settings)" -Color DarkGray
    if (Get-UserConfirmation "  Set visual effects to Best Performance?") {
        try {
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "VisualFXSetting" -Value 2 -Type DWord

            # Also set UserPreferencesMask for immediate effect
            $perfPath = "HKCU:\Control Panel\Desktop"
            Set-ItemProperty -Path $perfPath -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Type Binary -ErrorAction SilentlyContinue

            Write-ColorText "  [OK] Visual effects set to Best Performance." -Color Green
            Write-ColorText "       Log off/on or restart Explorer for full effect." -Color DarkGray
        } catch {
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

function Invoke-DismCleanup {
    param([bool]$IsAdmin)
    Write-Host ""
    Write-ColorText "  DISM Cleanup: Removes old component versions and update backups." -Color Gray
    if (-not $IsAdmin) {
        Write-ColorText "  [SKIP] Requires admin rights." -Color Yellow
        return
    }
    if (Get-UserConfirmation "  Run DISM component cleanup? (may take several minutes)") {
        try {
            Write-ColorText "  Running DISM cleanup (this may take a while)..." -Color Yellow
            $result = DISM.exe /online /Cleanup-Image /StartComponentCleanup 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-ColorText "  [OK] DISM component cleanup completed." -Color Green
            } else {
                Write-ColorText "  [!] DISM completed with warnings." -Color Yellow
            }
        } catch {
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

# --- Tier 3: Advanced ---

function Invoke-DisableTrackingServices {
    param([bool]$IsAdmin)
    Write-Host ""
    Write-ColorText "  Telemetry Services: Disables SysMain (Superfetch), DiagTrack, dmwappushservice." -Color Gray
    Write-ColorText "  (Reversible: Set-Service -StartupType Automatic)" -Color DarkGray
    if (-not $IsAdmin) {
        Write-ColorText "  [SKIP] Requires admin rights." -Color Yellow
        return
    }
    if (Get-UserConfirmation "  Disable telemetry/tracking services?") {
        foreach ($svcName in $Script:Config.OptimizationServices) {
            try {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($svc) {
                    if ($svc.Status -eq 'Running') {
                        Stop-Service -Name $svcName -Force -ErrorAction Stop
                    }
                    Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                    Write-ColorText "  [OK] $svcName disabled." -Color Green
                } else {
                    Write-ColorText "  [--] $svcName not found (already removed)." -Color DarkGray
                }
            } catch {
                Write-ColorText "  [X] $svcName error: $($_.Exception.Message)" -Color Red
            }
        }
    }
}

function Invoke-RemoveBloatware {
    Write-Host ""
    Write-ColorText "  Bloatware: Removes pre-installed Windows apps (Xbox, Solitaire, Bing, etc.)." -Color Gray
    Write-ColorText "  (Can be reinstalled from Microsoft Store)" -Color DarkGray

    # Show what will be removed
    $installed = @()
    foreach ($appName in $Script:Config.BloatwareApps) {
        $pkg = Get-AppxPackage -Name $appName -ErrorAction SilentlyContinue
        if ($pkg) {
            $installed += $pkg
            Write-ColorText "  [*] $($pkg.Name)" -Color White
        }
    }

    if ($installed.Count -eq 0) {
        Write-ColorText "  [OK] No bloatware apps found." -Color Green
        return
    }

    Write-ColorText "`n  Found $($installed.Count) bloatware app(s)." -Color Yellow
    if (Get-UserConfirmation "  Remove these apps?") {
        foreach ($pkg in $installed) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                Write-ColorText "  [OK] $($pkg.Name) removed." -Color Green
            } catch {
                Write-ColorText "  [X] $($pkg.Name) error: $($_.Exception.Message)" -Color Red
            }
        }
    }
}

function Invoke-DisableHibernation {
    param([bool]$IsAdmin)
    Write-Host ""
    Write-ColorText "  Hibernation: Disabling removes hiberfil.sys (typically 2-4 GB)." -Color Gray
    Write-ColorText "  (Reversible: powercfg /hibernate on)" -Color DarkGray
    if (-not $IsAdmin) {
        Write-ColorText "  [SKIP] Requires admin rights." -Color Yellow
        return
    }

    # Check current state
    $hiberFile = "$env:SystemDrive\hiberfil.sys"
    if (Test-Path $hiberFile -ErrorAction SilentlyContinue) {
        $hiberSize = (Get-Item $hiberFile -Force -ErrorAction SilentlyContinue).Length
        Write-ColorText "  Current hiberfil.sys size: $(Format-FileSize $hiberSize)" -Color White
    }

    if (Get-UserConfirmation "  Disable hibernation?") {
        try {
            powercfg /hibernate off
            if ($LASTEXITCODE -eq 0) {
                Write-ColorText "  [OK] Hibernation disabled." -Color Green
                if ($hiberSize) {
                    Write-ColorText "       Freed approximately $(Format-FileSize $hiberSize)." -Color Green
                }
            } else {
                Write-ColorText "  [X] Could not disable hibernation." -Color Red
            }
        } catch {
            Write-ColorText "  [X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

# ============================================
# DESKTOP SHORTCUT
# ============================================

function Install-DesktopShortcut {
    Write-SectionHeader "CREATE DESKTOP SHORTCUT"

    $scriptPath = $PSCommandPath
    if (-not $scriptPath) {
        $scriptPath = $MyInvocation.MyCommand.Path
    }
    if (-not $scriptPath) {
        $scriptPath = Join-Path (Get-Location) "WinBoost-Pro.ps1"
    }

    if (-not (Test-Path $scriptPath)) {
        Write-ColorText "[X] Script path could not be determined: $scriptPath" -Color Red
        return
    }

    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktopPath "WinBoost Pro.lnk"

    Write-ColorText "  Script:   $scriptPath" -Color White
    Write-ColorText "  Desktop:  $desktopPath" -Color White
    Write-ColorText "  Shortcut: $shortcutPath" -Color White
    Write-Host ""

    if (Get-UserConfirmation "Create desktop shortcut?") {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)

            $shortcut.TargetPath = "powershell.exe"
            $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
            $shortcut.WorkingDirectory = Split-Path $scriptPath -Parent
            $shortcut.Description = "WinBoost Pro v1.0 - Performance & Cleanup Toolkit"
            $shortcut.IconLocation = "%SystemRoot%\System32\shell32.dll,27"
            $shortcut.WindowStyle = 1

            $shortcut.Save()

            Write-ColorText "[OK] Shortcut created: $shortcutPath" -Color Green
        } catch {
            Write-ColorText "[X] Error: $($_.Exception.Message)" -Color Red
        }
    }
}

# ============================================
# MAIN MENU
# ============================================

function Invoke-Pause {
    Write-Host ""
    Write-ColorText "Press ENTER to continue..." -Color Gray -NoNewLine
    Read-Host | Out-Null
}

function Show-CloseAppsMenu {
    while ($true) {
        Write-SectionHeader "CLOSE APPS"

        Write-ColorText "  [1] " -Color Cyan -NoNewLine
        Write-ColorText "Close foreground apps" -Color White
        Write-ColorText "  [2] " -Color Cyan -NoNewLine
        Write-ColorText "TURBO: Close all (EXCEPT Teams)" -Color Yellow
        Write-ColorText "  [3] " -Color Cyan -NoNewLine
        Write-ColorText "TURBO: Close all (INCLUDING Teams)" -Color Red
        Write-ColorText "  [4] " -Color Cyan -NoNewLine
        Write-ColorText "Close by category (Browser, Office, Dev, ...)" -Color White
        Write-ColorText "  [5] " -Color Cyan -NoNewLine
        Write-ColorText "Auto-Cleanup (all categories + optional systray)" -Color White

        Write-Host ""
        Write-ColorText "  [Q] " -Color Red -NoNewLine
        Write-ColorText "Back to main menu" -Color White

        Write-Host ""
        Write-ColorText "Choice: " -Color Yellow -NoNewLine
        $choice = Read-Host

        switch ($choice.ToUpper()) {
            '1' { Close-ForegroundApps; Invoke-Pause }
            '2' { Close-AllApps; Invoke-Pause }
            '3' { Close-AllApps -IncludeTeams -IncludeSystray; Invoke-Pause }
            '4' { Close-ProcessesByCategory; Invoke-Pause }
            '5' { Start-AutoCleanup; Invoke-Pause }
            'Q' { return }
            default {
                Write-ColorText "Invalid choice!" -Color Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

function Show-ProcessManagerMenu {
    while ($true) {
        Write-SectionHeader "PROCESS MANAGER"

        Write-ColorText "  [1] " -Color Cyan -NoNewLine
        Write-ColorText "Resource overview (CPU/RAM top 15)" -Color White
        Write-ColorText "  [2] " -Color Cyan -NoNewLine
        Write-ColorText "Find performance issues (anomaly detection + kill)" -Color White
        Write-ColorText "  [3] " -Color Cyan -NoNewLine
        Write-ColorText "Interactive process killer" -Color White
        Write-ColorText "  [4] " -Color Cyan -NoNewLine
        Write-ColorText "Systray / background app manager" -Color White

        Write-Host ""
        Write-ColorText "  [Q] " -Color Red -NoNewLine
        Write-ColorText "Back to main menu" -Color White

        Write-Host ""
        Write-ColorText "Choice: " -Color Yellow -NoNewLine
        $choice = Read-Host

        switch ($choice.ToUpper()) {
            '1' { Get-ResourceHungryProcesses; Invoke-Pause }
            '2' { Find-SlowProcesses; Invoke-Pause }
            '3' { Show-ProcessManager; Invoke-Pause }
            '4' { Show-SystrayManager; Invoke-Pause }
            'Q' { return }
            default {
                Write-ColorText "Invalid choice!" -Color Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

function Show-MainMenu {
    while ($true) {
        Write-Banner

        Write-ColorText "====================================================================" -Color DarkCyan
        Write-ColorText "                           MAIN MENU                                " -Color Yellow
        Write-ColorText "====================================================================" -Color DarkCyan
        Write-Host ""

        Write-ColorText "  [1]  " -Color Cyan -NoNewLine
        Write-ColorText "Close Apps" -Color White
        Write-ColorText "  [2]  " -Color Cyan -NoNewLine
        Write-ColorText "Process Manager" -Color White
        Write-ColorText "  [3]  " -Color Cyan -NoNewLine
        Write-ColorText "Disk Cleanup" -Color White
        Write-ColorText "  [4]  " -Color Cyan -NoNewLine
        Write-ColorText "Uninstall Programs" -Color White
        Write-ColorText "  [5]  " -Color Green -NoNewLine
        Write-ColorText "System Optimization (Safe / Moderate / Advanced)" -Color Green
        Write-ColorText "  [6]  " -Color Cyan -NoNewLine
        Write-ColorText "Create Desktop Shortcut" -Color White

        Write-Host ""
        Write-ColorText "  [Q]  " -Color Red -NoNewLine
        Write-ColorText "Exit" -Color White

        Write-Host ""
        Write-ColorText "====================================================================" -Color DarkCyan
        Write-ColorText "Choice: " -Color Yellow -NoNewLine
        $choice = Read-Host

        switch ($choice.ToUpper()) {
            '1' { Show-CloseAppsMenu }
            '2' { Show-ProcessManagerMenu }
            '3' { Start-DiskCleanup; Invoke-Pause }
            '4' { Show-UninstallManager; Invoke-Pause }
            '5' { Show-PerformanceOptimizer; Invoke-Pause }
            '6' { Install-DesktopShortcut; Invoke-Pause }
            'Q' {
                Write-ColorText "`nGoodbye!" -Color Cyan
                return
            }
            default {
                Write-ColorText "Invalid choice!" -Color Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ============================================
# SCRIPT START
# ============================================

$isAdmin = Test-AdminRights

if (-not $isAdmin) {
    Write-ColorText "Note: Without admin rights, some features are limited." -Color Yellow
    Write-ColorText "      (Uninstall, System Cleanup, Performance Optimization)" -Color DarkYellow
    Start-Sleep -Seconds 2
}

Show-MainMenu
