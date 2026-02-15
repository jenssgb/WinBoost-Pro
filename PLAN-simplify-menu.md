# Plan: Simplify WinBoost-Pro.ps1 Menu & Structure

## Status: IN PROGRESS (Step 1 of 4 not yet started)

## Context

The current WinBoost-Pro.ps1 has 13 menu options across 5 sections with significant overlap. Goal: radically simplify the main menu by merging redundant options into sub-menus, reducing cognitive load from 13 choices to 6+Q.

## Current Problems

1. **[2] + [3]** are the same function with a flag difference — two main menu slots for one feature
2. **[5] + [6]** overlap heavily — both show resource-hungry processes, [6] just adds thresholds + kill
3. **[8] + [11]** both close apps by category — [8] picks categories, [11] does all categories with Teams/systray toggle
4. **[4] + [7]** both manage/kill processes — [4] systray-focused, [7] memory-focused
5. **[1]** is a simpler version of [2]/[3] — all three close foreground apps

## New Menu Structure (6 options + Quit)

```
=== WinBoost Pro v1.0 ===

[1]  Close Apps            (sub-menu: foreground / turbo / by category)
[2]  Process Manager       (sub-menu: resource overview / find issues / kill processes / systray)
[3]  Disk Cleanup
[4]  Uninstall Programs
[5]  System Optimization   (existing sub-menu: safe / moderate / advanced)
[6]  Desktop Shortcut
[Q]  Exit
```

## Step 1: Add `Show-CloseAppsMenu` function (~40 lines)

Insert BEFORE `Show-MainMenu` (around line 1782). New function with sub-menu loop that dispatches to existing functions:

```powershell
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
```

## Step 2: Add `Show-ProcessManagerMenu` function (~35 lines)

Insert right after `Show-CloseAppsMenu`. Dispatches to existing functions:

```powershell
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
```

## Step 3: Rewrite `Show-MainMenu`

Replace the entire `Show-MainMenu` function (lines 1782-1864) with a 6-option version:

```powershell
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
```

## Step 4: Update banner tagline

Replace line 93:
```
|   Close Apps | Cleanup | Uninstall | Optimize | Analyze             |
```
With:
```
|   Close | Processes | Cleanup | Uninstall | Optimize              |
```

## What does NOT change

- All underlying functions stay identical (no logic changes)
- Config stays identical
- Helper functions stay identical
- Performance Optimizer sub-menu stays identical
- Desktop Shortcut, Disk Cleanup, Uninstall Manager stay identical

## Verification

- Run script, verify 6-option main menu renders
- Enter [1], verify 5-option Close Apps sub-menu
- Enter [2], verify 4-option Process Manager sub-menu
- [3]-[6] and [Q] work as before
- Back navigation (Q) from sub-menus returns to main menu
