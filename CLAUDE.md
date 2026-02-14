# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`WinBoost-Pro.ps1` — a standalone Windows performance & cleanup toolkit for process management, disk cleanup, software uninstallation, and system optimization.

## Running

Requires PowerShell 5.1+. Many features need administrator privileges:

```powershell
.\WinBoost-Pro.ps1
```

No build step, no external modules, no tests. Single self-contained script.

## Architecture

The script follows this internal pattern:

1. **Comment-based help block** (`.SYNOPSIS`, `.DESCRIPTION`, `.AUTHOR`, `.DATE`)
2. **`#Requires -Version 5.1`**
3. **`$Script:Config` hashtable** — central configuration (protected processes, app categories, optimization services, bloatware list)
4. **Helper functions** — `Write-ColorText`, `Write-Banner`, `Write-SectionHeader`, `Get-UserConfirmation`, `Format-FileSize`, `Test-AdminRights`
5. **Process management** — close foreground/background/systray apps, resource analysis, category-based cleanup
6. **Disk cleanup** — temp files, browser caches, recycle bin, Windows Update cache
7. **Uninstall manager** — registry scan, paginated list, search, inline Windows Settings link
8. **Performance optimizer** — 3-tier system (Safe/Moderate/Advanced): cache cleanup, power plan, visual effects, DISM, service management, bloatware removal, hibernation
9. **Desktop shortcut** — creates a `.lnk` on the user's desktop using dynamic path detection
10. **Interactive menu loop** — `Show-MainMenu` with 13 numbered options + quit

## Conventions

- **Protected processes**: `$Script:Config.ProtectedProcesses` guards system-critical processes (explorer, dwm, csrss, lsass, etc.) that must never be terminated.
- **No external modules**: Script is self-contained with no PowerShell module dependencies.
- **Interactive menus**: Numbered menu system for user interaction.
- **Colored output**: Console output uses `Write-Host -ForegroundColor` via helper functions.
- Keep communication concise. Avoid verbose explanations.
- Use `.` as the working directory.
- Avoid adding external links or media unless explicitly requested.
