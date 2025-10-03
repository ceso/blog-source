---
title: "Windows"
date: 2025-10-03
draft: false
type: wiki
---

# Trusted Folders

```console
accesschk.exe "ceso" C:\ -wus
  -> -w is to locate writable directories
  -> -u supress errors
  -> -s makes recursion on all subdirectories

icacls.exe C:\Windows\Tasks
  ^-- Verify if Tasks has execution permissions for example (flag is "RX")
```

-----------------------------

# Check OS Information

```console
systeminfo
ver
```

-----------------------------

# Check Architecture

## Without PowerShell

```console
wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%
```

## With PowerShell

```console
[Environment]::Is64BitProcess
```

-----------------------------

# Check the Type of Language available with Powershell

```console
$ExecutionContext.SessionState.LanguageMode

Possible types are:
  - Full Language
  - RestrictedLanguage
  - No Language
  - Constrained Language
```

-----------------------------
