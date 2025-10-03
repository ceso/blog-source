---
title: "Samba"
date: 2025-10-03
draft: false
type: wiki
---

# Mount in Windows

Mounting it in Windows with Powershell:

```console
New-PSDrive -Name "tools" -PSProvider "Filesystem" -Root "\\192.168.42.42\tools"
```

Mounting it without Powershell:

```console
net use z: \\192.168.42.42\tools"
```

On windows, to list mounted shares, either Powershell or without it:

```console
Powershell: Get-SMBShare
Without Powershell: net share
```

-----------------------------

# Mount in Linux

Is needed to have installed cifs-utils, to install it (in debian based):

```console
sudo apt-get install cifs-utils
```

To mount it:

```console
sudo mount -t cifs //192.168.42.42/tools ~/my_share/
```

To list mounted shares:

```console
mount | grep cifs
grep cifs /proc/mount

```

-----------------------------
