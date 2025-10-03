---
title: "Samba"
date: 2025-10-03
draft: false
type: wiki
---

# smbclient

Check if there is anonymous login enabled:

```console
smbclient -L 192.168.24.24
```

-----------------------------

# impacket

Is also possible to use impacket in the same way than smbclient to check for anonymous login (and a lot more as browse the shares) in case of incompatible versions.

```console

/usr/share/doc/python3-impacket/examples/smbclient.py ""@192.168.24.24
```

-----------------------------

# smbmap

Check which permissions we have in those shares (if there are):

```console
smbmap -H 192.168.24.24
Or having an user:
smbmap -u ceso -H 192.168.24.24
```

-----------------------------
