---
title: "Metasploit"
date: 2025-10-03
draft: false
type: wiki
---

We use metasploit: autorute + socks_proxy

```background
use post/multi/manage/autoroute
set session 8
run
use auxiliary/server/socks_proxy
run -j
```

The SRVPORT of socks_proxy must match the one configured in proxychains.conf as the VERSION used as well.

-----------------------------
