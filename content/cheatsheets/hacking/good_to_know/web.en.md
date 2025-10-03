---
title: "Web"
date: 2025-10-03
draft: false
type: wiki
---

# IP restriction at application level - Bypass

Try to send a request modifying the HTTP header by adding:

```console
X-Forwarder-For: <ip allowed>
```

-----------------------------
