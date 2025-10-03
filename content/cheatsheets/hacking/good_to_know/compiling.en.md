---
title: "Compiling"
date: 2025-10-03
draft: false
type: wiki
---

# Arch cross compile exploit (and diff glibc version)

```console
gcc -m32 -Wall -Wl,--hash-style=both -o gimme.o gimme.c
```

-----------------------------
