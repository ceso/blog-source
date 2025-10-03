---
title: "Web directorie/file scanner"
date: 2025-10-03
draft: false
type: wiki
---

# Gobuster

Scan all the directories/files by extension:
```console
gobuster dir -u http://192.168.24.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,py -o webscan/gobuster-extensions
```

For scanning without extensions, just take out the -x

-----------------------------

# Nikto

Sometimes Nikto shows juicy information, I tend to run it like:

```console
nikto -Format txt -o webscan/nikto-initial -host http://192.168.24.24 -p 8080
```

-----------------------------

# fuff

Web fuzzer, [you can get fuff here](https://github.com/ffuf/ffuf), it basically bruteforces the dirs.

```console
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://192.168.24.24/FUZZ
```

-----------------------------
