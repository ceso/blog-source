---
title: "sshuttle"
date: 2025-10-03
draft: false
type: wiki
---

# One hop

Let's say we are in an intranet and we have compromised a firewall that gives us access to the management net (fw.example.mgmt - ips 192.168.20.35 and 192.168.30.253 as the management ip), by using sshuttle we can create a "vpn" to talk directly to those servers, for that, we use:

```console
sshuttle ceso@192.168.20.35 192.168.30.0/24
```

# Multi-hops

Now imagine that after we broke up into the management net after some some enumeration, we ended to compromise a machine that has also access to a production environment (foreman.example.mgmt - ips 192.168.30.40 and 192.168.25.87), we can take advantage of sshuttle + ProxyCommand of ssh to create a "vpn" through this multiple hops, so...putting it down, this will be kind of as follow (the diagram is extremly simplified and just for the sake of illustrate this visually, so it doesn't intend to provide a 100% precise network diagram):

{{< image src="/images/cheatsheet/multiple-hop-sshuttle.png" position="center" style="border-radius: 8px;" >}}

To have that working, is needed to put the next conf in your ssh conf file (normally ~/.ssh/config. It's based on the example above, but is easy to extrapolate to different scenarios):

```console
Host fw.example.mgmt
  Hostname 192.168.20.35
  User userOnFw
  IdentityFile ~/.ssh/priv_key_fw
Host foreman.example.mgmt
  Hostname 192.168.30.40
  User root
  ProxyJump fw.example.mgmt
  IdentityFile ~/.ssh/priv_key_internal
```

And now to setup the "multiple hop vpn", run:

```console
sshuttle -r foreman.example.mgmt -v 192.168.25.0/24 &

Later on is possible to connect from the local machine:
ssh foo@192.168.25.74
```

-----------------------------
