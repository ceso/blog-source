---
title: "CoreOS"
date: 2025-10-04
draft: false
type: wiki
---

# Delete all images and all instances:

```console
docker ps -a|awk '{print $1}'|grep -v CONTAINER|while read a;do docker rm -f $a;done
docker images|awk '{print $3}'|grep -v IMAGE|while read a;do docker rmi -f $a;done
```

-----------------------------

# Connect to VM

```console
DOCKER_NAME=ace-app
PID=$(docker inspect --format '{{.State.Pid}}' $DOCKER_NAME)
sudo nsenter --target $PID --mount --uts --ipc --net --pid
```

-----------------------------

# Forward ports to internal

```console
iptables -D PREROUTING -t nat -i enp0s8 -p tcp --dport 80 -j DNAT --to 10.1.0.56:80
```

-----------------------------

# Logs

```console
journalctl --follow
```

-----------------------------

# systemd

```console
systemctl start <process>
systemctl stop <process>
systemctl reload-daemon
```

-----------------------------

# Q: How do I change the current runlevel?

```console
systemctl isolate runlevel5.target
systemctl isolate graphical.target
```

-----------------------------

# Q: How do I change the default runlevel to boot into?

```console
ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target
ln -sf /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target
```

-----------------------------

# Docker functions

```console
docker_connect () {
  DOCKER_NAME=$1
  PID=$(docker inspect --format '{{.State.Pid}}' $DOCKER_NAME)
  sudo nsenter --target $PID --mount --uts --ipc --net --pid
}

docker_nuke() {
    docker ps -q | xargs docker stop
    docker ps -q -a | xargs docker rm
}

docker_rmi_none() {
    docker images | grep '<none>' | \
    awk '{ print $3 }' | \
    xargs docker rmi
}

docker_go() {
   docker run --rm -t -i $@
}

docker_rm_stop() {
   (docker ps -q -a;docker ps -q) | \
   sort | \
   uniq -u | \
   xargs docker rm
}
```

-----------------------------

# etcd

```console
curl -X GET http://localhost:5000/v1/search?q=postgresql
curl -s -X GET http://meerkat.dev.o2.co.uk:8080/v1/search|python -mjson.tool
curl -s -X GET http://meerkat.dev.o2.co.uk:8080/v1/repositories/jenkins-slave/tags|python -mjson.tool
```

-----------------------------
