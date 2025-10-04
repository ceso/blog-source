---
title: "Performance"
date: 2025-10-04
draft: false
type: wiki
---

# Diagrams

http://www.slideshare.net/slideshow/embed_code/16739605#

-----------------------------

# Load average across time. Load average can be impacted by IO

```console
uptime
```

-----------------------------

# On TOP The process list does not show KERNEL threads

```console
top
htop
atop
nmon        => press c + m + d + n
```

-----------------------------

# Network graphical tools

```console
iftop
nload
```

-----------------------------

# Multi processor statistics

```console
mpstat -P ALL 1
```

-----------------------------

# DISK I/O Statistics, First output is summary since boot

```console
iostat -xkdz 1A
```

-----------------------------

# Virtual Memory statistics. First line include some summaries since boot values
# r= total number of runnable threads, including those running

```console
vmstat 1
```

-----------------------------

# Memory usage summary

```console
free
```

-----------------------------

# Simple network latency but from kernel to kernel, including stack

```
ping
```

-----------------------------

# Network statistics tools. Check Utilization and Saturation columns (last 2)

```console
wget ftp://ftp.pbone.net/mirror/ftp5.gwdg.de/pub/opensuse/repositories/home:/cwx_holle/RedHat_RHEL-6/i686/nicstat-1.92-2.1.i686.rpm
yum install nicstat-1.92-2.1.i686.rpm
nicstat -z 1
```

-----------------------------

# System Activity reporter

```console
sar 1
sar -B 1
```

-----------------------------

# Various network protocol statistics

```console
netstat -s
```

-----------------------------

# who is consuming CPU

```console
pidstat 1
```

-----------------------------

# Pidstat to identify which application is writing to disk. It includes kernel threads with -d

```console
pidstat -d 1
```

-----------------------------

# System call tracer

```console
strace -tttT -p PID
strace -s 2000 -f -p PID => With lsof you can tell what are the file descriptors
```

Get statistics for each system call excecuted, this is useful to compare a process
that is working good vs a process that is not working right

```console
strace -c -p PID
```

For performance problems you can use the flag -T that can actually measure the
time each system call takes

```console
strace -T -p pid
```

-----------------------------

# Sysdig

```console
sysdig proc.name=python
```

## Sysdig port

```console
sysdig fd.type=ipv4
sysdig fd.l4proto=tcp
sysdig fd.sip=127.0.0.1
sysdig fd.sport=39157

# New processes:
sysdig evt.type=clone
sysdig evt.type=execve
evt.type=open
evt.type=creat
evt.type=connect
```

More documented sysdig

```console
http://sysdigcloud.com/fascinating-world-linux-system-calls/
```

-----------------------------

# Disk I/O by process

```console
iotop -od5
```

-----------------------------

# Kernel slab allocator usage top

```console
slabtop -sc
```

-----------------------------

# Read statistics directly

```console
cat /proc/meminfo
cat /proc/vmstat
```

-----------------------------

# Understand how your application works

```console
perf stat COMMAND
```

-----------------------------

# Ps

To See Threads ( LWP and NLWP) and arguments

```console
ps -AlFH
```

Set Output In a User-Defined Format

```console
ps -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,wchan:14,comm
ps axo stat,euid,ruid,tty,tpgid,sess,pgrp,ppid,pid,pcpu,comm
ps -eopid,tt,user,fname,tmout,f,wchan
Display Only The Process IDs of Lighttpd
```

Find Out The Top 10 Memory Consuming Process

```console
ps auxf | sort -nr -k 4 | head -10
```

Find Out top 10 CPU Consuming Process

```console
ps auxf | sort -nr -k 3 | head -10
```

-----------------------------
