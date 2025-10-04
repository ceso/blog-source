---
title: "General"
date: 2025-10-04
draft: false
type: wiki
---

# User. Run command as different user with /bin/nologin

```console
sudo -u user <command>
su -m user -c 'command'
```

-----------------------------

# Run Levels - get current runlevel

```console
runlevel
```

-----------------------------

# Crontab

https://crontab.guru/

-----------------------------

# Filesystem

## Filesystem tuning

```console
tune2fs -c 0 /dev/hda1 => Set number of mounts between checks. 0 is disable

blkid /dev/hda1        => Get the filesystem id:
findfs UUID=d40acb36-5f32-4832-bf1a-80c67833a618 => reverse uuid lookup

ls -l /dev/disk/by-*/  => List by different types:
```

## List filesystems suppported

```console
cat /proc/filesystems
```

-----------------------------

# Kernel

## Check shared memory

```console
ipcs
```

## Check current max and min

```console
/proc/sys/kernel
sysctl -a
```

## Change parameters

```console
sysctl -p /etc/sysctl.conf
```

-----------------------------

# Flush Disk Cache

```console
echo 3 | sudo tee /proc/sys/vm/drop_caches
```

-----------------------------

# See video in youtube

```console
mplayer $(youtube-dl -g https://www.youtube.com/watch?v=hqtZnJg9TM0)
```

-----------------------------

# Create a socks proxy with ssh

```console
ssh -v -D 4545 USER@WTF_DESKTOP
```

## Local port forwarding: allows you connect from your local computer to another server

```console
ssh -L 8080:www.ubuntuforums.org:80 host
```

## Sssh without prompting

```console
alias ssh='ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -q'
```

-----------------------------

# Change samba password

```console
smbpasswd -r london.net-a-porter.com -U <username> 
```

-----------------------------

# Hexdata to binary

```console
xxd bdata | xxd -r >bdata2
```

-----------------------------

# RAW data recovery

```console
foremost
```

-----------------------------

# Find latest files that changed in a dir and subdir

```console
find . -type f|xargs ls -alrt
```

-----------------------------

# Creating patches

```console
diff -Naur oldfile newfile > new-patch
diff <( ssh -nq lmn-prd-sendmailrelay001 cat /etc/mail/access ) <( ssh -qn prdlmn4912 cat /etc/mail/access )
```

Apply patches:

```console
patch -p0 < new-patch                  => -pN where N is to strip directory from header
```

-----------------------------

# Update ruby version

```console
update-alternatives --set ruby /usr/bin/ruby1.9.1
update-alternatives --config ruby 
update-alternatives --config gem 
```

-----------------------------

# Package manager

```console
yum provides <filename>
yum updateinfo -> Check what updates are needed
yum repolist
yum history
yum resolvedep libpanel.so.5
yum install /usr/bin/uuencode
yumdownloader --source ruby
repoquery --whatprovides system-release
repoquery --whatrequires system-release
repoquery --whatprovides /usr/bin/uuencode
repoquery -il sharutils -> list all files from an uninstalled package

find-repos-of-install  -> show package = repo relation
needs-restarting       -> show services that need restarting because of system update
```

-----------------------------

# Nmap

```console
nmap -Pn -sS  prdlamp01.breins.net         -> well known ports scan
nmap -sP 192.168.1.*                       -> Discover IPs
nmap -sV -T4 -F                            -> port scan including service versions
```

-----------------------------

# Wget full site

```console
$ wget \
  --recursive \
  --no-clobber \
  --page-requisites \
  --html-extension \
  --convert-links \
  --restrict-file-names=windows \
  --domains dacef.com \
  --no-parent \
  dacef.com
```

-----------------------------

# Flush DNS Cache

```console
/etc/init.d/nscd restart
/etc/init.d/dnsmasq restart
```

-----------------------------

# Measure requests per second on a log

```console
tail -f access.log | pv -l -i10 -r >/dev/null
```

-----------------------------

# Curl commands

```console
curl -o /dev/null -s -w "Time: %{time_total} %{http_code}\n" URL
curl -sL -w "%{http_code}\\n" www.example.com -o /dev/null
```

-----------------------------

# Temporary web server

```console
python -m http.sever <port>
```

-----------------------------

# Get your IP

```console
curl http://ipecho.net/plain
```

-----------------------------

# Get DNS

```console
nmcli dev list iface eth0 | grep IP4
nm-tool
```

-----------------------------

# Check if a server is idle by verifying connections

```console
syslog.conf:   kern.*          /var/log/iptables.log
iptables rule: iptables -A INPUT -i eth0 -m state --state NEW -j LOG
```

-----------------------------

# configure nat

```console
SRC=br0
DST=eth0
echo 1 > /proc/sys/net/ipv4/ip_forward
/sbin/iptables -t nat -A POSTROUTING -o $DST -j MASQUERADE
/sbin/iptables -A FORWARD -i $DST -o $SRC -m state --state RELATED,ESTABLISHED -j ACCEPT
/sbin/iptables -A FORWARD -i $SRC -o $DST -j ACCEPT
```

-----------------------------

# Redirect connection to internal server

```console
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.2.200:80
iptables -t nat -A POSTROUTING -j MASQUERADE
```

-----------------------------


# Configure port redirect to internal host

```console
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.168.56.202:443
iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 192.168.56.202:22
```

-----------------------------


# Ubuntu network configuration

```console
auto eth0
iface eth0 inet static
  address 192.168.56.10
  netmask 255.255.255.0
  gateway 192.168.56.1 
  dns-nameservers 10.136.85.27 10.136.85.32
```

-----------------------------

# Dig get ttl

```console
dig +noauthority +noquestion +nostats URL @DNS-SERVER
```

-----------------------------

# Some tools to monitor network connections and bandwith

```console
'lsof -i' monitors network connections in real time
'iftop' shows bandwith usage per *connection*
'nethogs' shows the bandwith usage per *process*
```

-----------------------------

# Debian / Redhat package management

```console
Feature                              rpm                                   deb
----------------------------------------------------------------------------------
View all installed packages          rpm -qa                               dpkg --get-selections
View files in an installed package   rpm -ql packagename                   dpkg -L packagename
View files in an package file        rpm -qlp ./packagename.rpm            dpkg -c ./packagename.deb
View package info, installed package rpm -qi packagename (1)               dpkg -s packagename
View package info, package file      rpm -qip ./packagename.rpm (1)        dpkg -I ./packagename.deb
View pre/post install shell scripts  rpm -q --scripts packagename
View changelog for a package file    rpm -qp --changelog ./packagename.rpm 
Uninstall a package                  rpm -e packagename                    dpkg -r/dpkg -P
Install a package file               rpm -ivh ./packagename.rpm            dpkg -i
Upgrade a package from a file        rpm -Uvh ./packagename.rpm
Find which package owns a file       rpm -qif /some/file.foo
List dependencies of a package       rpm -q --requires packagename
List dependencies of a package file  rpm -qp --requires ./packagename.rpm
View all installed packages          rpm -qa                               dpkg -l, dpkg-query -Wf '${Package}\n'
View package info, installed package rpm -qi packagename (1)               apt-cache show packagename
View pre/post install shell scripts  rpm -q --scripts packagename          cat /var/lib/dpkg/info/packagename.{pre,post}{inst,rm}
View changelog for a package file    rpm -qp --changelog ./packagename.rpm dpkg-deb --fsys-tarfile packagename.deb | tar -O -xvf - ./usr/share/doc/packagename/changelog.gz | gunzip
Uninstall a package                  rpm -e packagename                    apt-get remove/purge packagename
Upgrade a package from a file        rpm -Uvh ./packagename.rpm            dpkg -i packagename.deb
Find which package owns a file       rpm -qif /some/file.foo               dpkg -S /dome/file.foo
List dependencies of a package       rpm -q --requires packagename         apt-cache depends package
List dependencies of a package file  rpm -qp --requires ./packagename.rpm  (shown in packages info)
```

-----------------------------

# Tcpdump headers for http

```console
tcpdump -s 1024 -l -A port 8912|grep GET
```

-----------------------------

# Whos there

```console
w
last
```

-----------------------------

# What was previously done?

```console
history
```

-----------------------------

# What's running 

```console
pstree -a
ps aux
ps -efx                       -> show all
ps axwef                      -> List processes tree with child processes
ps -eFL |grep activemq        -> List all threads
```

Single process CPU and Memory user

```console
top -u user
top -H -u user                -> Showing all threads information
top -p pid
```

-----------------------------

# Top RES VIRT SHR DATA

VIRT is virtual memory usage, it can probably be best described as the app's used address space - every library the app uses, every data it creates, everything is included here. If the app requests 100M memory from the kernel but actually uses only 1M, VIRT will still increase by 100M.

RES is resident memory usage, i.e. what's actually in the memory. In a way it could be probably used for measuring real memory usage of the app - if the app requests 100M memory from the kernel but actually uses only 1M, this should increase only by 1M. There are only two small problems, a) RES doesn't include memory that's swapped out (and no, the SWAP field in 'top' is not usable, it's completely bogus), b) some of that memory may be shared.

SHR is shared memory. Potentionally shared memory. I.e. memory that may be used not only by this particular app but also by some else. And actually it seems to be the shared part of RES - SHR goes down if the app will be swapped out, at least with recent kernels. I actually don't think it used to do that before, I used to measure unshared memory usage simply as VIRT-SHR and it seemed to give usable numbers. If it used to be always like this then I guess I must have produced a couple of bogus benchmarks in the past. Oh well.
It seems using the DATA field does the job of saying how much total unshared memory the app is using (if it's not visible it can be added using the 'f' key).

# Listening services

```console
netstat -tulapn|grep LISTEN
netstat -lnt4|grep -Eo '[0-9]{2,6} ' -> all ipv4 ports open
```

-----------------------------

# Graphical tools

```console
htop
glances
apachetop
iotop
```

-----------------------------

# Hardware

```console
lspci
dmidecode
ethtool
```

-----------------------------

# IO

```console
iostat -kxd 2
vmstat 2 10
mpstat 2 10
dstat --top-io --top-bio
pidstat -wt                   -> show interrupts per process
watch -tdn1 /proc/interfaces
```

## Find processes on uninterruptable state "D" (probably waiting for IO)

```console
ps -eo ppid,pid,user,stat,pcpu,comm,wchan:32|egrep " D| Z"
```

## Measure disk speed

```console
FILE=/tmp/dd-data.raw
dd if=/dev/zero of=$FILE bs=8k count=256k conv=sync; rm -rf $FILE
fio
```

-----------------------------

# mount points

```console
mount
cat /etc/fstab
vgs
pvs
lvs
df -h
lsof +D
```

-----------------------------

# Kernel, interrupts and network usage

```console
sysctl -a | grep ...
cat /proc/interrupts
cat /proc/net/ip_conntrack /* may take some time on busy servers */
netstat
ss -s
```

-----------------------------

# System logs and messages

```console
dmesg
less /var/log/messages
less /var/log/secure
less /var/log/auth
```

-----------------------------

# Sudoers

```console
USER ALL=(ALL)   NOPASSWD: ALL
```

-----------------------------

# LDAP

```console
ldapsearch -W -D 'cn=LDAPBIND,cn=Users,dc=london,dc=net-a-porter,dc=com' -b 'ou=Users,ou=Whiteleys,dc=london,dc=net-a-porter,dc=com' -H ldaps://dc01-pr-whi.london.net-a-porter.com
```

-----------------------------

# vmstat fields

```console
r: The number of processes waiting for run time.
b: The number of processes in uninterruptible sleep.
swpd: the amount of virtual memory used.
free: the amount of idle memory.
buff: the amount of memory used as buffers.
cache: the amount of memory used as cache.
inact: the amount of inactive memory. (-a option)
active: the amount of active memory. (-a option)
si: Amount of memory swapped in from disk (/s).
so: Amount of memory swapped to disk (/s).
bi: Blocks received from a block device (blocks/s).
bo: Blocks sent to a block device (blocks/s).
in: The number of interrupts per second, including the clock.
cs: The number of context switches per second.
us: Time spent running non-kernel code. (user time, including nice time)
sy: Time spent running kernel code. (system time)
id: Time spent idle.
wa: Time spent waiting for IO.
```

-----------------------------

# OpenSSL

## Create self signed certs for apache

```console
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/puppet/files/support.breins.net.key -out /etc/puppet/files/support.breins.net.pem
```

## And non interactive

```console
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" -keyout www.example.com.key  -out www.example.com.cert
```

## Check a Certificate Signing Request (CSR)

```console
openssl req -text -noout -verify -in CSR.csr
```

## Check a private key

```console
openssl rsa -in privateKey.key -check
```

## Connect to remote host and gather certificate

```console
openssl s_client -connect localhost:8140 -showcerts
```

## Check a certificate

```console
openssl x509 -in certificate.crt -text -noout
```

Check a PKCS#12 file (.pfx or .p12)

```console
openssl pkcs12 -info -in keyStore.p12
```

## Check SHA encryption

```console
openssl s_client -connect woodfordfunds.com:443|openssl x509 -text -in /dev/stdin | grep "Signature Algorithm"
```

## Remove passworrfd from key

```console
openssl rsa -in www.key -out new.key
```

-----------------------------

# NTP

```console
ntpdate pool.ntp.org
```

-----------------------------

# Schedule a job

```console
at 4:00pm
warning: commands will be executed using /bin/sh
at> do
at> reboot
at> done
C-D
echo "wget download-some-file-later" | at now + 1 day
echo "wget download-some-file-later" | at now + 2 months
echo "wget download-some-file-later" | at now + 1 year
echo "wget download-some-file-later" | at Friday
echo "wget download-some-file-later" | at Tuesday
echo "wget download-some-file-later" | at 6/1/11
echo "wget download-some-file-later" | at 5 pm 3/1/11
```

-----------------------------

# IMagemagick

```console
DISPLAY=:99 import -window root screenshot.png
```

-----------------------------
