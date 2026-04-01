# HTTP READY

Function to detect all ports responding to http and https requests during a pentest

During some pentest, some ports are not detected by nmap as http ore https ports the objective of this  scripts is to detect ports responding to this requests

With hosts

```bash
╭─tuxvador@tuxvador-pentest /home/tuxvador/Documents/functions
╰─$ bash http_ready.sh
Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0
Hosts(s) : 192.168.1.254
192.168.1.254
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-25 11:40 CET
Stats: 0:01:00 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 62.08% done; ETC: 11:41 (0:00:37 remaining)
Nmap scan report for mabbox.bytel.fr (192.168.1.254)
Host is up (0.75s latency).
Not shown: 996 closed ports
PORT     STATE    SERVICE
53/tcp   open     domain
80/tcp   open     http
443/tcp  open     https
5060/tcp filtered sip

Nmap done: 1 IP address (1 host up) scanned in 100.15 seconds
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.254 Port :443  +++ https://192.168.1.254:443 --- https_code : 302
╭─tuxvador@tuxvador-pentest /home/tuxvador/Documents/functions
╰─$ cat http_ready.txt
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.254 Port :443 +++ http://192.168.1.254:443 --- http_code : 000
Host : 192.168.1.254 Port :443  +++ https://192.168.1.254:443 --- https_code : 302
Host : 192.168.1.254 Port :53 +++ http://192.168.1.254:53 --- http_code : 000
Host : 192.168.1.254 Port :5060 +++ http://192.168.1.254:5060 --- http_code : 000
Host : 192.168.1.254 Port :80  +++ https://192.168.1.254:80 --- https_code : 000
Host : 192.168.1.254 Port :53  +++ https://192.168.1.254:53 --- https_code : 000
Host : 192.168.1.254 Port :5060  +++ https://192.168.1.254:5060 --- https_code : 000
```
With file :
```bash
Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0
Hosts(s) : hosts.txt
192.168.1.30
192.168.1.65
192.168.1.74
192.168.1.254
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-25 11:51 CET
Stats: 0:01:00 elapsed; 0 hosts completed (4 up), 4 undergoing Connect Scan
Connect Scan Timing: About 90.81% done; ETC: 11:52 (0:00:06 remaining)
Nmap scan report for 192.168.1.30
Host is up (0.0096s latency).
Not shown: 997 closed ports
PORT      STATE SERVICE
80/tcp    open  http
3333/tcp  open  dec-notes
49152/tcp open  unknown

Nmap scan report for 192.168.1.65
Host is up (0.044s latency).
Not shown: 997 closed ports
PORT      STATE SERVICE
9080/tcp  open  glrpc
9999/tcp  open  abyss
49152/tcp open  unknown

Nmap scan report for 192.168.1.74
Host is up (0.00012s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE
4000/tcp open  remoteanything

Nmap scan report for mabbox.bytel.fr (192.168.1.254)
Host is up (0.0035s latency).
Not shown: 996 closed ports
PORT     STATE    SERVICE
53/tcp   open     domain
80/tcp   open     http
443/tcp  open     https
5060/tcp filtered sip

Nmap done: 4 IP addresses (4 hosts up) scanned in 100.72 seconds
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.65 Port :49152 +++ http://192.168.1.65:49152 --- http_code : 404
Host : 192.168.1.65 Port :9080 +++ http://192.168.1.65:9080 --- http_code : 200
Host : 192.168.1.65 Port :9999 +++ http://192.168.1.65:9999 --- http_code : 403
Host : 192.168.1.30 Port :80 +++ http://192.168.1.30:80 --- http_code : 200
Host : 192.168.1.254 Port :443  +++ https://192.168.1.254:443 --- https_code : 302
Host : 192.168.1.30 Port :49152 +++ http://192.168.1.30:49152 --- http_code : 404
╭─tuxvador@tuxvador-pentest /home/tuxvador/Documents/functions
╰─$ cat http_ready.txt
Host : 192.168.1.30 Port :3333 +++ http://192.168.1.30:3333 --- http_code : 000
Host : 192.168.1.254 Port :443 +++ http://192.168.1.254:443 --- http_code : 000
Host : 192.168.1.254 Port :80 +++ http://192.168.1.254:80 --- http_code : 302
Host : 192.168.1.65 Port :49152 +++ http://192.168.1.65:49152 --- http_code : 404
Host : 192.168.1.65 Port :9080 +++ http://192.168.1.65:9080 --- http_code : 200
Host : 192.168.1.65 Port :9999 +++ http://192.168.1.65:9999 --- http_code : 403
Host : 192.168.1.65 Port :49152  +++ https://192.168.1.65:49152 --- https_code : 000
Host : 192.168.1.65 Port :9080  +++ https://192.168.1.65:9080 --- https_code : 000
Host : 192.168.1.30 Port :80 +++ http://192.168.1.30:80 --- http_code : 200
Host : 192.168.1.65 Port :9999  +++ https://192.168.1.65:9999 --- https_code : 000
Host : 192.168.1.30 Port :80  +++ https://192.168.1.30:80 --- https_code : 000
Host : 192.168.1.254 Port :443  +++ https://192.168.1.254:443 --- https_code : 302
Host : 192.168.1.30 Port :49152 +++ http://192.168.1.30:49152 --- http_code : 404
Host : 192.168.1.74 Port :4000 +++ http://192.168.1.74:4000 --- http_code : 000
Host : 192.168.1.30 Port :3333  +++ https://192.168.1.30:3333 --- https_code : 000
Host : 192.168.1.74 Port :4000  +++ https://192.168.1.74:4000 --- https_code : 000
Host : 192.168.1.254 Port :5060 +++ http://192.168.1.254:5060 --- http_code : 000
Host : 192.168.1.254 Port :53 +++ http://192.168.1.254:53 --- http_code : 000
Host : 192.168.1.254 Port :80  +++ https://192.168.1.254:80 --- https_code : 000
Host : 192.168.1.30 Port :49152  +++ https://192.168.1.30:49152 --- https_code : 000
Host : 192.168.1.254 Port :5060  +++ https://192.168.1.254:5060 --- https_code : 000
Host : 192.168.1.254 Port :53  +++ https://192.168.1.254:53 --- https_code : 000
```