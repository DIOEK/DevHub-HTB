# DevHub-HTB
'''text
sudo nmap -T4 --min-rate 1000 -A -sC -p22,80,6274 devhub.htb
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-31 08:43 -0300
Nmap scan report for devhub.htb (10.129.9.109)
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevHub - Internal Development Platform
6274/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Sun, 31 May 2026 11:43:18 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
|     <script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
|     <link rel="stylesheet" crossorigin href="/assets/index-XvFRNbCs.css">
|     </head>
|     <body>
|     <div id="root"></div>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Sun, 31 May 2026 11:43:18 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Sun, 31 May 2026 11:43:19 GMT
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6274-TCP:V=7.98%I=7%D=5/31%Time=6A1C1ED6%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,290,"HTTP/1\.1\x20200\x20OK\r\naccess-control-allow-credential
SF:s:\x20true\r\ncontent-length:\x20466\r\ncontent-type:\x20text/html;\x20
SF:charset=utf-8\r\nvary:\x20Origin\r\nDate:\x20Sun,\x2031\x20May\x202026\
SF:x2011:43:18\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<
SF:html\x20lang=\"en\">\n\x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\"\x20/>\n\x20\x20\x20\x20<link\x20rel=\"icon\"\x20type=\"image/
SF:svg\+xml\"\x20href=\"/mcp_jam\.svg\"\x20/>\n\x20\x20\x20\x20<meta\x20na
SF:me=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\
SF:"\x20/>\n\x20\x20\x20\x20<title>MCPJam\x20Inspector</title>\n\x20\x20\x
SF:20\x20<script\x20type=\"module\"\x20crossorigin\x20src=\"/assets/index-
SF:DRYhT9Xb\.js\"></script>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20crossorigin\x20href=\"/assets/index-XvFRNbCs\.css\">\n\x20\x20</head>
SF:\n\x20\x20<body>\n\x20\x20\x20\x20<div\x20id=\"root\"></div>\n\x20\x20<
SF:/body>\n</html>\n")%r(HTTPOptions,F0,"HTTP/1\.1\x20204\x20No\x20Content
SF:\r\naccess-control-allow-credentials:\x20true\r\naccess-control-allow-m
SF:ethods:\x20GET,HEAD,PUT,POST,DELETE,PATCH\r\nvary:\x20Origin\r\ncontent
SF:-type:\x20text/plain;\x20charset=UTF-8\r\nDate:\x20Sun,\x2031\x20May\x2
SF:02026\x2011:43:18\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPReques
SF:t,F0,"HTTP/1\.1\x20204\x20No\x20Content\r\naccess-control-allow-credent
SF:ials:\x20true\r\naccess-control-allow-methods:\x20GET,HEAD,PUT,POST,DEL
SF:ETE,PATCH\r\nvary:\x20Origin\r\ncontent-type:\x20text/plain;\x20charset
SF:=UTF-8\r\nDate:\x20Sun,\x2031\x20May\x202026\x2011:43:19\x20GMT\r\nConn
SF:ection:\x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP
SF:/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSS
SF:tatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConn
SF:ection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nConnection:\x20close\r\n\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (90%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%), Linux 4.19 (90%), Linux 5.0 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 6274/tcp)
HOP RTT       ADDRESS
1   72.12 ms  10.10.16.1
2   124.98 ms devhub.htb (10.129.9.109)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.23 seconds
'''
