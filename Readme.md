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

From this I noted open ports to check out being 111, 80, 139, 445.

I like to leave webservers to be the last port to check out because they tend to take the most effort.  It is smart to start gobuster running while enumerating other services

To enumerate port 111 I ran rpcinfo  


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
