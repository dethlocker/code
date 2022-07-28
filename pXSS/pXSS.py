# pXSS is a simple Python script that parses a payloads text file for all possible
# XSS payloads and WAF evasion included. Development version, and just publicizing
# some simple auditing tools for web application testing.

# pXSS checks for XSS vulnerabilities on a target web application from list of XSS payloads you provided
# Requires: Python 3 and bs4 module (pip install bs4)
# Run : $ python pXSS.py http://example.com <vuln_page> <XSS_payloads_list.txt> <HTTP_request_type>
# Example: $ python pXSS.py http://example.com test.php payloads.txt POST
# Payloads file (payloads.txt) included for parsing

__author__ = "Felix Alcala"
__copyright__ = "Copyleft 2022, Felix Alcala"
__credits__ = ["Felix Alcala"]
__license__ = "GPL"
__version__ = "0.2a"
__maintainer__ = "dethlocker"
__email__ = "dethlocker@0xdeadbeef.ai"
__status__ = "DevSoup"

import sys
import requests
import re
from bs4 import BeautifulSoup
import html

host = sys.argv[1]
page = sys.argv[2]
payloads = sys.argv[3]
http_type = sys.argv[4]

# print header
print("----------------------------------------")
print("# URL: " + host )
print("# listing: " + "/" + page )
print("----------------------------------------")

def attack(formvars, payload):
	payload_return = []
	params = {}
	if formvars != "":
		if http_type.lower() == 'post':
			for name, value in formvars.items():
				params.update({ name : payload })
				print(params)

		print("-------payload----------")
		print(payload)
		print("-------formvars----------")
		print(params)
		requests_payload = requests.post(host+"/"+page, params)
	else:
		requests_payload = requests.post(host+"/"+page)
	for response in requests_payload.history:
		requests_status = response.status_code
		soup = BeautifulSoup(response.content, 'html.parser')
		find_payload = html.unescape(soup.get_text())
		find_payload = find_payload.replace("&#43;","+")
		find_payload = find_payload.replace("&#96;","`")
		find_pattern = re.compile('(WAF|access|vulnerable|hacked|through|error|alert|injected|success|denied|mind)|('+re.escape(payload)+')')
		if re.findall(find_pattern, find_payload):
			print("* Matched: " + payload + " Status: " + str(requests_status) + " Payload: " + payload )
		else:
			pass

def fetchpage(page):
	forms = []
	get_page = requests.get(host+"/"+page)
	soup = BeautifulSoup(get_page.content, 'html.parser')
	forms = soup.find_all('form')
	for form in forms:
		formvars = {}
		print("----------------------------------------")
		for i in form:
			print(i)
		action = form.get('action')
		if action == None:
			action = page
		input_fields = form.find_all('input')
		if input_fields != None:
			for input_field in input_fields:
				try:
					input_type = input_field.get('type')
					name = input_field.get('name')
					value = input_field.get('value')
					# print(input_type + " - " + name + " - "+ value)
					# print(input_type + " - " + name)
					if value == None:
						value = ""
					formvars.update({ name : value })
				except:
					pass
		#print(formvars)
		print("----------------------------------------")

		# get form method
		if http_type.lower() == 'post':
			method = 'POST'
		else:
			method = 'GET'

		print('# method: ' + method)
		# load payload
		print>>sys.stderr, "open payload file"
		with open(payloads, 'r') as xs:
			for payload in xs:
				payload = payload.strip()
				xss = attack(formvars, payload)

fetchpage(page)
