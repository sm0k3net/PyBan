import os, sys, re
from collections import Counter
from subprocess import call

PATH = sys.argv[1]
TYPE = sys.argv[2]
ACTION = sys.argv[3]

if TYPE == 'access':
	log = 'access.log'
elif TYPE == 'error':
	log = 'error.log'

f = open(PATH+log, 'r')
ipList = []

sql_match = '(.+(POST\s+|GET\s+|HEAD\s+|PUT\s+|OPTION\s+).+(\?|=|\+|\W)((S|s)(E|e)(L|l)(E|e)(C|c)(T|t)|(V|v)(E|e)(R|r)(S|s)(I|i)(O|o)(N|n)\(\)|(G|g)(R|r)(O|o)(U|u)(P|p)\_(C|c)(O|o)(N|n)(C|c)(A|a)(T|t)).+)'
xss_match = '(.+(POST\s+|GET\s+|HEAD\s+|PUT\s+|OPTION\s+).+?=.+?((S|s)(C|c)(R|r)(I|i)(P|p)(T|t)|(S|s)(E|e)(L|l)(F|f)|(A|a)(L|l)(E|e)(R|r)(T|t)).+?HTTP/[0-9]\.[0-9].+)'

time_regex = re.compile("([0-9]{2}:[0-9]{2}:[0-9]{2}\s+)")
date_regex = re.compile("((\d{2}|\d{4})/(\d{2}|\w{3})/(\d{2}|\d{4}))(?:\:|\s+)")
ip_regex = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
ip_regsearch = re.compile(ip_regex)
sql_payload_regex = re.compile("((POST\s+|GET\s+|HEAD\s+|PUT\s+|OPTION\s+).+(\?|=|\+|\W)((S|s)(E|e)(L|l)(E|e)(C|c)(T|t)|(V|v)(E|e)(R|r)(S|s)(I|i)(O|o)(N|n)\(\)|(G|g)(R|r)(O|o)(U|u)(P|p)\_(C|c)(O|o)(N|n)(C|c)(A|a)(T|t)).+)")
xss_payload_regex = re.compile("((POST\s+|GET\s+|HEAD\s+|PUT\s+|OPTION\s+).+?=.+?((S|s)(C|c)(R|r)(I|i)(P|p)(T|t)|(S|s)(E|e)(L|l)(F|f)|(A|a)(L|l)(E|e)(R|r)(T|t)|(J|j)(A|a)(V|v)(A|a)(S|s)(C|c)(R|r)(I|i)(P|p)(T|t)\:|(X|x)(S|S)(S|s)).+?HTTP/[0-9]\.[0-9].+)")



if ACTION == 'ban':
	for st in f.read().split('\n'):
		if re.match(sql_match, st)	or re.match(xss_match, st):
			st = st.split('-')[0].strip(' ')
			if (re.match(ip_regex, st)):
				ipList.append(st.replace(',', '').replace(']', ''))

	c = Counter(ipList)

	for i in set(ipList):
		#print(i + ' - ' + str(c[i]))
		if c[i] >= 3:
			call(["iptables", "-A", "INPUT", "-s", i, "-j", "DROP"])
			print("Banned IP: " + i + ' | Times detected: ' + str(c[i]))

elif ACTION == 'log':
	logs = open('pyban.log', 'w')
	for line in f.read().split('\n'):
		if re.match(sql_match, line) or re.match(xss_match, line):
			dateData = date_regex.search(line)
			timeData = time_regex.search(line)
			ipData = ip_regsearch.search(line)
			if re.match(sql_match, line):
				payloadType = "SQL Injection"
				payloadData = sql_payload_regex.search(line)
			elif re.match(xss_match, line):
				payloadType = "XSS"
				payloadData = xss_payload_regex.search(line)

			
			#inputData = "["+payloadType+"] "+dateData.group(0)+" | "+timeData.group(0)+" | "+ipData.group(0)+" | "+payloadData.group(0)
			#for dataLine in line:
			logs.write("["+payloadType+"] "+dateData.group(0)+" | "+timeData.group(0)+" | "+ipData.group(0)+" | "+payloadData.group(0)+"\n")
	logs.close()
			#print "["+payloadType+"] "+dateData.group(0)+" | "+timeData.group(0)+" | "+ipData.group(0)+" | "+payloadData.group(0)
