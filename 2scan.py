#!/usr/bin/env python

import thread
from time import strftime, sleep
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys

#user defined excpetion
class userDefined(Exception):
	pass
class rangeMiss(userDefined):
	pass

#open a file to write scan results to
fdesc = open("scan_results.txt","a")

def scan(sub_range, min_port_num, max_port_num):
	#scan logic here
	for dst_ip in sub_range:
		src_port = RandShort()
		if (dst_ip == max_ip):
			flag = 0
		for dst_port in range(min_port_num, (max_port_num+1)):
			scan_response = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=2)
			if (str(type(scan_response))=="<type 'NoneType'>"):
#				print "For IP: " + str(dst_ip) + " Port: " + str(dst_port) + " is filtered"
				pass
			elif(scan_response.haslayer(TCP)):
				if (str(scan_response.getlayer(TCP).flags) == "18"):					#SYNACK
					print "open!"
					sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=2)	#Send a RST if SYNACK is recvd
					print "For IP: " + str(dst_ip) + " Port: " + str(dst_port) + " port is open"
					write1 = str(dst_ip) + ":" + str(dst_port) + "==>" + " open" + "\n"
					fdesc.write(write1)
				elif(str(scan_response.getlayer(TCP).flags) == "20"): 				#RSTACK
					print "For IP: " + str(dst_ip) + " Port: " + str(dst_port) + " port is closed"
					write2 = str(dst_ip) + ":" + str(dst_port) + "==>" + " closed" + "\n"
					fdesc.write(write2)

try:
	IP_range = raw_input("[+]Enter the IP range: ")
	min_port_num = int(raw_input("[+]Enter the minimum port number: "))
	max_port_num = int(raw_input("[+]Enter the maximum port number: "))
	if (min_port_num > 0) and (max_port_num >= min_port_num):
		print "[+]All valid!"
		pass
	else:
		raise rangeMiss
except rangeMiss:
	print "[!]The port range is invalid!"
	print "[!]Exiting..."
	sys.exit(1)

except KeyboardInterrupt:
	print "[!]user requested exit..."
	sys.exit(1)

#Extracting the maximum and minimum IP from user input
max_ip = IP_range.split("-")[1]
min_ip = IP_range.split("-")[0]
IPList = []
#Creating list which includes all IPs as per user input
min_ip_last_octet = int(min_ip.split(".")[3])
max_ip_last_octet = int(max_ip.split(".")[3])
while (max_ip_last_octet >= min_ip_last_octet):
	a = min_ip.split(".")[0]
	b = min_ip.split(".")[1]
	c = min_ip.split(".")[2]
	intermediate_ip = a + "." + b + "." + c + "." + str(min_ip_last_octet)
	IPList.append(intermediate_ip)
	min_ip_last_octet += 1
#IPList "list" holds now the entire range of IP addresses from the user supplied data

ip_list_length = len(IPList)

c_1 = ip_list_length / 10
c_2 = ip_list_length % 10
iterations = c_1 + c_2

#print "Total iterations: " + str(iterations)

counter = 0
for x in range(0,iterations):
	#Dividng the entire IP list into smaller lists of 10 IPs
	sub_range = IPList[counter:counter+10]
	#Passing each smaller list to the thread module
	thread.start_new_thread(scan,(sub_range,min_port_num,max_port_num,))
	time.sleep(5)
	counter += 10

while True:
#	fdesc.close()
	pass

