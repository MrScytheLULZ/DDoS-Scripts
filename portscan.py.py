#!/usr/bin/env python
#Made By LiGhT

import socket, sys, os, threading

if len(sys.argv) < 5:
	sys.exit("Usage: python "+sys.argv[0]+" [start-range] [end-range] [port] [output-file]")
	sys.exit()

port = int(sys.argv[3])
outputF = sys.argv[4]

def ipRange(start_ip, end_ip):
	start = list(map(int, start_ip.split(".")))
	end = list(map(int, end_ip.split(".")))
	temp = start
	ip_range = []

	ip_range.append(start_ip)
	while temp != end:
		start[3] += 1
		for i in (3, 2, 1):
			if temp[i] == 256:
				temp[i] = 0
				temp[i-1] += 1
		ip_range.append(".".join(map(str, temp)))    

	return ip_range

class p0r75c4n(threading.Thread):
	def __init__ (self, ip):
		threading.Thread.__init__(self)
	def run(self):
		x = 1
		while x != 0:
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				result = sock.connect_ex((ip, port))
				if result == 0:
					os.system("echo "+ip+" >> "+outputF+"")
					print "\033[32mGood:\033[37m "+ip
				elif result != 0:
					print "\033[31mBad:\033[37m "+ip
				sock.close()
			except:
				pass
			x = 0
ip_range = ipRange("" +sys.argv[1], "" +sys.argv[2])
for ip in ip_range:
	try:
		t = p0r75c4n(ip)
		t.start()
	except:
		pass #MAY CRASH SERVER LMFAOOO DRUNK AF WHEN MADE THS