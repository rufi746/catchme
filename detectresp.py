#!/usr/bin/env python
import os 
import subprocess 
import sys
import socket 
import netifaces
import netaddr
from scapy.all import * 
from multiprocessing import Process
import logging
import logging.handlers
import string
import fcntl
import datetime
import threading
#SETS LOGGING FOR OUT TO SYSLOG
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s', datefmt='%m-%d %H:%M', filename='/home/.../Documents/resp.log', filemode='w')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
#grab interface settings for IP and BCAST
def netaddr():
	global ifaces 
	global addr 
	global broadcast
	global intf
	global intb	
	os.system('clear')
	print "Interfaces Found: " 
	if netifaces is None:
		raise RuntimeError('netifaces unavailable')
	for iface in netifaces.interfaces():
		interface = netifaces.ifaddresses(iface)
		if netifaces.AF_INET in interface:
			for af_inet_info in interface[netifaces.AF_INET]:
				#print af_inet_info
				addr = af_inet_info.get('addr', None)
				peer = af_inet_info.get('peer', None)
				broadcast = af_inet_info.get('broadcast', None)
				if addr is not None and broadcast is not None:
					#print iface
					#print addr
					#print broadcast
	#				ilist = [addr] 
	#				for i in ilist:
	#					print i
					ilist2 = [iface]
					for it in ilist2:
						print it
					ilist3 = [broadcast]
					for itw in ilist3:
						print itw
	print " " 
	intf = raw_input("Select interface: ") 
	intb = raw_input("Select Broadcast: ")	
	hw = intf
	conf.iface = intf
	conf.chekIPaddr = False
	pkt()
def getIP(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
#GENEREATE RANDOM STRING FOR FILESHARE
def rando(length):
	return ''.join(random.choice(string.lowercase) for i in range(length))
def pkt():
	global myip
	global ether
	global udp
	global nsquery
	global nbns
	global nbns2	
	myip = getIP(intf)
	ether = Ether(dst='ff:ff:ff:ff:ff:ff')
	#ip = IP(src=myip, dst='255.255.255.255')
	udp = UDP(sport=137, dport=137)
	nsquery = rando(16)
	nsquery2 = "WPAD"
	nbns = IP(src=myip, dst=intb)/UDP(sport=137, dport='netbios_ns')/NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME=nsquery, QUESTION_TYPE='NB')
	nbns2 = IP(src=myip, dst=intb)/UDP(sport=137, dport='netbios_ns')/NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME=nsquery2, QUESTION_TYPE='NB')
	main()
#SENDS REQUESTS FOR RANDOM FILESHARE AND LISTEN FOR RESPONSE on 137
def randoP():
	while 1:
		send(nbns,verbose=0) #removed this ,multi=True timeout=10
		#nbns.show()		
def wpad():
	while 1:
		send(nbns2,verbose=0)
		#nbns2.show()
		
#RUN BOTH FUNCTIONs IN PARallel
def capture():
	tcpd = subprocess.Popen(['sudo', 'tcpdump', '-v', '-i', 'eth0', 'port', '137', 'and', 'udp'], stdout=subprocess.PIPE)
	rex = re.compile(r'\[(.*?)\]')	
	for row in iter(tcpd.stdout.readline, b''):
		strip = row.rstrip()
		#print strip
		getr = rex.match(strip)
		#print getr
		if getr == 0x8500:
		#	logger1 = logging.getLogger('RandomString: ')
			print logger1.critical('A spoofed NBNS response for %s was detected by %s at %s from host %s - %s\n' %(nsquery, myip, str(now2), nbns.getlayer(ip), nbns.getlayer(ether)))
		else: 
		#print nbns.summary()
			print "No response...."
			time.sleep(2) 
def main():
	
	try:
		t = threading.Thread(target=randoP)
		#t2 = threading.Thread(target=wpad)
		t.start()
		capture()
		#t2.start()		
	except KeyboardInterrupt:
		print "\nStopping Server and Exiting...\n"
		#t.stop()
		now3 = datetime.datetime.now()
netaddr()	
