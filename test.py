from scapy.all import *
from Queue import Queue
import sys
import threading
import time

pkts=Queue()
with file("/home/atticus/Desktop/log.txt",'w') as f:
	f.write("")

def validAscii(h):
	if int(h,16)>31 and int(h,16)<127:
		return True
	return False

def readable(data):
	a=""
	for i in range(0,len(data)/2):
		if validAscii(data[i*2:i*2+2]):
			a+=data[i*2:i*2+2].decode("hex")
		#else:
			#a+=data[i*2:i*2+2]
	return a

def isTDS(data):
	if len(data)<51:
		return False
	tcpHeader=data[:40]
	tdsHeader=data[41:100]
	query=data[100:]
	println("TCP Header:\t%s\nTotal len:\t%s\nHeader len1:\t%s\nHeader len2:\t%s\nQuery:\t%s\n"%(tcpHeader,tdsHeader[3:7],tdsHeader[15:17],tdsHeader[23:25],readable(query)))
	
def println(s):
	with file("/home/atticus/Desktop/log.txt",'a') as f:
		f.write(s)
	print s

def scout():
	sniff(prn=pushToQueue,filter="tcp and host 192.168.37.135",store=0)

def pushToQueue(pkt):
	global pkts
	pkts.put(pkt)

def log():
	global pkts
	while True:
		while not pkts.empty():
			pkt=pkts.get()
			#println("--RAW PACKET--\n%s\n"%str(pkt.payload.payload).encode("hex"))
			#println("READABLE PACKET\n%s\n"%readable(str(pkt.payload.payload).encode("hex")))
			isTDS(str(pkt.payload.payload).encode("hex"))

def main():
	t1 = threading.Thread(target=scout)
	t1.start()
	t2 = threading.Thread(target=log)
	t2.start()

if __name__ == "__main__":
	main()
