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
			a+=data[i*2:i*2+2]
			#print "%s:%s:%s"%(data[i*2:i*2+2],int(data[i*2:i*2+2],16),data[i*2:i*2+2].decode("hex"))
	return a.decode("hex")

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
			#println("pkt\n%s\n"%pkt)
			println("PACKET\n%s\n"%readable(str(pkt.payload.payload).encode("hex")))

def main():
	t1 = threading.Thread(target=scout)
	t1.start()
	t2 = threading.Thread(target=log)
	t2.start()

if __name__ == "__main__":
	main()
