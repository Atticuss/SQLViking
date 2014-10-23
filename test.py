from scapy.all import *
from Queue import Queue
import threading
import time

with file("/home/atticus/Desktop/log.txt",'w') as f:
	f.write("")

def validAscii(h):
	if int(h)>19 and int(h)<127:
		return True
	return False

def hdecode(data):
	a=""
	for i in range(0,len(data)/2-2):
		if validAscii(data[i:i+2]):
			a+=data[i:i+2]
	return a.decode("hex")

def println(s):
	with file("/home/atticus/Desktop/log.txt",'a') as f:
		f.write(s)
	print s

def scout(pkts):
	while True:
		pkt = sniff(filter="tcp and host 192.168.37.1", count=1)
		pkts.put(pkt)

def log(pkts):
	while True:
		while pkts.qsize()>1:
			pkt=pkts.get()
			try:
				println("---PACKET---\n%s\n"%hdecode(pkt[0][TCP].load.encode("hex")))	
			except:
				println("PACKET ERROR\n%s\n"%pkt[0])

def main():
	pkts = Queue()
	t1 = threading.Thread(target=scout,args=(pkts,))
	t1.start()
	t2 = threading.Thread(target=log,args=(pkts,))
	t2.start()

if __name__ == "__main__":
	main()
