from scapy.all import *
from Queue import Queue
import sys
import threading
import time
import pytds

pkts=Queue()
with file("/home/atticus/Desktop/log.txt",'w') as f:
	f.write("")
	
def println(s):
	with file("/home/atticus/Desktop/log.txt",'a') as f:
		f.write(s)
	print(s)

class Parse(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.die = False

	def run(self):
		global pkts
		while not self.die:
			if not pkts.empty():
				log(pkts.get())

	def log(self,pkt):
		if pkt.payload.payload.sport == 1433:
			self.parseResp(str(pkt.payload.payload)[20:])
		elif pkt.payload.payload.dport == 1433:
			self.parseReq(str(pkt.payload.payload)[20:])

	def validAscii(self,h):
		if int(h,16)>31 and int(h,16)<127:
			return True
		return False

	def readable(self,data):
		a=""
		for i in range(0,len(data)/2):
			if validAscii(data[i*2:i*2+2]):
				a+=data[i*2:i*2+2].decode("hex")
			#else:
				#a+=data[i*2:i*2+2]
		return a

	def parseReq(self,data):
		println("\n--Req--\n%s\n"%readable(data.ecode('hex')))

	def parseResp(self,data):
		tdssock = pytds._TdsSocket(data)
		try:
			while True:
				tdssock._main_session.find_result_or_done()
		except:
			pass

		try:
			resp=tdssock._main_session.messages[0]['message']
		except:
			pass

		for a in tdssock._main_session.results:
			resp+=str(a)+"\n"
		println("--Resp--\n%s"%resp)

class Scout(threading.Thread):
	def __init__(self):
			threading.Thread.__init__(self)
			self.die = False
		
	def run(self):
		self.scout()

	def scout(self):
		while not self.die:
			sniff(prn=pushToQueue,filter="tcp and host 192.168.37.135",store=0,count=1)

	def pushToQueue(self,pkt):
		global pkts
		pkts.put(pkt)

def main():
	t1 = Scout()
	t1.start()
	t2 = Parse()
	t2.start()

	try:
		#join threads
	except KeyboardInterrupt:
		print('[!] Keyboard interrupt received. Shutting down...')
		t1.die=True
		t2.die=True
	
if __name__ == "__main__":
	main()
