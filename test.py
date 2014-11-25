from scapy.all import *
from Queue import Queue
import sys
import threading
import time
import pytds

pkts=Queue()
with file("/home/atticus/Desktop/log.txt",'w') as f:
	f.write("")

class Parse(threading.Thread):
	#need to be able to set MTU from cmdline
	def __init__(self,mtu=1500):
		threading.Thread.__init__(self)
		self.die = False
		self.mtu = mtu
		self.frag = {}

	def run(self):
		global pkts
		while not self.die:
			if not pkts.empty():
				self.parse(pkts.get())

	def parse(self,pkt):
		if pkt.payload.payload.sport == 1433:
			#reassesmble fragged pkts
			key='%s:%s'%(pkt[IP].dst,pkt[TCP].dport)
			if len(str(pkt[IP])) == self.mtu:
				try:
					self.frag[key]+=str(pkt[TCP])[20:]
				except KeyError:
					self.frag[key]=str(pkt[TCP])[20:]
			else:
				try:
					self.parseResp(self.frag[key]+str(pkt[TCP])[20:])
				except KeyError:
					self.parseResp(str(pkt[TCP])[20:])
		elif pkt.payload.payload.dport == 1433:
			self.parseReq(str(pkt[TCP]).encode('hex')[40:])

	def validAscii(self,h):
		if int(h,16)>31 and int(h,16)<127:
			return True
		return False

	def readable(self,data):
		a=""
		for i in range(0,len(data)/2):
			if self.validAscii(data[i*2:i*2+2]):
				a+=data[i*2:i*2+2].decode("hex")
			#else:
				#a+=data[i*2:i*2+2]
		return a

	def parseReq(self,data):
		self.println("\n--Req--\n%s\n"%self.readable(data))

	def parseResp(self,data):
		resp=''
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

		if len(resp) == 0:
			resp = 'error parsing response'
		self.println("--Resp--\n%s"%resp)

	def println(self,s):
		with file("/home/atticus/Desktop/log.txt",'a') as f:
			f.write(s)
		print(s)

class Scout(threading.Thread):
	def __init__(self):
			threading.Thread.__init__(self)
			self.die = False
		
	def run(self):
		self.scout()

	def scout(self):
		while not self.die:
			try:
				sniff(prn=self.pushToQueue,filter="tcp and host 192.168.37.135",store=0,timeout=5)
			except:
				self.die = True

	def pushToQueue(self,pkt):
		global pkts
		pkts.put(pkt)

class Pillage(threading.Thread):
	def __init__(self):
			threading.Thread.__init__(self)
			self.die = False

	def run(self):
		while not self.die:
			query = raw_input("[*] Enter query to run:")
			print('Command added to queue:\n%s'%query)

def main():
	print('==Welcome to SQLViking!==\n[*] Starting up sniffer')#\n[*]ctrl+q to run SQL query')

	t1 = Scout()
	t2 = Parse()
	#t3 = Pillage()
	t1.start()
	t2.start()
	#t3.start()

	try:
		while True:
			t1.join(1)
			t2.join(1)
			#t3.join(1)
	except KeyboardInterrupt:
		print('\n[!] Keyboard interrupt received. Shutting down...')
		t1.die=True
		t2.die=True
		#t3.die=True
	
if __name__ == "__main__":
	main()
