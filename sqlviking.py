import sys,threading,time,logging,os,datetime
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

#when adding additional DBs, assign their value to the next unused prime number
UNKNOWN     = 1
REQUEST     = 2
RESPONSE    = 3
MYSQL       = 5
SQLSERV     = 7
MYSQLREQ    = MYSQL * REQUEST
MYSQLRESP   = MYSQL * RESPONSE
SQLSERVREQ  = SQLSERV * REQUEST
SQLSERVRESP = SQLSERV * RESPONSE

ISREQ     = lambda x: x % REQUEST == 0
ISRESP    = lambda x: x % RESPONSE == 0
ISMYSQL   = lambda x: x % MYSQL == 0
ISSQLSERV = lambda x: x % SQLSERV == 0

class Traffic():
	def __init__(self,query=None,result=None):
		self.query = query
		self.result = result
		self.timestamp = datetime.datetime.now()

class Conn():
    def __init__(self,cip,cport,db=UNKNOWN):
        self.cip     = cip
        self.cport   = cport
        self.db      = db
        self.traffic = []
        self.frag    = []
        #unused; implement later to increase dropped/out of order packet fault tolerance
        self.seq     = -1
        self.ack     = -1
        self.nextseq = -1
        self.neqack  = -1

class DataBase():
    def __init__(self,ip,port,dbtype,name=UNKNOWN):
        self.ip      = ip
        self.port    = port
        self.name    = name
        self.dbtype  = dbtype
        self.traffic = []
        self.users   = [] #unused currently

class Parse(threading.Thread):
    #TODO: need to be able to set MTU
    def __init__(self,mtu=1500):
        threading.Thread.__init__(self)
        self.die = False
        self.mtu = mtu
        self.frag = {}
        self.res = ''
        self.knownConns = []
        self.knownDBs = []
        self.knownDBServs = []
        with open('out.txt','w') as f:
            f.write('')

    def run(self):
        global pkts
        while not self.die:
            if not pkts.empty():
                self.handle(pkts.get())

    def fingerprint(self,pkt):
        pktType = self.isMySql(pkt)
        if pktType == UNKNOWN:
            pktType = self.isSqlServ(pkt)
        return pktType

    def parse(self,pkt,conn):
    	db = conn.db
        pktType = UNKNOWN
    	if db.dbtype == SQLSERV:
            if pkt[IP].src == db.ip:
                pktType = SQLSERVRESP
            else:
                pktType = SQLSERVREQ
        elif db.dbtype == MYSQL:
            if pkt[IP].src == db.ip:
                pktType = MYSQLRESP
            else:
                pktType = MYSQLREQ

        if pktType == MYSQLREQ:
            self.parseMySqlReq(str(pkt[TCP])[20:],conn)
        elif pktType == MYSQLRESP:
            self.parseMySqlResp(str(pkt[TCP])[20:],conn)
        elif pktType == SQLSERVREQ:
            self.parseSqlServReq(str(pkt[TCP])[20:],conn)
        elif pktType == SQLSERVRESP:
            self.parseSqlServResp(str(pkt[TCP])[20:],conn)
        else:
            self.printLn("[*] Unidentified Packet")
            self.printLn("[*] Raw:\t%s"%str(pkt[TCP][20:]).encode('hex'))
            self.printLn("[*] ASCII:\t%s"%self.readable(str(pkt[TCP])[20:].encode('hex')))

    def isMySql(self,pkt):
        encpkt = str(pkt[TCP])[20:].encode('hex')
        pktlen = len(encpkt)/2
        lengths = []
        payloads = []

        while len(encpkt)>0:
            length = int(self.flipEndian(encpkt[:6]),16)
            lengths.append(length)
            payloads.append(encpkt[8:8+(length*2)])
            encpkt = encpkt[8+(length*2):]

        tlen=0
        for l in lengths:
            tlen+=l
        tlen+= len(lengths)*4

        if tlen == pktlen and len(payloads) > 0:
            if self.isMySqlReq(payloads):
                return MYSQLREQ
            elif self.isMySqlResp(payloads):
                return MYSQLRESP
            else:
                return UNKNOWN
        else:
            return UNKNOWN

    def isMySqlReq(self,payloads):
        if payloads[0] == '0e': #COM_PING
            return True

    def isMySqlResp(self,payloads):
        if payloads[0] == '00000002000000': #OK RESP 
            return True
        elif payloads[0][:2] == 'ff': #ERR RESP
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

    def isKnownDB(self,pkt):
        for db in self.knownDBs:
            if pkt[IP].dst == db.ip and pkt[TCP].dport == dp.port and db.name == UNKNOWN:
                return db
            if pkt[IP].src == db.ip and pkt[TCP].sport == db.port and db.name == UNKNOWN:
                return db

    def addConn(self,pkt,db):
        if db:
            if pkt[IP].dst == db.port:
                c = Conn(pkt[IP].src,pkt[TCP].sport,db)
            else:
                c = Conn(pkt[IP].dst,pkt[TCP].dport,db)
            self.knownConns.append(c) 
            return c   	

    def delConn(self,conn):
        if len(conn.traffic) > 0:
            for t in conn.traffic:
                conn.db.traffic.append(t)
        self.knownConns.remove(conn)

    def handle(self,pkt):
        c = self.getConn(pkt)
        if c:
            if pkt[TCP].flags == "FA":
                self.delConn(c)
                return
            self.parse(pkt,c)
            return
        
        db = self.isKnownDB(pkt)
        if db:
            c = self.addConn(pkt,db)
            self.parse(pkt,c)
            return

        pktType = self.fingerprint(pkt)
        self.printLn("[*] Pkt found:\t%s"%pktType)
        ip, port, dbType = None, None, None
        if ISRESP(pktType):
            ip = pkt[IP].src
            port = pkt[TCP].sport
        elif ISREQ(pktType):
            ip = pkt[IP].dst
            port = pkt[TCP].dport

        if ISMYSQL(pktType):
            dbType = MYSQL
        elif ISSQLSERV(pktType):
            dbType = SQLSERV

        if ip and port and dbType:
            db = DataBase(ip=ip,port=port,dbtype=dbType)
            self.knownDBs.append(db)
            c = self.addConn(pkt,db)
            self.parse(pkt,c)
        else:
            self.printLn("ip and port and dbtype not successfully set:\t%s, %s, %s"%(ip,port,dbType))

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

    def printLn(self,msg):
        with open('out.txt','a') as f:
            f.write(msg+'\n')

    #calls to store() uses old method; need to change to new params
    #if database can be determined, create db if it doesn't exist or point to existing db
    #if user can be determined, update db.users
    def parseMySqlReq(self,data,conn):
        self.printLn("\n--MySQL Req--\n")
        data = data.encode('hex')
        pktlen = len(data)/2
        lengths=[]
        while len(data)>0:
            length = int(self.flipEndian(data[:6]),16)
            lengths.append(length)
            self.printLn("SubPacket Raw:\t%s"%data[8:8+(length*2)])
            self.printLn("SubPacket ASCII:\t%s"%self.readable(data[8:8+(length*2)]))
            data = data[8+(length*2):]
        #self.store(parseddata,MYSQLREQ,conn)    
        #data = data.encode('hex')        

    def parseMySqlResp(self,data,conn):
        self.printLn("\n--MySQL Resp--\n")
        #self.store('[*] Raw:\t%s'%str(data).encode('hex'))
        encdata = data.encode('hex')
        pktlen = len(encdata)/2
        lengths=[]
        while len(encdata)>0:
            length = int(self.flipEndian(encdata[:6]),16)
            lengths.append(length)
            self.printLn("SubPacket Raw:\t%s"%encdata[8:8+(length*2)])
            self.printLn("SubPacket ASCII:\t%s"%self.readable(encdata[8:8+(length*2)]))
            encdata = encdata[8+(length*2):]

        res = connections.MySQLResult(connections.Result(data))
        try:
            res.read()
            self.printLn('[*] Message:\t%s'%str(res.message))
            self.printLn('[*] Description:\t%s'%str(res.description))
            self.printLn('[*] Rows:')
            if len(res.rows)>0:
                for r in res.rows:
                    self.printLn(self.formatTuple(r))
        except:
            self.printLn('[!] Error:\t%s'%sys.exc_info()[1])
        self.printLn('[*] Raw:\t%s\n'%str(data).encode('hex'))

    def parseSqlServReq(self,pkt,conn):
    	data = str(pkt[TCP][20:]).encode('hex')
        self.store("\n--SQLServ Req--\n%s\n"%self.readable(data))

    def parseSqlServResp(self,pkt,conn):
    	data = str(pkt[TCP])[20:]
        resp = sqlserver.Response(data)
        resp.parse()
        
        if len(resp.messages) > 0:
            self.store("--SQLServ Resp--\n%s"%resp.messages[0]['message'])
        else:
            self.store("--SQLServ Resp--\n%s"%resp.results)

    def store(self,data,pktType,conn):
        if conn.db.name == UNKNOWN: #schema unknown, track traffic in conn
            if ISRESP(pktType) and conn.traffic[-1].result == None: #is result
                conn.traffic[-1].result = data
            elif ISRESP(pktType): #is result, missed query
                conn.traffic.append(Traffic(result=data))
            else: #is query
                conn.traffic.append(Traffic(query=data))
        else: #schema known, track traffic in conn.db
            if len(conn.traffic) > 0:
                for t in conn.traffic:
                    conn.db.traffic.append(t)
                conn.traffic = []
            if ISRESP(pktType) == conn.db.ip and conn.db.traffic[-1].result == None: #is result
                conn.db.traffic[-1].result = data
            elif ISRESP(pktType) == conn.db.ip: #is result, missed query
                conn.db.traffic.append(Traffic(result=data))
            else: #is query
                conn.db.traffic.append(Traffic(query=data))

    #no longer functions; Parse.res attr deprecated
    def writeln(self,path):
        pass
        #with file(path,'w') as f:
        #    f.write(self.res)

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

    t1 = Scout()
    t2 = Parse()
    t3 = Pillage()
    t1.start()
    t2.start()
    t3.start()

    while True:
        #printMainMenu()
        try:
            #parseInput(raw_input("\n> "),t2)
            time.sleep(1)
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
