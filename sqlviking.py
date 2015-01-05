import sys,threading,time,logging,os,datetime,signal,binascii
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Queue import Queue
from sys import path
path.append("pytds/")
import sqlserver
path.append("databases/")
from constantvalues import *
import mysql

mysql = mysql.MysqlDB()

pkts=Queue()
queries=Queue()

class Traffic():
	def __init__(self,query=None,result=None):
		self.query = query
		self.result = result
		self.timestamp = datetime.datetime.now()

class Conn():
    def __init__(self,cip,cport,nextseq,db=UNKNOWN):
        self.cip     = cip
        self.cport   = cport
        self.db      = db
        self.traffic = []
        self.frag    = []
        #unused; implement later to increase dropped/out of order/redundant packet fault tolerance and for TCP injection support
        self.nextseq = nextseq

class DataBase():
    def __init__(self,ip,port,dbType,name=UNKNOWN):
        self.ip      = ip
        self.port    = port
        self.name    = name
        self.dbType  = dbType
        self.traffic = []
        self.users   = [] #unused currently

    def getType(self):
        if ISMYSQL(self.dbType):
            return 'MySQL'
        elif ISSQLSERV(self.dbType):
            return 'SQL Server'
        else:
            return 'Unknown'

    def getName(self):
        if self.name == UNKNOWN:
            return "Unknown"
        else:
            return self.name

    def status(self):
        res = "---%s:%s---\n"%(self.ip,self.port)
        res += "Type:\t%s\n"% self.getType()
        res += "Users:\t"
        if len(self.users) > 0:
            for u in self.users:
                res += u+", "
            res = res[:-2]+"\n"
        else:
            res += "no users identified yet\n"
        res += "Schema:\t%s\n"%self.getName()
        res += "\nIdentified traffic:\n"
        for t in self.traffic:
            res += 'Query:\n\t%s\n'%t.query
            res += 'Response:\n%s\n'%t.result
        return res

class AlarmException(Exception):
    pass

class Parse(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.die = False
        self.frag = {}
        self.res = ''
        self.knownConns = []
        self.knownDBs = []
        with open('out.txt','w') as f:
            f.write('')

    def run(self):
        global pkts
        while not self.die:
            if not pkts.empty():
                self.handle(pkts.get())

    def dumpResults(self,outfile):
        with open(outfile, 'w') as f:
            f.write('\t\t===SQLViking Results===\n\n')
        with open(outfile,'a') as f:
            for db in self.knownDBs:
                f.write(db.status()+'\n'+'~'*80+'\n')

    def getNumConns(self):
        return len(self.knownConns)

    def getNumDBs(self):
        return len(self.knownDBs)

    def fingerprint(self,pkt):
        pktType = mysql.isDB(pkt)
        if pktType == UNKNOWN:
            pktType = self.isSqlServ(pkt)
        return pktType

    def parse(self,pkts,conn):
        payload = ''
        for p in pkts:
            payload += str(p[TCP].payload)

    	db = conn.db
        if db.dbType == UNKNOWN:
            pktType = self.fingerprint(payload)

    	if ISSQLSERV(db.dbType):
            if pkts[0][IP].src == db.ip and pkt[TCP].sport == db.port:
                pktType = SQLSERVRESP
            else:
                pktType = SQLSERVREQ
        elif ISMYSQL(db.dbType):
            if pkts[0][IP].src == db.ip and pkts[0][TCP].sport == db.port:
                pktType = MYSQLRESP
            else:
                pktType = MYSQLREQ

        if pktType == MYSQLREQ:
            self.printLn('[*] Mysql Req:\n%s'%self.readable(payload.encode('hex')))
            self.store(mysql.parseReq(payload,conn),MYSQLREQ,conn)
        elif pktType == MYSQLRESP:
            self.printLn('[*] Mysql Resp:\n%s'%self.readable(payload.encode('hex')))
            self.store(mysql.parseResp(payload,conn),MYSQLRESP,conn)
        elif pktType == SQLSERVREQ:
            self.parseSqlServReq(payload,conn)
        elif pktType == SQLSERVRESP:
            self.parseSqlServResp(payload,conn)

    def isSqlServ(self,payload):
        return UNKNOWN

    def isSqlServReq(self,payload):
        return False

    def isSqlServResp(self,payload):
        return False

    def inConn(self,c,pkt):
        #self.printLn("[*] Comparing pkt with known conns:")
        #self.printLn("\tpkt.srcip;pkt.sport;pkt.dstip;pkt.dport: %s;%s;%s;%s"%(pkt[IP].src,pkt[TCP].sport,pkt[IP].dst,pkt[TCP].dport))
        #self.printLn("\tcon.srcip;con.sport;con.dstip;con.dport: %s;%s;%s;%s"%(c.cip,c.cport,c.db.ip,c.db.port))
        if c.cip == pkt[IP].dst and c.cport == pkt[TCP].dport and c.db.ip == pkt[IP].src and c.db.port == pkt[TCP].sport:
            #self.printLn("\tIs a reponse")
            return RESPONSE
        elif c.cip == pkt[IP].src and c.cport == pkt[TCP].sport and c.db.ip == pkt[IP].dst and c.db.port == pkt[TCP].dport:
            #self.printLn("\tIs a requet")
            return REQUEST

    def getConn(self,pkt):
        for c in self.knownConns:
            if self.inConn(c,pkt):
                return c

    def isKnownDB(self,pkt):
        for db in self.knownDBs:
            if pkt[IP].dst == db.ip and pkt[TCP].dport == db.port and db.name == UNKNOWN:
                return db
            if pkt[IP].src == db.ip and pkt[TCP].sport == db.port and db.name == UNKNOWN:
                return db

    def addConn(self,pkt,db=None):
        if db:
            if pkt[IP].dst == db.ip and pkt[TCP].dport == db.port: #isReq
                c = Conn(pkt[IP].src,pkt[TCP].sport,len(pkt[TCP].payload)+pkt[TCP].seq,db)
            elif pkt[IP].src == db.ip and pkt[TCP].sport == db.port: #isResp
                c = Conn(pkt[IP].dst,pkt[TCP].dport,len(pkt[TCP].payload)+pkt[TCP].seq,db)
        else:
            c = Conn(pkt[IP].src,pkt[TCP].sport,len(pkt[TCP].payload)+pkt[TCP].seq)

        self.knownConns.append(c) 
        return c   	

    def delConn(self,conn):
        #curently unused as all traffic is tracked in db object, not conn
        #if len(conn.traffic) > 0:
        #    #self.printLn("[*] Moving traffic to DB before deleting conn")
        #    for t in conn.traffic:
        #        conn.db.traffic.append(t)
        self.knownConns.remove(conn)

    def handle(self,pkt):
        #even with TCP filter set on scapy, will occassionally get packets
        #with no TCP layer. throws exception and breaks thread.
        pkts = []
        try:
            pkt[TCP]
        except:
            return

        c = self.getConn(pkt)
        if c and pkt[TCP].flags == 17: #FIN/ACK pkt, remove conn
            self.delConn(c)
            return
        #empty pkt, no reason to parse. scapy sometimes returns empty pkts with [tcp].payload set to '\x00'*6    
        elif len(pkt[TCP].payload) == 0 or (len(pkt[TCP].payload) == 6 and str(pkt[TCP].payload).encode('hex') == '0'*12): 
            return

        if not c: #check if conn is being made to a known DB
            db = self.isKnownDB(pkt)
            if db:
                c = self.addConn(pkt,db)

        ip, port, dbType = None, None, None
        if not c and pkt[TCP].flags == 3: #SYN pkt; src is client, dst is serv
            c = self.addConn(pkt)

        if not c:
            pktType = self.fingerprint(str(pkt[TCP].payload))
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
                db = DataBase(ip=ip,port=port,dbType=dbType)
                self.knownDBs.append(db)
                c = self.addConn(pkt,db)
        
        if c:
            if pkt[TCP].seq != c.nextseq: #probably pkt retransmission
                self.printLn("[*] pkt retransmission detected: seq;nextseq - %s;%s"%(pkt[TCP].seq,c.nextseq))
                return

            self.printLn("[*] valid pkt: seq;nextseq - %s;%s"%(pkt[TCP].seq,c.nextseq))

            if (pkt[TCP].flags >> 3) % 2 == 0: #PSH flag not set, is a fragged pkt
                self.printLn("[*] Fragged pkt detected")
                c.nextseq = len(pkt[TCP].payload)+c.nextseq
                c.frag.append(pkt)
            else:
                c.nextseq = pkt[TCP].ack
                if len(c.frag) > 0:
                    for p in c.frag:
                        pkts.append(p)
                    c.frag = []
                pkts.append(pkt)
                self.parse(pkts,c)

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
            #f.write('\n')

    #calls to store() uses old method; need to change to new params
    #if database can be determined, create db if it doesn't exist or point to existing db
    #if user can be determined, update db.users

    def parseSqlServReq(self,pkt,conn):
    	data = str(pkt[TCP])[20:].encode('hex')
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
        #if conn.db.name == UNKNOWN: #schema unknown, track traffic in conn
        #    if ISRESP(pktType) and len(conn.traffic) > 0 and conn.traffic[-1].result == None: #is result
        #        conn.traffic[-1].result = data
        #    elif ISRESP(pktType): #is result, missed query
        #        conn.traffic.append(Traffic(result=data))
        #    else: #is query
        #        conn.traffic.append(Traffic(query=data))
        #else: #schema known, track traffic in conn.db
        #if len(conn.traffic) > 0:
        #    for t in conn.traffic:
        #        conn.db.traffic.append(t)
        #    conn.traffic = []
        if ISRESP(pktType) and len(conn.db.traffic) > 0 and conn.db.traffic[-1].result == None: #is result
            conn.db.traffic[-1].result = data
            #self.printLn("[1] Storing pkt")
        elif ISRESP(pktType): #is result, missed query
            conn.db.traffic.append(Traffic(result=data))
            #self.printLn("[2] Storing pkt")
        else: #is query
            conn.db.traffic.append(Traffic(query=data))
            #self.printLn("[3] Storing pkt")

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
        global pkts
        while not self.die:
            try:
                sniff(prn=self.queuePkt,filter="tcp",store=0,timeout=5)
            except:
                print sys.exc_info()[1]
                self.die = True

    def queuePkt(self,pkt):
        global pkts
        pkts.put(pkt)
        #self.printLn("[*] pkt found: src;dst - %s;%s"%(pkt[IP].src,pkt[IP].dst))
        #self.printLn("[*] ASCII:\t%s"%self.readable(str(pkt[TCP].payload).encode('hex')))

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
    t.dumpResults(path)  

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

def alarmHandler(signum, frame):
    raise AlarmException

def nonBlockingRawInput(t, prompt='> ', timeout=5):
    signal.signal(signal.SIGALRM, alarmHandler)
    signal.alarm(timeout)
    try:
        text = raw_input(prompt)
        signal.alarm(0)
        parseInput(text,t)
    except AlarmException:
        printMainMenu(t)
    signal.signal(signal.SIGALRM,signal.SIG_IGN)
    return ''

def printMainMenu(t,wipe=True):
    if wipe:
        wipeScreen()
        y,x = os.popen('stty size', 'r').read().split()
    
    print('{{:^{}}}'.format(x).format('===Welcome to SQLViking==='))
    print('\n[*] Current number of known DBs:\t\t%s'%t.getNumDBs())
    print('[*] Current number of known connections:\t%s'%t.getNumConns())
    print('\n[*] Menu Items:')
    print('\tw - dump current results to file specified')
    print('\tr - run a query against a specified DB (not implemented yet)')
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
        printMainMenu(t2)
        try:
            nonBlockingRawInput(t2)
        except KeyboardInterrupt:
            print('\n[!] Shutting down...')
            t1.die = True
            t2.die = True
            t3.die = True
            break
        #except:
            #t1.die = True
            #t2.die = True
            #t3.die = True
            #print sys.exc_info()[1]
            #break
    
if __name__ == "__main__":
    main()
