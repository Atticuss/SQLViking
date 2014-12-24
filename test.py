import sys,threading,time,logging,os,datetime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Queue import Queue
from sys import path
path.append("pymysql/")
import connections
path.append("pytds/")
import sqlserver

pkts = Queue()

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
        sefl.nextseq = -1
        self.neqack  = -1

class DataBase():
    def __init__(self,ip,port,name=UNKNOWN,dbtype):
        self.ip      = ip
        self.port    = port
        self.name    = name
        self.dbtype  = dbtype
        self.traffic = []
        self.users   = [] #unused currently

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
                print(sys.exc_info()[1])
                self.die = True

    def pushToQueue(self,pkt):
        global pkts
        pkts.put(pkt)

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
        with file('out.txt','w') as f:
            f.write('')

    def run(self):
        global pkts
        while not self.die:
            if not pkts.empty():
                self.handle(pkts.get())

    def inConn(self,c,pkt):
        if c.cip == pkt[IP].dst and c.cport == pkt[TCP].dport and c.db.ip == pkt[IP].src and c.db.port == pkt[TCP].sport:
            return RESPONSE
        elif c.cip == pkt[IP].src and c.cport == pkt[TCP].sport and c.db.ip == pkt[IP].dst and c.db.port == pkt[TCP].dport:
            return REQUEST

    def getConn(self,pkt):
        for c in self.knownConns:
            if self.inConn(c,pkt):
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
        ip, port, dbtype = None, None, None
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

        if ip and port and dbtype:
            db = DataBase(ip=ip,port=port,dbtype=dbtype)
            self.knownDBs.append(db)
            c = self.addConn(pkt,db)
            self.parse(pkt,c)

    def fingerprint(self,pkt):
        pktType = self.isMySql(pkt)
        if pktType == UNKNOWN:
            pktType = self.isSqlServ(pkt)
        return pktType

    def flipEndian(self,data):
        resp=''
        for i in range(0,len(data),2):
            resp = data[i]+data[i+1]+resp
        return resp

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

    def parse(self,pkt,pktType):
        if pktType == MYSQLREQ:
            self.parseMySqlReq(str(pkt[TCP])[20:])
        elif pktType == MYSQLRESP:
            self.parseMySqlResp(str(pkt[TCP])[20:])
        elif pktType == SQLSERVREQ:
            self.parseSqlServReq(str(pkt[TCP])[20:])
        elif pktType == SQLSERVRESP:
            self.parseSqlServResp(str(pkt[TCP])[20:])
        else:
            self.store("Unknown packet type")

    def parseMySqlReq(self,data):
        self.store("\n--MySQL Req--\n")
        data = data.encode('hex')
        pktlen = len(data)/2
        lengths=[]
        while len(data)>0:
            length = int(self.flipEndian(data[:6]),16)
            lengths.append(length)
            self.store("SubPacket Raw:\t%s"%data[8:8+(length*2)])
            self.store("SubPacket ASCII:\t%s"%self.readable(data[8:8+(length*2)]))
            data = data[8+(length*2):]

        #data = data.encode('hex')
        #self.store("Raw:\t%s"%data)
        

    def parseMySqlResp(self,data):
        self.store("\n--MySQL Resp--\n")
        #self.store('[*] Raw:\t%s'%str(data).encode('hex'))
        encdata = data.encode('hex')
        pktlen = len(encdata)/2
        lengths=[]
        while len(encdata)>0:
            length = int(self.flipEndian(encdata[:6]),16)
            lengths.append(length)
            self.store("SubPacket Raw:\t%s"%encdata[8:8+(length*2)])
            self.store("SubPacket ASCII:\t%s"%self.readable(encdata[8:8+(length*2)]))
            encdata = encdata[8+(length*2):]

        res = connections.MySQLResult(connections.Result(data))
        try:
            res.read()
            self.store('[*] Message:\t%s'%str(res.message))
            self.store('[*] Description:\t%s'%str(res.description))
            self.store('[*] Rows:')
            if len(res.rows)>0:
                for r in res.rows:
                    self.store(self.formatTuple(r))
                self.store('\n')
        except:
            self.store('[!] Error:\t%s'%sys.exc_info()[1])
        self.store('[*] Raw:\t%s\n'%str(data).encode('hex'))

    def store(self,msg):
        with file('out.txt','a') as f:
            f.write(msg+"\n")

    def formatTuple(self,t):
        res=''
        for i in t:
            res+="%s, "%i
        return res[:-2]

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

def main():
    #TODO: better menu. running counter of reqs/resps capped and DBs discovered.

    t1 = Scout()
    t2 = Parse()
    t1.start()
    t2.start()

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print('\n[!] Shutting down...')
            t1.die = True
            t2.die = True
            break
        except:
            t1.die = True
            t2.die = True
            print(sys.exc_info()[1])
            break
    
if __name__ == "__main__":
    main()