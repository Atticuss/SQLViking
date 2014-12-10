from scapy.all import *
from Queue import Queue
from sys import path
import sys, threading, time
path.append("pymysql/")
import connections
path.append("pytds/")
import response

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
        resp = response.Response(data)
        resp.parse()
        
        if len(resp.results) == 0:
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
    queries.put([query,dst])

def parseInput(input,t):
    if input == 'w':
        writeResults(t)
    elif input == 'p':
        t.println()
    elif input == 'r':
        pillage()
    elif input == 'q':
        raise KeyboardInterrupt
    else:
        print('Unknown command entered')    

def main():
    #TODO: better menu. running counter of reqs/resps capped and DBs discovered.
    print('==Welcome to SQLViking!==')

    t1 = Scout()
    t2 = Parse()
    t3 = Pillage()
    t1.start()
    t2.start()
    t3.start()
    
    while True:
        print('\n\n[*] Menu Items:')
        print('\tw - dump current results to file specified')
        print('\tp - print current results to screen')
        print('\tr - run a query against a specified DB')
        print('\tq - quit')
        try:
            parseInput(raw_input("> "),t2)
        except KeyboardInterrupt:
            print('\n[!] Shutting down...')
            t1.die = True
            t2.die = True
            t3.die = True
            break
        #TODO: cheap hack to make sure everything prints before reprinting menu. need better solution. using Queue()?       
        time.sleep(1)
    
if __name__ == "__main__":
    main()
