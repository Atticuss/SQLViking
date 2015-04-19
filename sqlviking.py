from os import walk
from operator import itemgetter
from Queue import Queue
import sys, getopt, re, argparse,threading
sys.path.append("databases/")
from constantvalues import *
import mysql,sqlserver

dbQueue = Queue()
injectionQueue = Queue()

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

class Scout(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.die = False
        self.toInject = []
        self.knownDatabases = []

    def run(self):
        global dbs
        while not self.die:
            if not dbQueue.empty():
                self.knownDatabases.append(dbQueue.get())
                #dprint('[?] DB found: %s at %s:%s'%(self.knownDatabases[-1].getHumanType(),self.knownDatabases[-1].ip,self.knownDatabases[-1].port))
            if not injectionQueue.empty():
                self.toInject.append(injectionQueue.get())
                #dprint('[?] Injection parsed - %s'%self.toInject[-1])

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
                dbQueue.put(Database(l[0],l[1],l[2]))
            elif flag == INJECTION:
                injectionQueue.put(l)
            elif flag == DATA:
                l = l #do nothing for know, leave check so i remember to update later when stuff is actually implemented
            elif flag == MISC:
                l = l #do nothing for know, leave check so i remember to update later when stuff is actually implemented

def main():
    parser = argparse.ArgumentParser(description='Pwn the network, pwn the database', prog='sqlviking.py', usage='%(prog)s [-v] -c <config file location>', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=65, width =150))
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
