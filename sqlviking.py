from os import walk
from operator import itemgetter
from Queue import Queue
import sys, getopt, re, argparse,threading
sys.path.append("databases/")
from constantvalues import *
import mysql,sqlserver

dbs = Queue()
toInject = Queue()

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

class DataBase():
    def __init__(self,dbType,ip,port):
        self.ip       = ip
        self.port     = port
        self.dbType   = dbType
        self.traffic  = []
        self.users    = []
        self.hashes   = []
        self.schemas  = []

    def getHumanType(self):
        if ISMYSQL(self.dbType):
            return 'MySQL'
        elif ISSQLSERV(self.dbType):
            return 'SQL Server'
        else:
            return 'Unknown'

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
        self.knownDatabases = []

    def run(self):
        global dbs
        while not self.die:
            if not dbs.empty():
                self.knownDatabases.append(dbs.get())
                print '[*] DB found: %s at %s:%s'%(self.knownDatabases[-1].getHumanType(),self.knownDatabases[-1].ip,self.knownDatabases[-1].port)

def parseConfig(f):
    global dbs,toInject
    DATABASES = 0
    INJECTION = 1
    DATA = 2
    MISC = 3

    flag = -1
    with open(f,'r') as f:
        for l in f:
            if len(l.strip()) == 0:
                flag = -1
            elif l == '[Databases]':
                flag = DATABASES
            elif l == '[Injection]':
                flag = INJECTION
            elif l == '[Data]':
                flag = DATA
            elif l == '[Misc]':
                flag = MISC

            if flag == DATABASES:
                l = l.split(':')
                dbs.put(Database(l[0],l[1],l[2]))
            elif flag == INJECTION:
                toInject.put(l)
            elif flag == DATA:
                l = l #do nothing for know, leave check so i remember to update later when stuff is actually implemented
            elif flag == MISC:
                l = l #do nothing for know, leave check so i remember to update later when stuff is actually implemented

def main():
    #t1 = Scout()
    #t2 = Parse()
    #t1.start()
    #t2.start()

    parser = argparse.ArgumentParser(description='Pwn the network, pwn the database', prog='sqlviking.py', usage='%(prog)s [-v] -c <config file location>', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=65, width =150))
    parser.add_argument('-v', '--verbose', action='store_true', help='Turn on verbose mode; will print out all captured traffic')
    parser.add_argument('-c', '--configfile', default='sqlviking.conf', help='Config file location, defaults to sqlviking.conf')
    parser.add_argument('-h', '--help', help='Display help info about using sqlviking')
    args = parser.parse_args()

    try:
        parseConfig(args.configfile)
    except IOError:
        print('[!] Error reading config file. Exiting...')
        sys.exit(0)

    while True:
        #printMainMenu(t2)
        try:
            a = 1
            #nonBlockingRawInput(t2)
        except KeyboardInterrupt:
            print('\n[!] Shutting down...')
            t1.die = True
            #t2.die = True
            break
        except:
            t1.die = True
            #t2.die = True
            print sys.exc_info()[1]
            break

if __name__ == "__main__":
    main()
