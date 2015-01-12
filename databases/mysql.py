import abc,sys
from basedb import BaseDB
from sys import path
from constantvalues import *
path.append("databases/pymysql/")
import connections

COM_INIT_DB = '02'

class MySqlDB(BaseDB):
    def __init__(self):
        pass

    def encodeQuery(self,query):
        length = '240000'
        return (length+'0003').decode('hex')+query

    def getPayloads(self,data):
        encpkt = str(data).encode('hex')
        pktlen = len(encpkt)/2
        payloads = []

        while len(encpkt)>0:
            length = int(self.flipEndian(encpkt[:6]),16)
            payloads.append(encpkt[8:8+(length*2)])
            encpkt = encpkt[8+(length*2):]

        return payloads

    def printLn(self,msg):
        with open('out.txt','a') as f:
            f.write(msg+'\n')

    def isDB(self,payload):
        encpkt = str(payload).encode('hex')
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
            if self.isReq(payloads):
                pktType = MYSQLREQ
            elif self.isResp(payloads):
                pktType = MYSQLRESP
            else: #possibly MySQL, cannot determine if req/resp right now
                pktType = MYSQL
        else: #not a MySQL pkt
            pktType = UNKNOWN

        return pktType

    def isReq(self,payloads):
        if payloads[0] == '0e': #COM_PING
            return True

    def isResp(self,payloads):
        if payloads[0] == '00000002000000': #OK RESP 
            return True
        elif payloads[0][:2] == 'ff': #ERR RESP
            return True
        elif len(payloads[0]) == 2 and int(payloads[0], 16) == self.getMysqlCols(payloads): #Query RESP
            return True

    #if database can be determined, create db if it doesn't exist or point to existing db
    #if user can be determined, update db.users

    def parseReq(self,data,conn):
        payloads = self.getPayloads(data)
        if conn.state == HANDSHAKE: #parse login pkt
            p = payloads[0][64:] #assumes HandshakeResponse41, no check for HandshakeResponse320. should be fine, 4.1 was released 2004. doubt any dbs are on a decade old version.
            username = ''
            for c in p:
                if p[:2] != '00':
                    username += p[:2].decode('hex')
                else:
                    break
                p = p[2:]
            conn.db.addUser(username)
            conn.state = ESTABLISHED

        if payloads[0][:2] == COM_INIT_DB: #assumes schema is correct. no check for successful response from server
            conn.db.addSchema(payloads[0][2:].decode('hex'))
            return "Client request to use database:\t%s"%payloads[0][2:].decode('hex')

        data = data.encode('hex')
        pktlen = len(data)/2
        lengths = []
        ret = ''
        while len(data)>0:
            length = int(self.flipEndian(data[:6]),16)
            lengths.append(length)
            ret += self.readable(data[8:8+(length*2)])
            data = data[8+(length*2):]
        return ret    

    def parseResp(self,data,conn):
        resp = ''
        encdata = data.encode('hex')
        pktlen = len(encdata)/2
        lengths=[]
        while len(encdata)>0:
            length = int(self.flipEndian(encdata[:6]),16)
            lengths.append(length)
            encdata = encdata[8+(length*2):]

        payloads = self.getPayloads(data)
        if payloads[0] == '00000002000000': #OK resp
            return '\tServer OK response\n'

        ret = ''
        res = connections.MySQLResult(connections.Result(data))
        try:
            res.read()
            if res.message and len(res.message) > 0:
                ret += '\tMessages:'
                for m in res.message:
                    ret += '\t\t%s\n'%m
            if res.description and len(res.description) > 0:
                ret += '\tDescription:\t%s\n'%str(res.description)
            if res.rows and len(res.rows)>0:
                ret += '\tResult:\n'
                for r in res.rows:
                    ret += "\t\t%s\n"%str(r)
        except:
            ret += '\tError:\t%s\n'%sys.exc_info()[1]
        return ret

    def getMysqlCols(self,payloads):
        c = -1 #ignore first payload
        for p in payloads:
            if p == "fe00002200":
                return c
            else:
                c+=1

    def flipEndian(self,data):
        resp=''
        for i in range(0,len(data),2):
            resp = data[i]+data[i+1]+resp
        return resp

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