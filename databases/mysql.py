import abc,sys
from basedb import BaseDB
from sys import path
from constantvalues import *
path.append("databases/pymysql/")
import connections

class MysqlDB(BaseDB):
    def __init__(self):
        pass

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

        #self.printLn("[*] Lengths & tlen:\t%s; %s"%(lengths,tlen))
        #self.printLn("[*] Payloads:\t%s"%payloads)
        #for p in payloads:
        #    #self.printLn("[*] ASCII:\t%s"%self.readable(p))

        if tlen == pktlen and len(payloads) > 0:
            if self.isReq(payloads):
                pktType = MYSQLREQ
            elif self.isResp(payloads):
                pktType = MYSQLRESP
            else: #possibly MySQL, cannot determine right now
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

    def parseReq(self,data,conn):
        #self.printLn("\n--MySQL Req--\n")
        #self.printLn("Payload len:\t%s"%len(data))
        #self.printLn('[*] ASCII:\t%s'%self.readable(str(data).encode('hex')))
        data = data.encode('hex')
        pktlen = len(data)/2
        lengths = []
        ret = ''
        while len(data)>0:
            length = int(self.flipEndian(data[:6]),16)
            lengths.append(length)
            #self.printLn("SubPacket Raw:\t%s"%data[8:8+(length*2)])
            #self.printLn("SubPacket ASCII:\t%s"%self.readable(data[8:8+(length*2)]))
            ret += self.readable(data[8:8+(length*2)])
            data = data[8+(length*2):]
        #self.store(parseddata,MYSQLREQ,conn)    
        #data = data.encode('hex')
        #self.store(ret,MYSQLREQ,conn)  
        return ret    

    def parseResp(self,data,conn):
        resp = ''
        #self.printLn("\n--MySQL Resp--\n")
        #self.printLn("Payload len:\t%s"%len(data))
        #self.printLn('[*] ASCII:\t%s'%self.readable(str(data).encode('hex')))
        encdata = data.encode('hex')
        pktlen = len(encdata)/2
        lengths=[]
        while len(encdata)>0:
            length = int(self.flipEndian(encdata[:6]),16)
            lengths.append(length)
            #self.printLn("SubPacket Raw:\t%s"%encdata[8:8+(length*2)])
            #self.printLn("SubPacket ASCII:\t%s"%self.readable(encdata[8:8+(length*2)]))
            encdata = encdata[8+(length*2):]

        ret = ''
        res = connections.MySQLResult(connections.Result(data))
        try:
            res.read()
            #self.printLn('[*] Message:\t%s'%str(res.message))
            #self.printLn('[*] Description:\t%s'%str(res.description))
            #self.printLn('[*] Rows:')
            #if res.rows and len(res.rows)>0:
            #    for r in res.rows:
                    #self.printLn(self.formatTuple(r))
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
            #self.printLn('[!] Error:\t%s'%sys.exc_info()[1])
            ret += '\tError:\t%s\n'%sys.exc_info()[1]
        #self.printLn('[*] Raw:\t%s\n'%str(data).encode('hex'))
        #self.store(ret,MYSQLRESP,conn)
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