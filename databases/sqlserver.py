import abc,sys,binascii
from basedb import BaseDB
from sys import path
from constantvalues import *
path.append("databases/pytds/")
import tds

class SqlServerDB(BaseDB):
    def __init__(self):
        pass

    def encodeQuery(self,query):
        return query

    def isDB(self, payload):
        return UNKNOWN

    def isReq(self, payloads):
        return UNKNOWN

    def isResp(self, payloads):
        return UNKNOWN

    def parseReq(self,pkt,conn):
        data = str(pkt[TCP])[20:].encode('hex')
        return "\n--SQLServ Req--\n%s\n"%self.readable(data)
        
    def parseResp(self, data, conn):
        data = str(pkt[TCP])[20:]
        resp = Response(data)
        resp.parse()
        
        if len(resp.messages) > 0:
            self.store("--SQLServ Resp--\n%s"%resp.messages[0]['message'])
        else:
            self.store("--SQLServ Resp--\n%s"%resp.results)

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

class Response():
    def __init__(self, data):
        self.data = data
        self.messages = []
        self.results = []
        self.tdssock = tds._TdsSocket(self.data)
        
    def parse(self):
        try:
            while True:
                self.tdssock._main_session.find_result_or_done()
        except:
            pass

        try:
            self.messages = self.tdssock._main_session.messages
        except:
            pass
        
        self.results = self.tdssock._main_session.results
        
class Request():
    def __init__(self):
        self.tdssock = tds._TdsSocket()
        
    def buildRequest(self,query):
        self.tdssock._main_session.submit_plain_query(query)
        return binascii.hexlify(self.tdssock._main_session._writer.data).decode('hex')