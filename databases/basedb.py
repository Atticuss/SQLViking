import abc

class BaseDB():
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def encodeQuery(self,query):
        return

    @abc.abstractmethod
    def isDB(self, payload):
        return

    @abc.abstractmethod
    def isReq(self, payloads):
        return

    @abc.abstractmethod
    def isResp(self, payloads):
        return

    @abc.abstractmethod
    def parseReq(self, data, conn):
        return
        
    @abc.abstractmethod
    def parseResp(self, data, conn):
        return