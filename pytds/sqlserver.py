import tds

#TODO: this is ghetto as shit. need to clean up pytds fork. also need to add ability to parse col names from query responses
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
        return self.tdssock._main_session._writer.data
  