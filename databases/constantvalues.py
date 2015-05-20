#when adding additional DBs, assign their value to the next unused prime number
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

HANDSHAKE   = 1
ESTABLISHED = 2

HUMAN = 1
CSV   = 2
JSON  = 3