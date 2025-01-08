## ocp_auth

from inmem_db import InMemDB

class Authenticator:
    def __init__(self):
        self.inMemBD=InMemDB()
        return
        
    def authenticate(self, _user):
        if (_user=="alice"): 
            return self.inMemBD.getAlice()
        return self.inMemBD.getBob()
    