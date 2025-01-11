## ocp_receiver
import time
import identus
from sender import Sender

class Receiver:
    def __init__(self):
        self.passphrase = None
        self.encoded_condition=None
        self.User=None
        self.sender = Sender()                              ## our notary

    def set_user(self, _user):
        self.user=_user

##
## remember lastest passphrase
##

    def set_passphrase(self, passphrase):
        print("=> Receiver passphrase set to = "+passphrase)
        self.passphrase = passphrase
    
    def get_passphrase(self):
        return self.passphrase
        
##
## Creds
##

    # use this to issue encoded_condition into a VC for the sender (own use for decoding)
    def accept_vc_offer(self, iteration):
        try:
            ## we have an offer, and we are the one to receive, so we accept it right now
            offeredToHolder=identus.get_credential_for_iteration(self.user, iteration)                
            if offeredToHolder== None:
                raise Exception("Could not find RecordId") 

            ## receiver accepts this offer (with its own recordId)
            dataAcceptedByHolder = identus.postIdentus(self.user["entity"]["apiKey"], "issue-credentials/records/"+offeredToHolder["recordId"]+"/accept-offer", {
                "subjectId": self.user["did"]
            })

            time.sleep(6)   ## shit identus delay
            self.sender.notify_accepted_vc(self.user["did"], offeredToHolder)
            return offeredToHolder        

        except Exception as e:
            return False             

    def get_all_pending_creds(self):
        vcs=identus.getIdentus(self.user["entity"]["apiKey"], "issue-credentials/records")
        return vcs["contents"]
            
##
## decode secret
##

    def set_encoded_condition(self, condition):
        self.encoded_condition=condition

    def decode_secret(self, encoded, param):
        return param["notary"].decode_secret(encoded, {
            "passphrase": param["passphrase"],
            "encoded_condition": self.encoded_condition,
            "did_sender": param["did_sender"],
            "iterations": param["iterations"],
        })