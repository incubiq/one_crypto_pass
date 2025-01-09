## ocp_receiver

class Receiver:
    def __init__(self):
        self.passphrase = None
        self.encoded_condition=None

##
## remember lastest passphrase
##

    def set_passphrase(self, passphrase):
        print("=> Receiver passphrase set to = "+passphrase)
        self.passphrase = passphrase
    
    def get_passphrase(self):
        return self.passphrase
        
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