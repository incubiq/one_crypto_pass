## ocp_receiver

from encoder import Encoder

class Receiver:
    def __init__(self):
        self.passphrase = None
        self.encoded_condition=None
        self.decoder = Encoder()

    def set_passphrase(self, passphrase):
        print("=> Receiver passphrase set to = "+passphrase)
        self.passphrase = passphrase
    
    def get_passphrase(self):
        return self.passphrase
        
    def set_encoded_condition(self, condition):
        self.encoded_condition=condition
    
    def decode_secret(self, encoded, param):
        return param["notary"].decode_secret(encoded, {
            "passphrase": self.passphrase,
            "encoded_condition": self.encoded_condition,
            "iterations": param["iterations"],
            "timestamp": param["timestamp"],
        })