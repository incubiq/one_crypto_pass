## ocp_notary

from encoder import Encoder

class Notary:
    def __init__(self):
        self.aSecretParam=[]                    ## array of secret param  ## array of secret param  (timestamp, salt)
        self.decoder = Encoder()                ## a decoder engine

    ## Notary can retrieve its salt for a particular timestamp
    def _get_salt_for_iteration(self, _i):
        result = None
        for item in self.aSecretParam:
            if item["iterations"] == _i:
                result = item
                break  # Exit the loop once the item is found
        if result==None:
            return None
        return result["salt"]
            
    ## for each timestamp value, we keep a salt (at this stage, in memory only - store in DB later??)
    def set_salt_for_iteration(self, _did, _i, salt):
        self.aSecretParam.append({
            "did": _did,
            "iterations": _i,
            "salt": salt  
        })
        print("=> Notary was set with salt = "+str(salt))

    ## only notary can decode the encoded condition
    def _decode_encoded_condition(self, encoded_condition, param):
        if encoded_condition==None:
            return None
        decoded=self.decoder.decode(encoded_condition, {
            "passphrase": param["passphrase"],
            "extra": "condition",
            "iterations": param["iterations"],            
            "salt" : self._get_salt_for_iteration(param["iterations"]) 
        })
        if decoded==None:
            return None
        return decoded.decode('utf-8')
    
    ## Notary can check if the condition os valid or not
    def _is_condition_valid(self, encoded_condition, param):
        condition=self._decode_encoded_condition(encoded_condition, param)
        if condition==None:
            return False
        
        ## TODO : really check if condition is met (for now we return True)
        return True
    
    ## public decode_secret API that anyone can call into notary (maybe behing auth later?)
    def decode_secret(self, encoded, param):
        ## notary must first check if condition is valid
        if self._is_condition_valid(param["encoded_condition"], param) == False:
            return None

        ## condition is met, notary can decode the secret
        decoded=self.decoder.decode(encoded, {
            "passphrase": param["passphrase"],
            "extra": param["encoded_condition"],
            "iterations": param["iterations"],                 
            "salt" : self._get_salt_for_iteration(param["iterations"]) 
        })
        if decoded==None:
            return None
        return decoded.decode('utf-8')
