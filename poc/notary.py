
###################################################################################### 
##   BASIC IMPLEMENTATION OF ENCODING/DECODING WITH A NOTARY IN THE MIDDLE
###################################################################################### 

import os
import base64
import random
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

## --------------
## ENCODE/DECODE
## --------------

class Encoder:
    def __init__(self):
        self.length=32
        
    def _getKeyFromParam (self, param):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=param["salt"],
            iterations=param["iterations"],
            backend=default_backend()
        )

        ## get a key from the params (incl passphrase & extra)
        derivation = param["passphrase"]
        if param["extra"]!=None :
            derivation = param["passphrase"] + param["extra"]
        key = kdf.derive((derivation).encode())
        return key

    # public encode method
    def encode(self, _secret, param) :

        ## UTF8 encode the plain text secret
        utf8_secret = _secret.encode('utf-8') 

        # get the key for encoding/decoding 
        key=self._getKeyFromParam(param)

        # Encrypt the secret
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_secret = encryptor.update(utf8_secret) + encryptor.finalize()

        # Encode for storage or transmission
        encrypted_secret_b64 = base64.b64encode(iv + encrypted_secret).decode('utf-8')
        return encrypted_secret_b64

    # public decode method
    def decode(self, _encoded, param) :

        if param["salt"] == None:
            return None
        
        # get the key for encoding/decoding 
        key=self._getKeyFromParam(param)

        # Decode the base64 encoded data
        encrypted_secret_data = base64.b64decode(_encoded)

        # Decrypt the secret
        iv = encrypted_secret_data[:16]
        encrypted_secret = encrypted_secret_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_secret = decryptor.update(encrypted_secret) + decryptor.finalize()

        return decrypted_secret

## --------------
##    NOTARY
## --------------

class Notary:
    def __init__(self):
        self.aSecretParam=[]                    ## array of secret param  ## array of secret param  (timestamp, salt)
        self.decoder = Encoder()                ## a decoder engine

    ## Notary can retrieve its salt for a particular timestam
    def _get_salt_for_timestamp(self, _ts):
        result = None
        for item in self.aSecretParam:
            if item["timestamp"] == _ts:
                result = item
                break  # Exit the loop once the item is found
        if result==None:
            return None
        return result["salt"]
        
    ## for each timestam value, we keep a salt (at this stage, in memory only - store in DB later??)
    def set_salt_for_timestamp(self, ts, salt):
        self.aSecretParam.append({
            "timestamp": ts,
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
            "salt" : self._get_salt_for_timestamp(param["timestamp"]) 
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
            "salt" : self._get_salt_for_timestamp(param["timestamp"]) 
        })
        if decoded==None:
            return None
        return decoded.decode('utf-8')

## --------------
##    SENDER
## --------------

class Sender:
    def __init__(self):
        self.set_passphrase("shared_passphrase")            ## a randon passphrase (new one each time sender is initialised)
        self.notary = Notary()                              ## our notary
        self.encoder = Encoder()
        self.aSecretParam=[]         ## array of secret param  (timestamp, iterations, salt, encoded_condition)

    def set_passphrase(self, passphrase):
        print("=> Sender passphrase set to = "+passphrase)
        self.passphrase = passphrase
    
    def get_passphrase(self):
        return self.passphrase
        
    def set_condition(self, str_condition, ts, iterations, salt):
        encoded_condition=self.encoder.encode(str_condition, {
                    "passphrase": self.passphrase,
                    "extra" : "condition",
                    "iterations": iterations,     
                    "salt" : salt 
                })
        self.add_encoded_condition_to_timestamp(ts, encoded_condition)
        return encoded_condition

    def get_encoded_condition(self, _ts):
        item=self.get_param_from_timestamp(_ts)
        if item==None:
            return None
        return item["encoded_condition"]
        
    def get_notary(self):
        return self.notary
    
    def add_encoded_condition_to_timestamp(self, _ts, encoded_condition):
        item=self.get_param_from_timestamp(_ts)
        if item!= None:
            item["encoded_condition"]=encoded_condition

    def get_param_from_timestamp(self, _ts):
        # Find the dictionary with the matching timestamp
        result = None
        for item in self.aSecretParam:
            if item["timestamp"] == _ts:
                result = item
                break  # Exit the loop once the item is found
        return result
    
    def encode_secret(self, plain_text_secret, plain_text_condition):
        ts=time.time()
        iterations = random.randint(1,100000)          ## a random iteration 
        salt = os.urandom(32)                          ## a random salt that sender shares with Notary

        ## store the iteration / salt with this timestamp
        self.aSecretParam.append({
            "timestamp": ts,
            "iterations": iterations,
            "salt": salt  
        })
        self.notary.set_salt_for_timestamp (ts, salt)       ## share this salt with notary
        encoded_condition=self.set_condition(plain_text_condition, ts, iterations, salt)        ## get the encoded condition (will be shared with receiver)

        encoded=self.encoder.encode(plain_text_secret, {
            "passphrase": self.passphrase,
            "extra": encoded_condition,
            "iterations": iterations,                 
            "salt" : salt 
        })
        return {
            "ts": ts,               ## important timestamp, used by Notary to know which salt to retrieve
            "i": iterations,        ## in plain text
            "s": encoded,           ## encoded secret
        }
    
    def decode_secret(self, encoded, param):
        item=self.get_param_from_timestamp(param["timestamp"])
        if item== None:
            return None
        decoded=self.encoder.decode(encoded, {
            "passphrase": self.passphrase,
            "extra": item["encoded_condition"],
            "iterations": param["iterations"],                 
            "salt" : item["salt"]
        })
        if decoded==None:
            return None
        return decoded.decode('utf-8')
     
## --------------
##    RECEIVER
## --------------

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
    
## --------------
##  HERE WE GO!
## --------------

print ("READY TO GO")
print("")

alice = Sender()
bob = Receiver()

## Alice creates secret and condition
secret="this is Alice's secret"
condition="a condition that must be met"                     ## alice defines the condition which must be met to unlock secret

print("=> Plain text Secret:", secret)
print("=> Plain text condition:", condition)

encoded_json=alice.encode_secret(secret, condition)                     ## alice encodes her secret (and can keep th encrypted secret for herself, and share with others too)
encoded_condition=alice.get_encoded_condition(encoded_json["ts"])       ## alice's conditions are encoded so that noone can know those conditions (even the notary will not know)
print("=> Encrypted Secret:", encoded_json["s"])

## Alice does not need the notary to decode her secret
decoded_by_alice=alice.decode_secret(encoded_json["s"], {
    "iterations": encoded_json["i"],
    "timestamp": encoded_json["ts"]
})
print("=> Alice can decode her secret alone:", decoded_by_alice)

## Alice shares passphrase and notary with Bob
bob.set_passphrase(alice.get_passphrase())      ##  Alice shares passphrase with Bob

## Bob tries to decode the secret (when conditions are not met)
decoded = bob.decode_secret(encoded_json["s"], {
    "iterations": encoded_json["i"],
    "timestamp": encoded_json["ts"],
    "notary": alice.get_notary()                ##  Alice shares her Notary with Bob
})
print("=> Decrypted Secret (condition not met):", decoded)

## Bob receives conditions from Alice, and tries to decode the secret once more. 
## In this simple example, Alice's notary will instantly accept this condition as "validated" 
bob.set_encoded_condition(encoded_condition)            ##  Alice sents the conditions to BOB (later this can be a VC)
decoded = bob.decode_secret(encoded_json["s"], {
    "iterations": encoded_json["i"],
    "timestamp": encoded_json["ts"],
    "notary": alice.get_notary()                ##  Alice shares her Notary with Bob
})
print("=> Decrypted Secret (condition met):", decoded)

print("FINISHED")
