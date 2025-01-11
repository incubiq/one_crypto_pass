## ocp_sender
import os
import random
import time
import qrcode
import base64
import hashlib
from io import BytesIO

from encoder import EncoderDecoder
from notary import Notary
import identus


class Sender:

##
## misc var inits
##

    def __init__(self):
        self.withVC=False                   ## True if we work with Verifiable Creds, False if not
        self.passphraseForSecret=None
        self.passphraseForCondition=None
        self.iterations=None
        self.notary = Notary()                              ## our notary
        self.encoder_decoder = EncoderDecoder()
        self.aSecretParam=[]         ## array of secret param  (timestamp, iterations, salt, encoded_condition)

    def set_user(self, _user):
        self.user=_user
    
    def get_notary(self):
        return self.notary
    
    def set_with_vc(self, bHasVC):
        self.withVC=(bHasVC==True)
    
    def TOKEN_PASSPHRASE_FOR_SECRET (self): 
        return "token4secret" 
    
    def TOKEN_PASSPHRASE_FOR_CONDITION (self): 
        return "token4condition" 
    
    def TOKEN_SALT (self): 
        return "token4salt" 
    
    def SHA_PASSPHRASE (self): 
        return 256
    
    def SHA_SALT (self): 
        return 512

##
## generating passphrases and salts
##

    def generate_passphrase(self, private_key: str) -> str:
        iterations = random.randint(1000000000,100000000000000)        ## a random iteration 
        self.iterations = iterations
        self.passphraseForSecret=self.get_unique_token(self.TOKEN_PASSPHRASE_FOR_SECRET(), private_key, iterations)
        self.passphraseForCondition=self.get_unique_token(self.TOKEN_PASSPHRASE_FOR_CONDITION(), private_key, iterations)
        self.salt=self.get_unique_token(self.TOKEN_SALT(), private_key, iterations)
        print("=> Sender iterations set to = "+str(self.iterations))
        print("=> Sender passphrase for Secret set to = "+self.passphraseForSecret)
        print("=> Sender salt set to = "+str(self.salt))

    def get_unique_token(self, _type, private_key: str, iterations)  -> str:
        if _type==self.TOKEN_PASSPHRASE_FOR_SECRET():
            return self._get_unique_token(self.SHA_PASSPHRASE(), private_key, str(iterations))
        if _type==self.TOKEN_PASSPHRASE_FOR_CONDITION():
            first_8_digits = int(str(iterations)[:8])
            return self._get_unique_token(self.SHA_PASSPHRASE(), private_key, str(first_8_digits)+"_conditions")
        if _type==self.TOKEN_SALT():
            return self._get_unique_token(self.SHA_SALT(), private_key, str(iterations))
        return None

    def _get_unique_token(self, _sha: int, private_key: str, _extra: str)  -> str:
        # Combine the private key and the big number as bytes
        combined_data = (private_key + _extra).encode('utf-8')
        
        # Generate a unique token using SHA-256 / 512
        if _sha==256:
            return hashlib.sha256(combined_data).hexdigest()
        return hashlib.sha512(combined_data).digest()

    def get_param_from_iteration(self, _i):
        # Find the dictionary with the matching timestamp
        result = None
        for item in self.aSecretParam:
            if item["iterations"] == _i:
                result = item
                break  # Exit the loop once the item is found
        return result

##
## conditions
##

    def set_condition(self, str_condition, iterations, salt):
        encoded_condition=self.encoder_decoder.encode(str_condition, {
                    "passphrase": self.passphraseForCondition,
                    "extra" : "condition",
                    "iterations": iterations,     
                    "salt" : salt 
                })
        self.add_encoded_condition_to_iteration(iterations, encoded_condition)
        return encoded_condition

    def get_encoded_condition(self, _i):
        item=self.get_param_from_iteration(_i)
        if item==None:
            return None
        return item["encoded_condition"]
        
    
    def add_encoded_condition_to_iteration(self, _i, encoded_condition):
        item=self.get_param_from_iteration(_i)
        if item!= None:
            item["encoded_condition"]=encoded_condition

    def get_encoded_condition(self, _condition, _i): 
        ## where do we get the condition? if we have it, OK
        if _condition!= "" and _condition!=None:
            return _condition
        
        ## if we do not hav e it, then from VC
        vc=identus.get_credential_for_iteration(self.user, _i)
        if vc!=None:
            return vc["claims"]["condition"]
        return None
    
##
## creds
##

    # use this to issue encoded_condition into a VC for the sender (own use for decoding)
    def ensure_condition(self, objShare):
        if self.withVC:
            try:
                vcOffer=self.notary.emitVCOffer(objShare)
                if vcOffer==None:
                    return False
                
                ## we have an offer, and we are the one to receive, so we accept it right now
                time.sleep(6)   ## shit identus delay
                offeredToHolder=identus.get_credential_for_thid(self.user, vcOffer["thid"])                

                if offeredToHolder== None:
                    raise Exception("Could not find RecordId") 

                ## sender accepts this offer (with its own recordId)
                time.sleep(6)   ## shit identus delay
                dataAcceptedByHolder = identus.postIdentus(self.user["entity"]["apiKey"], "issue-credentials/records/"+offeredToHolder["recordId"]+"/accept-offer", {
                    "subjectId": self.user["did"]
                })

                ## now ask notary to issue the VC
                dataVCByIssuer=self.notary.issueVCWithRecordId(vcOffer["recordId"])

                time.sleep(6)   ## shit identus delay
                vcToHolder=identus.get_credential_for_thid(self.user, vcOffer["thid"])                
                return vcToHolder

            except Exception as e:
                return False
             
        return True
    
    def sign_share_secret(self, objShare):
        vcOffer=self.notary.emitVCOffer(objShare)
        if vcOffer==None:
            return False
        return

    def notify_accepted_vc(self, did_receiver, objVC):
        ## the receiver has accepted the VC offer for our secret, we tell the notary to issue the VC
        self.notary.issueVCWithThid(objVC["thid"])

##
## secrets
##
    
    def encode_secret(self, plain_text_secret, plain_text_condition):
        # we replaced the random salt with a derived token from priv key + iteration 
        # salt = os.urandom(32)                          ## a random salt that sender shares with Notary

        ## store the iteration / salt with this timestamp
        self.aSecretParam.append({
            "iterations": self.iterations,
            "salt": self.salt  
        })

        ## share did, iteration and salt with notary
        self.notary.set_salt_for_iteration (self.user["did"], self.iterations, self.salt)       

        #ask the notary to encode the condition (notary must be able to accept / refuse condition)
        encoded_condition=self.notary.encode_condition(self.user["did"], plain_text_condition, self.iterations, self.passphraseForCondition) 

        ## with VC? then we ask the Notary to issue a VC for ourself as sender (otherwise we will not be able to decode)
        cond=self.ensure_condition({
            "did_receiver": self.user["did"],
            "did_sender": self.user["did"],
            "encoded_condition": encoded_condition,
            "iteration": self.iterations
        })
        if cond==False:
            return None

        encoded=self.encoder_decoder.encode(plain_text_secret, {
            "passphrase": self.passphraseForSecret,
            "extra": encoded_condition,
            "iterations": self.iterations,                 
            "salt" : self.salt 
        })

        # generate QRCode secret (+ condition if operating without VC)
        qr={
            "s": encoded, 
            "i": self.iterations
        }
        if self.withVC==False:
            qr["c"]=encoded_condition

        objQRSecret=self.generate_qrcode(qr)
        return {
            "i": self.iterations,        ## in plain text
            "sa": self.salt,             ## the salt            
            "pass": self.passphraseForSecret, ## the shared passphrase            
            "s": encoded,           ## encoded secret
            "c": encoded_condition, ## the condition for decoding the secret
            "q": objQRSecret["qrcode"],   ## base64 qrcode image
            "f": objQRSecret["filename"], ## file image of qrcode
            "e": objQRSecret["encoded"],  ## content of the qrcode,
        }
        
    def decode_secret(self, encoded, param):
        try:
            item=self.get_param_from_iteration(param["iterations"])
            if item== None and param["salt"]==None:
                raise Exception("No incoming params") 
            
            encoded_condition = None
                    
            if param and "encoded_condition" in param:                
                encoded_condition=param["encoded_condition"]

            else :
                if item and "encoded_condition" in item:
                    encoded_condition=item["encoded_condition"]

            salt = None
            if param and "salt" in param:
                salt=param["salt"]
            else :
                if item and "salt" in item:
                    salt=item["salt"]

            passphrase = self.passphraseForSecret
            if param and "passphrase" in param:
                passphrase=param["passphrase"]
            else :
                if item and "passphrase" in item:
                    passphrase=item["passphrase"]

            # get the condition
            objDecodeParam={
                "passphrase": passphrase,
                "extra": encoded_condition,
                "iterations": param["iterations"],                 
                "salt" : salt
            }

            decoded=self.encoder_decoder.decode(encoded, objDecodeParam)
            if decoded==None:
                raise Exception("Could not decode") 
            
            return {
                "decoded": decoded.decode('utf-8'),
                "isConditionPassed": True
            }
                
        except Exception as e:
            return {
                "error": e,
                "decoded": None,
                "isConditionPassed": False
            }

##
## qrCodes
##
        
    def generate_qrcode(self, objS):
        qr = qrcode.QRCode(
            version=1,  # Version determines the size of the QR code
            error_correction=qrcode.constants.ERROR_CORRECT_L,  # Error correction level
            box_size=10,  # Size of each box in the QR code grid
            border=4,  # Border size
        )

        # Add data to the QR Code
        encoded='{"s": "'+str(objS['s'])+'", "i": '+str(objS['i'])+'}'
        if self.withVC==False:
            encoded='{"s": "'+str(objS['s'])+'", "c": "'+str(objS['c'])+'", "i": '+str(objS['i'])+'}'
        qr.add_data(encoded)
        qr.make(fit=True)

        # Save the QR code as a base64-encoded image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
        buffer.close()

        # Save the QR code to a file
        filename="temp/qr_"+str(time.time())+".png"
        img.save(filename)

        return {
            "encoded": encoded,
            "qrcode": qr_code_base64,
            "filename": filename
        }
