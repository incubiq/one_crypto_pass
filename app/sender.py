## ocp_sender
import os
import random
import time
import qrcode
import base64
import hashlib
from io import BytesIO

from encoder import Encoder
from notary import Notary

class Sender:
    def __init__(self):
        self.passphrase=None
        self.iterations=None
        self.notary = Notary()                              ## our notary
        self.encoder = Encoder()
        self.aSecretParam=[]         ## array of secret param  (timestamp, iterations, salt, encoded_condition)

    def generate_passphrase(self, private_key: str) -> str:
        iterations = random.randint(1,100000)        ## a random iteration 
        self.iterations = iterations
        self.passphrase=self.get_passphrase(private_key, iterations)
        print("=> Sender iterations set to = "+str(self.iterations))
        print("=> Sender passphrase set to = "+self.passphrase)

    def get_passphrase(self, private_key: str, iteration)  -> str:
        # Combine the private key and the big number as bytes
        combined_data = (private_key + str(iteration)).encode('utf-8')
        
        # Generate a unique token using SHA-256
        token = hashlib.sha256(combined_data).hexdigest()
        return token
        
    def set_condition(self, str_condition, iterations, salt):
        encoded_condition=self.encoder.encode(str_condition, {
                    "passphrase": self.passphrase,
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
        
    def set_did(self, _did):
        self.did=_did
    
    def get_notary(self):
        return self.notary
    
    def add_encoded_condition_to_iteration(self, _i, encoded_condition):
        item=self.get_param_from_iteration(_i)
        if item!= None:
            item["encoded_condition"]=encoded_condition

    def get_param_from_iteration(self, _i):
        # Find the dictionary with the matching timestamp
        result = None
        for item in self.aSecretParam:
            if item["iterations"] == _i:
                result = item
                break  # Exit the loop once the item is found
        return result
    
    def encode_secret(self, plain_text_secret, plain_text_condition):
        salt = os.urandom(32)                          ## a random salt that sender shares with Notary

        ## store the iteration / salt with this timestamp
        self.aSecretParam.append({
            "iterations": self.iterations,
            "salt": salt  
        })
        self.notary.set_salt_for_iteration (self.did, self.iterations, salt)       ## share this salt with notary
        encoded_condition=self.set_condition(plain_text_condition, self.iterations, salt)        ## get the encoded condition (will be shared with receiver)

        encoded=self.encoder.encode(plain_text_secret, {
            "passphrase": self.passphrase,
            "extra": encoded_condition,
            "iterations": self.iterations,                 
            "salt" : salt 
        })

        # generate QRCode secret + condition
        objQRSecret=self.generate_qrcode({
            "s": encoded, 
            "c": encoded_condition, 
            "i": self.iterations
        })
        return {
            "i": self.iterations,        ## in plain text
            "sa": salt,             ## the salt            
            "pass": self.passphrase, ## the shared passphrase            
            "s": encoded,           ## encoded secret
            "c": encoded_condition, ## the condition for decoding the secret
            "q": objQRSecret["qrcode"],   ## base64 qrcode image
            "f": objQRSecret["filename"], ## file image of qrcode
            "e": objQRSecret["encoded"],  ## content of the qrcode,
        }
    
    def decode_secret(self, encoded, param):
        item=self.get_param_from_iteration(param["iterations"])
        if item== None and param["salt"]==None:
            return None
        
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

        passphrase = self.passphrase
        if param and "passphrase" in param:
            passphrase=param["passphrase"]
        else :
            if item and "passphrase" in item:
                passphrase=item["passphrase"]

        # get the condition

        decoded=self.encoder.decode(encoded, {
            "passphrase": passphrase,
            "extra": encoded_condition,
            "iterations": param["iterations"],                 
            "salt" : salt
        })
        if decoded==None:
            return None
        return decoded.decode('utf-8')
     
    def generate_qrcode(self, objS):
        qr = qrcode.QRCode(
            version=1,  # Version determines the size of the QR code
            error_correction=qrcode.constants.ERROR_CORRECT_L,  # Error correction level
            box_size=10,  # Size of each box in the QR code grid
            border=4,  # Border size
        )

        # Add data to the QR Code
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
