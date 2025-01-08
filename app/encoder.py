
## ocp_utils

import os
import base64

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