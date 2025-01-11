## ocp_notary

from encoder import EncoderDecoder
from inmem_db import InMemDB
import base64
import json
import identus

file_path = 'notary.txt'

class Notary:
    def __init__(self):
        self.aSecretParam=self.read_json_from_file()                    ## array of secret param  ## array of secret param  (timestamp, salt)
        self.encoder_decoder = EncoderDecoder()                ## a decoder engine
        self.db=InMemDB()              
        self.notary=self.db.getNotary()

##
## DB
##

    ## simulating our DB (txt file for now)
    def read_json_from_file(self):
        try:
            with open(file_path, 'r') as file:
                # Read the content and parse as JSON
                data = json.load(file)

            self.aSecretParam=data
            return data
        except FileNotFoundError:
            print(f"File {file_path} not found. Returning empty dictionary.")
            return []  # Return an empty dictionary if the file doesn't exist
        except json.JSONDecodeError:
            print(f"Error decoding JSON in file {file_path}. Returning empty dictionary.")
            return []

    # Function to write JSON data to a text file
    def write_json_to_file(self):
        try:
            with open(file_path, 'w') as file:
                # Write the JSON data in pretty-printed format
                json.dump(self.aSecretParam, file, indent=4)
            print(f"Data successfully written to {file_path}")
        except Exception as e:
            print(f"Error writing to file {file_path}: {e}")

##
## keeping track of important data
##

    ## Notary can check sender did for a particular iteration
    def _check_did_for_iteration(self, _i, _did):
        result = None
        for item in self.aSecretParam:
            if item["iterations"] == _i:
                result = item
                break  # Exit the loop once the item is found
        if result==None:
            return False
        if result["did"]==_did:
            return True
        return False

    def _get_item_for_iteration(self, _i):
        for item in self.aSecretParam:
            if item["iterations"] == _i:
                return item
        return None
    
    ## Notary can retrieve its salt for a particular iteration
    def _get_salt_for_iteration(self, _i):
        item=self._get_item_for_iteration(_i)
        if item==None:
            return None
        return base64.b64decode(item["salt"].encode('utf-8'))
            
    ## for each iteration value, we keep the salt and did
    def set_salt_for_iteration(self, _did, _i, salt):
        if self._get_salt_for_iteration(_i) == None:
            self.aSecretParam.append({
                "did": _did,
                "iterations": _i,
                "salt": base64.b64encode(salt).decode('utf-8')
            })
            self.write_json_to_file()
            print("=> Notary was set with salt = "+str(salt))
        else: 
            print("=> Notary already aware of this salt = "+str(salt))

    def add_passcond_to_iteration(self, _did, _i, _pass):
        item=self._get_item_for_iteration(_i)
        if item!=None:
            item["passcond"]=_pass
            self.write_json_to_file()

##
## encode/decode condition
##

    ## only notary can decode the encoded condition
    def _decode_encoded_condition(self, encoded_condition, param):
        if encoded_condition==None:
            return None

        # does the notary have recollection of this iteration for this did sender?        
        if self._check_did_for_iteration(param["iterations"], param["did_sender"])==False:
            return None

        item=self._get_item_for_iteration(param["iterations"])
        if item!=None:
            decoded=self.encoder_decoder.decode(encoded_condition, {
                "passphrase": item["passcond"],
                "extra": "condition",
                "iterations": param["iterations"],            
                "salt" : self._get_salt_for_iteration(param["iterations"]) 
            })
            if decoded==None:
                return None
            return decoded.decode('utf-8')
        return None
    
    ## Notary can check if the condition os valid or not
    def _is_condition_valid(self, encoded_condition, param):
        condition=self._decode_encoded_condition(encoded_condition, param)
        if condition==None:
            return False
        
        ## TODO : really check if condition is met (for now we return True)
        return True
    
    def encode_condition(self, did_sender, plain_text_condition, iterations, passphrase) :
        ## based on the plain_text_condition, decide if we accept of not (at moment we accept all)
        bIsConditionAccepted=True
        bIsConditionAccepted=self._check_did_for_iteration(iterations, did_sender)
        if bIsConditionAccepted:
            try:
                salt=self._get_salt_for_iteration(iterations)
                self.add_passcond_to_iteration(did_sender, iterations, passphrase)
                encoded_condition=self.encoder_decoder.encode(plain_text_condition, {
                    "passphrase": passphrase,
                    "extra" : "condition",
                    "iterations": iterations,     
                    "salt" : salt 
                })

                return encoded_condition
            except Exception as e:
                return None            
        return None
    
##
## Verif Creds
##

    def emitVCOffer(self, objShare) :
        objVC={
            "sender" : objShare["did_sender"],
            "condition": objShare["encoded_condition"],
            "iteration": objShare["iteration"],
            "title": objShare["title"]
        }

        ## get comm channel for Notary - toDid
        receiver=self.db.getUserByDid(objShare["did_receiver"])
        if receiver==None:
            return None
        
        connection=receiver["connection"]
        dataOfferByIssuer= identus.async_createVCOfferWithoutSchema({
            "connection": connection,
            "validity": 3600000,
            "key": self.notary["entity"]["apiKey"],
            "author": self.notary["did"],
            "claims": objVC
        })

        return dataOfferByIssuer

    def issueVCWithRecordId(self, recordId) :
        vc=identus.postIdentus(self.notary["entity"]["apiKey"], "issue-credentials/records/"+recordId+"/issue-credential", {})
        return vc

    def issueVCWithThid(self, thid) :
        offer=identus.get_credential_for_thid(self.notary, thid)
        if offer:
            vc=identus.postIdentus(self.notary["entity"]["apiKey"], "issue-credentials/records/"+offer["recordId"]+"/issue-credential", {})
            return vc
        return None

##
## encode/decode secret
##

    ## public decode_secret API that anyone can call into notary (maybe behing auth later?)
    def decode_secret(self, encoded, param):
        try:
            ## notary must first check if condition is valid
            if self._is_condition_valid(param["encoded_condition"], param) == False:
                return {
                    "error": "Condition was not fulfilled",
                    "decoded": None,
                    "isConditionPassed": False
                }

            ## condition is met, notary can decode the secret
            decoded=self.encoder_decoder.decode(encoded, {
                "passphrase": param["passphrase"],
                "extra": param["encoded_condition"],
                "iterations": param["iterations"],                 
                "salt" : self._get_salt_for_iteration(param["iterations"]) 
            })

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
                "isConditionPassed": True
            }
