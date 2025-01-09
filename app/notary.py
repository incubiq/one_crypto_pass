## ocp_notary

from encoder import Encoder
import base64
import json

file_path = 'notary.txt'

class Notary:
    def __init__(self):
        self.aSecretParam=self.read_json_from_file()                    ## array of secret param  ## array of secret param  (timestamp, salt)
        self.decoder = Encoder()                ## a decoder engine

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


    ## Notary can retrieve its salt for a particular timestamp
    def _get_salt_for_iteration(self, _i):
        result = None
        for item in self.aSecretParam:
            if item["iterations"] == _i:
                result = item
                break  # Exit the loop once the item is found
        if result==None:
            return None
        return base64.b64decode(result["salt"].encode('utf-8'))
            
    ## for each timestamp value, we keep a salt (at this stage, in memory only - store in DB later??)
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
        try:
            ## notary must first check if condition is valid
            if self._is_condition_valid(param["encoded_condition"], param) == False:
                return {
                    "error": "Condition was not fulfilled",
                    "decoded": None,
                    "isConditionPassed": False
                }

            ## condition is met, notary can decode the secret
            decoded=self.decoder.decode(encoded, {
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
