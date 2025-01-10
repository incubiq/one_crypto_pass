import requests
import time

def getRoot():
    return "https://identus.opensourceais.com/cloud-agent/"

def getHeaders(_key) :
    return {
        "apikey": _key,
        "Content-Type": "application/json"
    }

# Making GET request
def getIdentus(_key, _url):
    url=getRoot()+_url
    headers=getHeaders(_key)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Making POST request
def postIdentus(_key, _url, _payload):
    url=getRoot()+_url
    headers=getHeaders(_key)
    response = requests.post(url, headers=headers, json=_payload)
    if response.status_code == 201:
        return response.json()
    else:
        return None


# Making PATCH request
def patchIdentus(_key, _url, _payload):
    url=getRoot()+_url
    headers=getHeaders(_key)
    response = requests.patch(url, headers=headers, json=_payload)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Making DELETE request
def deleteIdentus(_key, _url):
    url=getRoot()+_url
    headers=getHeaders(_key)
    response = requests.delete(url, headers=headers)
    if response.status_code == 204:
        return response.json()
    else:
        return None

def async_createVCOfferWithoutSchema(objParam):
    try:
        objPost={
            "validityPeriod": objParam["validity"],
            "schemaId": None,
            "credentialFormat": "JWT",
            "claims": objParam["claims"],
            "automaticIssuance": False,
            "issuingDID": objParam["author"],
            "connectionId": objParam["connection"]
        }
        dataRet = postIdentus(objParam["key"], "issue-credentials/credential-offers/", objPost)
        return dataRet
    
    except Exception as e:
        return None
