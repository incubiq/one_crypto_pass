## ocp_auth

AUTH_ALICE={
    "name": "Alice",
    "did": "did:prism:04cfc06a2f98b8f0b341a1f0538dd0927bc899e7063f700e0a9a5c9bb8cb6392",
    "wallet": {
        "id": "b0c21737-6644-432b-9ce3-9864d6933d8f",
        "name": "wallet for Alice",
        "seed": "aaaa4785ce6d548134020f610b76102ca1075d323672a75ec8c9a27a7b8607e3b9b384e43b77bb08f8d5159651ae38b98573f7ecc79f2d7e1f220371ce60cf8a",
        "private": "ed25519e_sk1epgkgh6kysctm3tsum2rzl4v07yfmd5qmdtnjygtt5jajkf35pq9hmulagey0src3mjl0haww9mg98pf59zwy25fsmyp4fz4a0nfnsqa0004z",    
    },
    "entity": {
        "self": "/iam/entities/37c9b1f3-be95-4176-ba85-0a619b75844e",
        "id": "37c9b1f3-be95-4176-ba85-0a619b75844e",
        "name": "Bob Identity",
        "apiKey": "Alice_api_key_secret"
    },
    "connection": "ad228e76-2050-4e47-833d-d773d4d8108b"
}

AUTH_BOB={
    "name": "Bob",
    "did": "did:prism:c9d33452db742dffbb25e120578f13ffafd9a7d97bb14ab46780e23a2bddcb0c",
    "wallet": {
        "id": "d9e2e359-0b9f-4a6b-9c58-fe0c59ac3ddb",
        "name": "wallet for Bob",
        "seed": "bbbb4785ce6d566654020f610b76102ca1075d3bb672a75ec8c9a27a7b8607e3b9b384e43b77bb08f8d5159651ae38b98573f7ecc79f2d7e1f1cc371ce60cf8b",
        "private": "ed25519e_sk17zk4ma5pr3duhvw4cqpkyqs86datm7cts7cvg7h6nrxfphys7dvz2vl8cvav8vhfvc2kx6lpwfay7a6zqarhph3tyvp4snrmlj2rukqmlsy77",
    },
    "entity": {
        "self": "/iam/entities/a784d6b3-524a-451c-a660-59c18efe062b",
        "id": "a784d6b3-524a-451c-a660-59c18efe062b",
        "name": "Notary Identity",
        "apiKey": "BOB_api_key_secret"
    },
    "connection": "8bb626b9-b814-49ea-9eab-e46ba4b37b64"
}

AUTH_NOTARY={
    "name": "Notary",
    "did": "did:prism:dd74fce7283e6a9ff8dc149975281f996a4baa93f166d8aecd0e540d72e526c9",
    "wallet": {
        "id": "f9e294d9-e62b-4725-8dc9-92b6518b12a6",
        "name": "wallet for Notary",
        "seed": "eeeee785ce6d548134020f610b76102ca1075d323672a75ec8c9a27a7b8607e3b9b384e43b77bb08f8d5159651ae38b98573f7ecc79f2d7e1f220371ce60cf8a",        
        "private": "ed25519e_sk17zk4ma5pr3duhvw4cqpkyqs99datm7cts7cvg7h6nrxfphys7dvz2vl8cvav8vhfvc2kx6lpwfay888zqarhph3tyvp4snrmlj2rukqmlsy33",
    },
    "entity": {
        "self": "/iam/entities/a784d6b3-524a-451c-a660-59c18efe062b",
        "id": "a784d6b3-524a-451c-a660-59c18efe062b",
        "name": "Notary Identity",
        "apiKey": "Notary_api_key_secret"
    },
    "connections": [{
        "thid": "8bb626b9-b814-49ea-9eab-e46ba4b37b64"
    }, {
        "thid": "ad228e76-2050-4e47-833d-d773d4d8108b"
    }]
}

class InMemDB:
    def __init__(self):
        return
        
    def getAlice(self):
        return AUTH_ALICE
    
    def getBob(self):
        return AUTH_BOB
    
    def getNotary(self):
        return AUTH_NOTARY

    def getUsers(self): 
        return[AUTH_ALICE, AUTH_BOB]

    def getUserByDid(self, _did):
        if _did== AUTH_ALICE["did"]:
            return AUTH_ALICE
        
        if _did== AUTH_BOB["did"]:
            return AUTH_BOB
        
        if _did== AUTH_NOTARY["did"]:
            return AUTH_NOTARY
        return None
