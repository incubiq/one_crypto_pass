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
        "name": "Alice Identity",
        "apiKey": "Alice_api_key_secret"
    },
    "connection": "815f2d5e-a8be-492d-b1c0-db41e94964b1"
}

AUTH_ALICE2={
    "name": "Alice",
    "did": "did:prism:7e1d3868b811954f223953efb92988e141eb0aefb5ca8c60d788ad414c1b3f11",
    "wallet": {
        "id": "ef6bd6fd-82a2-47c0-99f3-7c03c77ef1c9",
        "name": "wallet for Alice2",
        "seed": "aaaa4785ce6d548134020f610b76102ca1075d323672a75ec8c9a27a7b8607e3b9b384e43b77bb08f8d5159651ae38b98573f7ecc79f2d7e1f220371ce60fefe",
        "private": "ed25519e_sk1epgkgh6kysctm3tsum2rzl4v07yfmd5qmdtnjygtt5jvbyf35pq9hmulagey0src3mjl0haww9mg98pf59zwy25fsmyp4fz4a0nfnsqa00055",    
    },
    "entity": {
        "self": "/iam/entities/78dd416e-a7bf-4fd9-a074-a0216472fc0a",
        "id": "78dd416e-a7bf-4fd9-a074-a0216472fc0a",
        "name": "Alice2 Identity",
        "apiKey": "Alice2_api_key_secret"
    },
    "connection": "6f67fc0f-0eff-47b9-b121-33662bb1a986"
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

## V2 identus

AUTH_ALICE_V2={
    "name": "Alice",
    "did": "did:prism:7e1d3868b811954f223953efb92988e141eb0aefb5ca8c60d788ad414c1b3f11",
    "wallet": {
        "id": "c141c6cc-d165-405f-8fae-4746e8f1bbd7",
        "name": "wallet for Alice",
        "seed": "aaaa4785ce6d548134020f610b76102ca1075d323672a75ec8c9a27a7b8607e3b9b384e43b77bb08f8d5159651ae38b98573f7ecc79f2d7e1f220371ce60fefe",
        "private": "ed25519e_sk1epgkgh6kysctm3tsum2rzl4v07yfmd5qmdtnjygtt5jajkf35pq9hmulagey0src3mjl0haww9mg98pf59zwy25fsmyp4fz4a0nfnsqa0004z",    
    },
    "entity": {
       "self": "/iam/entities/f573d5ec-838b-4865-95c4-ffa70101e20c",
        "id": "f573d5ec-838b-4865-95c4-ffa70101e20c",
        "name": "Alice Identity",
        "apiKey": "Alice_api_key_secret"
    },
    "connection": "db0423d3-cd4d-41c1-91f1-b1a696ffd0a7"
}

AUTH_BOB_V2={
    "name": "Bob",
    "did": "did:prism:c9d33452db742dffbb25e120578f13ffafd9a7d97bb14ab46780e23a2bddcb0c",
    "wallet": {
        "id": "42d94701-ac0b-4f62-89a5-34f1106337a3",
        "name": "wallet for Bob",
        "seed": "bbbb4785ce6d566654020f610b76102ca1075d3bb672a75ec8c9a27a7b8607e3b9b384e43b77bb08f8d5159651ae38b98573f7ecc79f2d7e1f1cc371ce60cf8b",
        "private": "ed25519e_sk17zk4ma5pr3duhvw4cqpkyqs86datm7cts7cvg7h6nrxfphys7dvz2vl8cvav8vhfvc2kx6lpwfay7a6zqarhph3tyvp4snrmlj2rukqmlsy77",
    },
    "entity": {
        "self": "/iam/entities/b6c2267e-6043-42b3-a8e0-d00f9cfdf9be",
        "id": "b6c2267e-6043-42b3-a8e0-d00f9cfdf9be",
        "name": "Bob Identity",
        "apiKey": "BOB_api_key_secret"
    },
    "connection": "31d83196-5ba4-44c9-9d9e-1426dc839d2b"
}

AUTH_NOTARY_V2={
    "name": "Notary",
    "did": "did:prism:dd74fce7283e6a9ff8dc149975281f996a4baa93f166d8aecd0e540d72e526c9",
    "wallet": {
        "id": "41b7c152-c18b-4245-85d2-68ce8977634f",
        "name": "wallet for Notary",
        "seed": "eeeee785ce6d548134020f610b76102ca1075d323672a75ec8c9a27a7b8607e3b9b384e43b77bb08f8d5159651ae38b98573f7ecc79f2d7e1f220371ce60cf8a",        
        "private": "ed25519e_sk17zk4ma5pr3duhvw4cqpkyqs99datm7cts7cvg7h6nrxfphys7dvz2vl8cvav8vhfvc2kx6lpwfay888zqarhph3tyvp4snrmlj2rukqmlsy33",
    },
    "entity": {
        "self": "/iam/entities/36cdd109-0d9f-43b0-ade2-9c4b44b6f3ed",
        "id": "36cdd109-0d9f-43b0-ade2-9c4b44b6f3ed",
        "name": "Notary Identity",
        "apiKey": "Notary_api_key_secret"
    },
    "connections": [{
        "thid": "db0423d3-cd4d-41c1-91f1-b1a696ffd0a7"
    }, {
        "thid": "31d83196-5ba4-44c9-9d9e-1426dc839d2b"
    }]
}

class InMemDB:
    def __init__(self):
        return
        
    def getAlice(self):
        return AUTH_ALICE_V2
    
    def getBob(self):
        return AUTH_BOB_V2
    
    def getNotary(self):
        return AUTH_NOTARY_V2

    def getUsers(self): 
        return[AUTH_ALICE_V2, AUTH_BOB_V2]

    def getUserByDid(self, _did):
        if _did== AUTH_ALICE_V2["did"]:
            return AUTH_ALICE_V2
                
        if _did== AUTH_BOB_V2["did"]:
            return AUTH_BOB_V2
        
        if _did== AUTH_NOTARY_V2["did"]:
            return AUTH_NOTARY_V2
        return None
