#ocp_didcomm

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import asyncio
from datetime import datetime

from didcomm.message import Message
from didcomm.pack_plaintext import pack_plaintext
from didcomm.unpack import unpack
from pydid import DIDCommService
from pydid.doc import DIDDocument
from didcomm.did_doc.did_doc import DIDDoc


def getDidDoc(_did, _pubKey):
    return DIDDoc(
        id=_did,
        verification_method=[{
            "id": _did+"#key1",
            "type": "Ed25519VerificationKey2018",
            "controller": _did,
            "public_key_base58": _pubKey
        }],
        service=[DIDCommService(
            id=_did+"#service",
            type="DIDCommMessaging",  # Updated type
            service_endpoint="http://example.com",
            recipient_keys=[_did+"#key1"]  # Added recipientKeys
        )]
    )
    
def createMessage(objParam) :
    msg = Message(
        type="BasicMessage",  # Type is required
        body={"text": objParam["content"]},  # The message body content
        frm=objParam["fromDid"],  # DID (sender)
        to=[objParam["toDid"]],  #  DID (recipient)
        created_time=int(datetime.now().timestamp()),  # Optional: time of creation
        expires_time=None,  # Optional: expiration time, can be left as None
    )
    return msg


async def async_packMessage(objParam):    
    resolvers_config = {}  # Set up your resolvers_config appropriately
    packed_message = await pack_plaintext(resolvers_config, objParam["message"])
    packed_message = packed_message.packed_msg
    print("Packed message:", packed_message)  # This is the encrypted message
    return packed_message

async def async_unpackMessage(objParam):
    resolvers_config = {}  # Set up your resolvers_config appropriately
    unpacked_message = await unpack(resolvers_config, objParam["message"])
    print("Unpacked Message:", unpacked_message)
    return unpacked_message

def genKey():
    # Generate keys for the sender
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes=private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()  # No encryption for raw private key
    )

    pub_bytes=public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return {
        "private": private_key,
        "public": public_key,
        "priv_bytes": priv_bytes,
        "pub_bytes": pub_bytes
    }

