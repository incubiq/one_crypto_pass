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
    
async def main():
    # Step 1: Create DIDDoc for Alice and Bob 
    alice_did_doc = getDidDoc(
        "did:example:alice",        # did
        "addr_test1qpseam5yw9yq6lpvev4lpv7cjnd79n740ul8ktlggffa5aq3pn85twq2wsctps9v7swhq7nv5ckuxaezf29pfeqdy5hs5xqkfk",       # public key
    )

    bob_did_doc = getDidDoc(
        "did:example:bob",        # did
        "addr_test1qry393l8jvjt9tkwmh5ku7qgt4ykh2pwg5tsslsnpatvy7t6rfvlnm8p37l49sjvtqaxqdf5rfd258ahyz70g35ytvss7jwmhm",
    )

    # Step 2: Create DIDComm messages (No secrets, just simple messages)
    message_from_alice = Message(
        type="BasicMessage",  # Type is required
        body={"text": "Hello from Alice!"},  # The message body content
        frm="did:example:alice",  # Alice's DID (sender)
        to=["did:example:bob"],  # Bob's DID (recipient)
        created_time=int(datetime.now().timestamp()),  # Optional: time of creation
        expires_time=None,  # Optional: expiration time, can be left as None
    )

    # Step 3: Alice sends and packs the message
    resolvers_config = {}  # Set up your resolvers_config appropriately
    packed_message = await pack_plaintext(resolvers_config, message_from_alice)
    
    print("Packed Message:", packed_message)

    # Step 4: Bob receives and unpacks the message
    packed_message = packed_message.packed_msg
    unpacked_message = await unpack(resolvers_config, packed_message)
    print("Unpacked Message:", unpacked_message)

    # Step 5: Bob reads the message
    print("Bob received message:", unpacked_message.message.body)

# Run the async main function
asyncio.run(main())
