## ocp_app

from inmem_db import InMemDB
from my_didcomm import genKey, createMessage, async_packMessage, async_unpackMessage


gInMemDB=InMemDB()

# App entry
testSend=genKey()
testReceive=genKey()
objAlice=gInMemDB.getAlice()
objBob=gInMemDB.getBob()

msg=createMessage ({
    "content": "hello world", 
    "fromDid": objAlice["did"], 
    "toDid": objBob["did"]})

packed=async_packMessage({
    "message": msg,
    "fromDid": objAlice["did"], 
    "toDid": objBob["did"]
})

unpacked=async_unpackMessage({
    "message": packed
})
