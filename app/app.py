## ocp_app

from flask import Flask, render_template, request, jsonify
from http.server import BaseHTTPRequestHandler, HTTPServer
import ast
import base64

from inmem_db import InMemDB
from auth import Authenticator
from sender import Sender
from receiver import Receiver
from my_didcomm import genKey, createMessage, async_packMessage, async_unpackMessage


gInMemDB=InMemDB()
gAuthenticator=Authenticator()
gSender = Sender()
gReceiver = Receiver()

class MyHandler(BaseHTTPRequestHandler):
    global gSender
    global gReceiver
    global gAuthenticator

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

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    name = request.form.get('username', None)
    objAuth=gAuthenticator.authenticate(name)
    return render_template('auth.html', user={
        "name": objAuth["name"],
        "addr": objAuth["addr"],
        "did": objAuth["did"]
    })

@app.route('/encode')
def encode():
    return render_template('encode.html')

@app.route('/encode', methods=['POST'])
def post_encode():
    _username = request.form.get('username', None)
    objUser=gAuthenticator.authenticate(_username)
    _did = request.form.get('did', None)
    secret = request.form.get('secret', None)
    condition = request.form.get('condition', None)
    title = request.form.get('title', None)

    # Encode the text
    gSender.set_did(_did)
    gSender.generate_passphrase(objUser["private"])
    encoded_json = gSender.encode_secret(secret, condition)
    return render_template('encoded.html', secret={
        "sa": base64.b64encode(encoded_json["sa"]).decode('utf-8'),         # salt
#        "pass": encoded_json["pass"],                                       # passphrase
        "s": encoded_json["s"],     # encoded secret
        "c": encoded_json["c"],     # encoded condition
        "i": encoded_json["i"],     # iteration
        "e": encoded_json["e"],     # content of the qrcode
        "q": encoded_json["q"],     # qrcode
        "t": title                  # display title
    })

@app.route('/share', methods=['POST'])
def post_share():
    _username = request.form.get('username', None)
    objUser=gAuthenticator.authenticate(_username)
    objBob=gAuthenticator.authenticate("Bob")
    secret_i = request.form.get('secret_i', None)
    secret_c = request.form.get('secret_c', None)

    gSender.share_condition(objBob["did"], secret_c)
    secret_pass=gSender.get_unique_token(gSender.TOKEN_PASSPHRASE_FOR_SECRET(), objUser["private"], secret_i)
    gReceiver.set_passphrase(secret_pass)

    return render_template('shared_with.html')


@app.route('/decode_as_sender')
def decode_as_sender():
    return render_template('decode_as_sender.html')

@app.route('/decode_as_receiver')
def decode_as_receiver():
    return render_template('decode_as_receiver.html')

@app.route('/decoded_as_sender', methods=['POST'])
def post_decode_as_sender():
    _username = request.form.get('username', None)
    _did = request.form.get('did', None)
    objUser=gAuthenticator.authenticate(_username)

    # found in the QR code
    secret_s = request.form.get('secret_s', None)
    secret_i = request.form.get('secret_i', None)
    secret_c = request.form.get('secret_c', None)

    # kept secretly by sender and receiver (via didcomm?? where stored?)
    secret_pass=gSender.get_unique_token(gSender.TOKEN_PASSPHRASE_FOR_SECRET(), objUser["private"], secret_i)
    secret_passCond=gSender.get_unique_token(gSender.TOKEN_PASSPHRASE_FOR_CONDITION(), objUser["private"], secret_i)
    secret_sa=gSender.get_unique_token(gSender.TOKEN_SALT(), objUser["private"], secret_i)

    decoded_json=None
    decoded_condition=None

    # user decode own secret?
    try:
        decoded_condition = gSender.decode_secret(secret_c, {
            "iterations": int(secret_i),
            "salt": secret_sa,
            "passphrase": secret_passCond,
            "encoded_condition": "condition"
        })        

        decoded_json = gSender.decode_secret(secret_s, {
            "iterations": int(secret_i),
            "salt": secret_sa,
            "passphrase": secret_pass,
            "encoded_condition": secret_c
        })        

        if decoded_json["decoded"] == None:
            raise Exception("Could not decode") 
        
        return render_template('decoded.html', secret={
            "encoded":  secret_s,
            "decoded": decoded_json["decoded"],
            "condition": decoded_condition["decoded"]
        })
    except Exception as e:
        return render_template('decoded.html', secret={
            "encoded":  secret_s,
            "decoded": "COULD NOT DECODE"
        })


@app.route('/decoded_as_receiver', methods=['POST'])
def post_decode_as_receiver():

    # found in the QR code
    secret_s = request.form.get('secret_s', None)
    secret_i = request.form.get('secret_i', None)
    secret_c = request.form.get('secret_c', None)
    did_sender = request.form.get('did_sender', None)

    # kept receiver (via didcomm?? where stored?)

    decoded_json=None

    # receiver decode sender secret
    try:
        gReceiver.set_encoded_condition(secret_c)
        decoded_json = gReceiver.decode_secret(secret_s, {
            "notary": gSender.get_notary(),  
            "iterations": int(secret_i),
            "passphrase": gReceiver.get_passphrase(),
            "did_sender": did_sender
        })

        if decoded_json["decoded"] == None:
            raise Exception("Could not decode") 

        return render_template('decoded.html', secret={
            "encoded":  secret_s,
            "decoded": decoded_json["decoded"],
            "condition": "Fulfilled"
        })
    
    except Exception as e:
        return render_template('decoded.html', secret={
            "encoded":  secret_s,
            "decoded": "COULD NOT DECODE",
            "condition": "NOT YOUR BUSINESS"
        })

if __name__ == '__main__':
    app.run(debug=True)  # Starts the server at http://127.0.0.1:5000
