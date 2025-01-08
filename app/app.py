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
    _did = request.form.get('did', None)
    secret = request.form.get('secret', None)
    condition = request.form.get('condition', None)
    title = request.form.get('title', None)

    # Encode the text
    gSender.set_did(_did)
    gSender.generate_passphrase("alice_private_key_of_did")
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

@app.route('/decode')
def decode():
    return render_template('decode_as_sender.html')

@app.route('/decode', methods=['POST'])
def post_decode():
    _username = request.form.get('username', None)
    _did = request.form.get('did', None)

    # found in the QR code
    secret_s = request.form.get('secret_s', None)
    secret_i = request.form.get('secret_i', None)
    secret_c = request.form.get('secret_c', None)

    # kept secretly by sender and receiver (via didcomm?? where stored?)
    secret_pass=gSender.get_passphrase("alice_private_key_of_did", secret_i)

    # kept by sender and notary for decoding
    secret_sa = request.form.get('secret_sa', None)

    # Preprocess the string to replace single quotes with double quotes and add double quotes to keys
    #secret = request.form.get('secret', None)
    #secret = secret.replace("'", '"').replace("s:", '"s":').replace("i:", '"i":')
    #objSecret = ast.literal_eval(secret)        # Convert to a dictionary

    decoded_json=None
    decoded_condition=None

    # user decode own secret?
    if secret_sa :
        decoded_condition = gSender.decode_secret(secret_c, {
            "iterations": int(secret_i),
            "salt": base64.b64decode(secret_sa),
            "passphrase": secret_pass,
            "encoded_condition": "condition"
        })        

        decoded_json = gSender.decode_secret(secret_s, {
            "iterations": int(secret_i),
            "salt": base64.b64decode(secret_sa),
            "passphrase": secret_pass,
            "encoded_condition": secret_c
        })        
    else :   
        if secret_pass:      
            decoded_json = gReceiver.decode_secret(secret_s, {
                "notary": gSender.get_notary(),  
                "iterations": int(secret_i),
                "encoded_condition": None,
                "passphrase": secret_pass,
            })
        else :
            return render_template('decoded.html', secret={
                "encoded":  secret_s,
                "decoded": "COULD NOT DECODE"
            })

    return render_template('decoded.html', secret={
        "encoded":  secret_s,
        "decoded": decoded_json,
        "condition": decoded_condition
    })

if __name__ == '__main__':
    app.run(debug=True)  # Starts the server at http://127.0.0.1:5000
