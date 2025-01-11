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

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

##
## login
##

def authenticate(_request) :
    name = _request.form.get('username', None)
    objAuth=gAuthenticator.authenticate(name)
    objAuth["isSender"]= objAuth["name"]=="Alice"
    if objAuth["isSender"]:
        gSender.set_user(objAuth)
    else:
        gReceiver.set_user(objAuth)
    return objAuth

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    objUser=authenticate(request)
    return render_template('auth.html', user={
        "isSender": objUser["isSender"],
        "name": objUser["name"],
        "addr": objUser["wallet"]["id"],
        "did": objUser["did"]
    })

##
## encoding
##

@app.route('/encode')
def encode():
    return render_template('encode.html')

@app.route('/encode', methods=['POST'])
def post_encode():
    objUser=authenticate(request)

    secret = request.form.get('secret', None)
    condition = request.form.get('condition', None)
    title = request.form.get('title', None)
    hasVC = request.form.get('hasVC', None)


    # Encode the text
    gSender.set_with_vc(hasVC=="true")
    gSender.generate_passphrase(objUser["wallet"]["private"])
    encoded_json = gSender.encode_secret(secret, condition)
    if encoded_json==None:
        return render_template('404.html', error={
            "message": "Could not encode secret"
        })

    return render_template('encoded.html', secret={
        "sa": base64.b64encode(encoded_json["sa"]).decode('utf-8'),         # salt
#        "pass": encoded_json["pass"],                                       # passphrase
        "s": encoded_json["s"],     # encoded secret
        "c": encoded_json["c"],     # encoded condition
        "i": encoded_json["i"],     # iteration
        "e": encoded_json["e"],     # content of the qrcode
        "q": encoded_json["q"],     # qrcode
        "t": title,                 # display title
        "hasVC": hasVC              # needs a VC?
    })

##
## sharing
##

@app.route('/share')
def share():
    return render_template('share.html')

@app.route('/share_no_vc', methods=['POST'])
def post_share_no_vc():
    objUser=authenticate(request)
    secret_i = request.form.get('secret_i', None)
    secret_t = request.form.get('secret_t', None)
    
    if secret_i=="":
         return render_template('share.html')

    secret_pass=gSender.get_unique_token(gSender.TOKEN_PASSPHRASE_FOR_SECRET(), objUser["wallet"]["private"], secret_i)
    gReceiver.set_passphrase(secret_pass)
    return render_template('shared_with.html', shared={
        "hasVC": False,
        "title": secret_t,
        "passphrase":secret_pass,
        "did_sender": objUser["did"]
    })

@app.route('/share_with_vc', methods=['POST'])
def post_share_with_vc():
    objUser=authenticate(request)
    secret_i = request.form.get('secret_i', None)
    secret_c = request.form.get('secret_c', None)
    secret_t = request.form.get('secret_t', None)
    
    ## get Bob's DID
    objBob=gAuthenticator.authenticate("Bob")

    if secret_i=="":
         return render_template('share.html')

    secret_pass=gSender.get_unique_token(gSender.TOKEN_PASSPHRASE_FOR_SECRET(), objUser["wallet"]["private"], secret_i)
    gReceiver.set_passphrase(secret_pass)
    gSender.sign_share_secret({
        "did_receiver": objBob["did"],
        "did_sender": objUser["did"],
        "encoded_condition": secret_c,
        "iteration": int(secret_i),
        "title": secret_t
    })
    return render_template('shared_with.html', shared={
        "hasVC": True,
        "title": secret_t,
        "passphrase":secret_pass
    })

@app.route('/accept_vc', methods=['GET'])
def accept_vc():
    ## list all VCs
    aVC=gReceiver.get_all_pending_creds()
    return render_template('accept_vc.html', aVC=aVC)

@app.route('/accept_vc', methods=['POST'])
def post_accept_vc():
    objUser=authenticate(request)

    secret_i = int(request.form.get('secret_i', None))
    vc=gReceiver.accept_vc_offer(secret_i)
    return render_template('accepted_vc.html', vc=vc)

##
## decoding
##

@app.route('/decode_as_sender')
def decode_as_sender():
    return render_template('decode_as_sender.html')

@app.route('/decode_as_receiver')
def decode_as_receiver():
    return render_template('decode_as_receiver.html')

@app.route('/decoded_as_sender', methods=['POST'])
def post_decode_as_sender():
    objUser=authenticate(request)

    # found in the QR code
    secret_s = request.form.get('secret_s', None)
    secret_i = request.form.get('secret_i', None)
    secret_c = request.form.get('secret_c', None)       ## if not in QR code, then found in VC

    # kept by sender (derived from priv key, does not need storage)
    secret_pass=gSender.get_unique_token(gSender.TOKEN_PASSPHRASE_FOR_SECRET(), objUser["wallet"]["private"], secret_i)
    secret_passCond=gSender.get_unique_token(gSender.TOKEN_PASSPHRASE_FOR_CONDITION(), objUser["wallet"]["private"], secret_i)
    secret_sa=gSender.get_unique_token(gSender.TOKEN_SALT(), objUser["wallet"]["private"], secret_i)

    # user decode own secret?
    try:
        encoded_condition = gSender.get_encoded_condition(secret_c, int(secret_i))
        decoded_condition = gSender.decode_secret(encoded_condition, {
            "iterations": int(secret_i),
            "salt": secret_sa,
            "passphrase": secret_passCond,
            "encoded_condition": "condition"
        })        

        decoded_json = gSender.decode_secret(secret_s, {
            "iterations": int(secret_i),
            "salt": secret_sa,
            "passphrase": secret_pass,
            "encoded_condition": encoded_condition
        })        

        if decoded_json["decoded"] == None:
            raise Exception("Could not decode") 
        
        return render_template('decoded_as_sender.html', secret={
            "encoded":  secret_s,
            "decoded": decoded_json["decoded"],
            "condition": decoded_condition["decoded"]
        })
    except Exception as e:
        return render_template('decoded_as_sender.html', secret={
            "encoded":  secret_s,
            "decoded": "COULD NOT DECODE"
        })


@app.route('/decoded_as_receiver', methods=['POST'])
def post_decode_as_receiver():
    objUser=authenticate(request)

    # found in the QR code
    secret_s = request.form.get('secret_s', None)
    secret_i = request.form.get('secret_i', None)
    secret_c = request.form.get('secret_c', None)           ## if not in QR code, then found in VC

    # known by the receiver
    did_sender = request.form.get('did_sender', None)
    passphrase = request.form.get('passphrase', None) 
    if passphrase=='':
        passphrase=gReceiver.get_passphrase(),

    # receiver decode sender secret
    try:
        decoded_json = gReceiver.decode_secret(secret_s, {
            "notary": gSender.get_notary(),  
            "iterations": int(secret_i),
            "condition": secret_c,
            "passphrase": passphrase,
            "did_sender": did_sender
        })

        if decoded_json["decoded"] == None:
            raise Exception("Could not decode") 

        return render_template('decoded_as_receiver.html', secret={
            "encoded":  secret_s,
            "decoded": decoded_json["decoded"],
            "condition": "Fulfilled"
        })
    
    except Exception as e:
        return render_template('decoded_as_receiver.html', secret={
            "encoded":  secret_s,
            "decoded": "COULD NOT DECODE",
            "condition": "NOT YOUR BUSINESS"
        })

if __name__ == '__main__':
    app.run(debug=True)  # Starts the server at http://127.0.0.1:5000
