#!/usr/bin/python3

from flask import Flask, url_for, Response, request
import inspect, sys, json
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
import json
from error_codes import error_codes

# SSL Configuration (Enable it if you want a security context here)
# import ssl
# context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
# context.load_cert_chain('certificate.crt', 'privatekey.key')

app = Flask(__name__)
CORS(app)

# Cambio auth a Token:
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth(scheme='Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)

users = {
    "first_user": {
        "password": generate_password_hash("123abc"),
        "token": "abcdef1234567890"
    },
}

roles = {
    "first_user": ["admin"]
}

# Tomo el log de stdout y stderr y lo envio a syslog
class LoggerWriter:
    def __init__(self, log_name):
        self.log_name = log_name
        self.buf = []

    def write(self, msg):
        #if msg.endswith('\n'):
        msg = msg.replace("\n", '')
        if len(msg) > 0:
            self.buf.append(f"[{self.log_name}] " + msg)
            # Necesito imprimirlo ya que hago un override de stdout y stderr
            print(''.join(self.buf), file=sys.__stdout__, flush=True)
            # gigasyslog.syslog(''.join(self.buf))
            self.buf = []
            
    def flush(self):
        self.buf = []
        pass

# Para acceder a stdout/stderr, usar sys.__stdout__/sys.__stderr__
sys.stdout = LoggerWriter("INFO")
sys.stderr = LoggerWriter("ERROR")

def generate_response(response, responseno = 200):
    '''Uso: generate_response("Datos", codigo_respuesta, 200)'''
    if type(response) is tuple:
        response, response_code = response
        print(f"Se devolverá una excepción {response_code}: {response}")
    else:
        response_code = responseno
    
    response_hint = {
        'error': False,
        'data': response, 
        'code': response_code,
        'diagnostic': error_codes[response_code]
    }

    if response_code >= 400:
        response_hint['error'] = True
    
    return json.dumps(response_hint, indent=4), responseno

def generate_error(diagnostic, errno = 400):
    if type(diagnostic) is tuple:
        diagnostic, error_code = diagnostic
        print(f"Se devolverá una excepción {error_code}: {diagnostic}")
    elif type(diagnostic) is int:
        error_code = diagnostic
        diagnostic = None
    else:
        error_code = errno
    
    error_hint = {
        'error': True,
        'data': None,
        'diagnostic': (error_codes[error_code] if diagnostic == None else diagnostic),
        'code': error_code
    }
    return json.dumps(error_hint, indent=4), errno

@token_auth.get_user_roles
@basic_auth.get_user_roles
def get_user_roles(user):
    return roles[user]

# This error handles Flask/Python exceptions, in case you need to catch a 404 or 500 error, use @app.errorhandler(404)
@app.errorhandler(Exception)
def all_exception_handler(error):
    print(str(error))
    return generate_error(str(error), 500)

@token_auth.error_handler
@basic_auth.error_handler
def default_error(status):
    return generate_error(status)

@basic_auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username)["password"], password):
        return username

@token_auth.verify_token
def verify_token(token):
    ''' I'm using a very inefficient script here. If you implement your own
    database, you can obtain your username via a valid token'''

    print(f"[TOKEN] Checking token {token}", file=sys.stderr)

    for user in users:
        if users[user]["token"] == token:
            return user
    return None

@app.route('/')
@multi_auth.login_required(role=['admin'])
def hello_world():
    """Prints identificator"""
    return "My basic API"

@app.route('/goodbye', methods=['POST', 'GET'])
@multi_auth.login_required(role=['admin'])
def goodbye_world():
    if request.method == 'POST':
        # I'm just returning something... magic happens here
        response = request.args
        return response
    else:
        return generate_error(405)

if __name__ == "__main__":
    # If you run Flask standalone, these are your settings.

    # With SSL
    # app.run(host='127.0.0.1', port=5000, ssl_context=context)

    app.run(host='127.0.0.1', port=5000)