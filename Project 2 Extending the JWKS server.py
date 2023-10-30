import json
import time
import sqlite3
from flask import Flask, request, jsonify
from OpenSSL import crypto
from jwt import JWT, jwk_from_pem

app = Flask(__name__)

# Create/open SQLite database at the start
db_file = 'private_keys.db'
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Create the 'keys' table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY,
        key TEXT,
        kid TEXT,
        exp INTEGER
    )
''')
conn.commit()

def create_rsa_keypair(bits=2048):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)
    return key

def insert_key(key, kid, expiration):
    cursor.execute('INSERT INTO keys (key, kid, exp) VALUES (?, ?, ?)', (key, kid, expiration))
    conn.commit()

def get_private_key(kid):
    cursor.execute('SELECT key FROM keys WHERE kid = ?', (kid,))
    result = cursor.fetchone()
    return result[0] if result else None

def create_jwt_token(payload, kid):
    priv_key = get_private_key(kid)
    jwt = JWT()
    key = jwk_from_pem(priv_key)
    token = jwt.encode(payload, key, algorithm='RS256')
    return token

@app.route('/auth', methods=['POST'])
def auth():
    if request.method != 'POST':
        return 'Method Not Allowed', 405

    # Check if the "expired" query parameter is set to "true"
    expired = request.args.get('expired') == 'true'

    # Create payload for JWT
    now = int(time.time())
    expiration = now - 1 if expired else now + 24 * 3600
    kid = 'expiredKID' if expired else 'goodKID'
    payload = {
        'iss': 'auth0',
        'type': 'JWT',
        'sample': 'test',
        'iat': now,
        'exp': expiration,
        'kid': kid
    }

    token = create_jwt_token(payload, kid)

    return token

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    if request.method != 'GET':
        return 'Method Not Allowed', 405

    cursor.execute('SELECT kid, key FROM keys')
    results = cursor.fetchall()
    
    keys = []
    for kid, key in results:
        pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, crypto.load_privatekey(crypto.FILETYPE_PEM, key))
        n_encoded = pub_key.split(b'\n')[1].decode('utf-8').strip()
        e_encoded = pub_key.split(b'\n')[2].decode('utf-8').strip()
        
        jwk = {
            'alg': 'RS256',
            'kty': 'RSA',
            'use': 'sig',
            'kid': kid,
            'n': n_encoded,
            'e': e_encoded
        }
        keys.append(jwk)

    return jsonify({'keys': keys})

if __name__ == '__main__':
    key_pair = create_rsa_keypair()
    insert_key(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair).decode('utf-8'), 'goodKID', int(time.time()) + 24 * 3600)

app.run(port=8080)
