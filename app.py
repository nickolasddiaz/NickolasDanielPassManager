from flask import Flask, jsonify, make_response, request # Python version 3.11.2 
from flask_talisman import Talisman #Secure Headers
from flask_wtf.csrf import CSRFProtect #CSRF protection
from flask_limiter import Limiter # denial-of-service Protection
from flask_limiter.util import get_remote_address # denial-of-service Protection
from dotenv import load_dotenv # environment variables
from psycopg2 import pool #connection pooling
from flask_cors import CORS
from flask_wtf.csrf import generate_csrf

import os
import hashlib
from cryptography.fernet import Fernet
from random import randint
import re
import jwt
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import atexit

app = Flask(__name__)
CORS(app)  # This will allow all origins by default

csrf = CSRFProtect()

@app.after_request
def set_csrf_cookie(response):
    response.set_cookie('csrf_token', generate_csrf(), domain='localhost', samesite='Strict')
    return response

load_dotenv()
local_salt = os.getenv('local_salt') # node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
databasesx = os.getenv('databasesx')
hostsx = os.getenv('hostsx')
usersx = os.getenv('usersx')
passwordsx = os.getenv('passwordsx')
portsx = os.getenv('portsx')
csrfsecretekey = os.getenv('csrfsecretekey')

app.secret_key = csrfsecretekey
CORS(app, supports_credentials=True, origins=["http://localhost:8000"])

# Initialize the connection pool
db_pool = pool.SimpleConnectionPool( 
    minconn=1,
    maxconn=10,
    database=databasesx,
    host=hostsx,
    user=usersx,
    password=passwordsx,
    port=portsx
)

def close_db_pool():
    if db_pool:
        db_pool.closeall()
        print("Database pool closed.")

atexit.register(close_db_pool)

app.config['SECRET_KEY'] = secrets.token_hex(32) #CSRF protection
csrf = CSRFProtect(app)

csp = { #Secure Headers
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline'",
}
Talisman(app, content_security_policy=csp, force_https=True)

# denial-of-service Protection
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Rate limit exceeded", message=str(e.description)), 429

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify(error="An unexpected error occurred"), 500

FERNET_KEY = Fernet.generate_key()  # Generate a key for Fernet encryption
cipher_suite = Fernet(FERNET_KEY)



def hash_password(password, salt):
    # Concatenate the password and salt and hash using SHA-256
    return hashlib.sha256((password + salt).encode()).hexdigest()

def encrypt(data, password):
    # Create a 32-byte key from the hashed password
    key = hashlib.sha256(password.encode()).digest()

    # Initialize the cipher in CBC mode with a 16-byte IV
    cipher = AES.new(key, AES.MODE_CBC)
    
    # Pad the data to ensure it's a multiple of 16 bytes
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))

    # Encode the IV and ciphertext in base64 to return as a string
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')

    return iv + ct

def decrypt(data, password):
    # Create a 32-byte key from the hashed password
    key = hashlib.sha256(password.encode()).digest()

    # Extract the IV and ciphertext from the encoded data
    iv = base64.b64decode(data[:24])  # Adjust if your IV is longer or shorter
    ct = base64.b64decode(data[24:])

    # Initialize the cipher in CBC mode with the extracted IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the data
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except ValueError as e:
        # Handle the padding error
        print(f"Decryption failed: {str(e)}")
        return None

def generate_salt():
    return secrets.token_hex(16)

def create_jwt_token(user_id,key): 
    expiration = datetime.now(tz=timezone.utc) + timedelta(hours=25)
    payload = {
        'user_email': user_id,
        'key': key,
        'exp': expiration
    }
    token = jwt.encode({ 'user_id': user_id, 'exp': expiration }, JWT_SECRET_KEY, algorithm='HS256')
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def verify_jwt_token(token):
    try:
        payload = jwt.decode(str(token), JWT_SECRET_KEY, algorithms=['HS256'])
        return [payload['user_email'], payload['key']]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    
def send_email(to_email, subject, body):
    print(f"Sending email to: {to_email}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")

if __name__ == "__main__":
    app.run(debug=True)
    
@app.route("/signup", methods=['POST'])
@csrf.exempt
@limiter.limit("5 per minute")
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    hashed_email = hash_password(email, local_salt)

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE hashed_email = %s", (hashed_email,))
            if cursor.fetchone():
                return jsonify({"error": "Email already registered"}), 400

            salt = generate_salt()
            password_hash = hash_password(hashed_email + password, salt)
            key = generate_salt()
            encrypted_key = encrypt(local_salt + '.' + key, password_hash)

            verification_code = randint(100000, 999999)

            cursor.execute(
                "INSERT INTO users (hashed_email, encrypted_key, salt, verification_code, is_verified) VALUES (%s, %s, %s, %s, FALSE)",
                (hashed_email, encrypted_key, salt, verification_code)
            )
            conn.commit()

        send_email(email, "Verification Code", f"Your verification code is: {verification_code}")
        return jsonify({"message": "User registered. Please check your email for verification code."}), 201
    finally:
        db_pool.putconn(conn)

@app.route("/signupwithcode", methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def signupwithcode():
    data = request.json
    email = data.get('email')
    code = data.get('code')

    if not email or not code: #Check if email/code exists
        return jsonify({"error": "Email and verification code are required"}), 400
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            hashed_email = hash_password(email, local_salt)
            cursor.execute("SELECT * FROM users WHERE hashed_email = %s AND verification_code = %s", (hashed_email, code)) # Verify code
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "Invalid email or verification code"}), 400

            cursor.execute("UPDATE users SET is_verified = TRUE, verification_code = NULL WHERE hashed_email = %s", (hashed_email,)) # Mark user as verified
            conn.commit()

            return jsonify({"message": "Email verified. You can now log in."}), 200
    finally:
        db_pool.putconn(conn)

@app.route("/login", methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            hashed_email = hash_password(email, local_salt)
            cursor.execute("SELECT encrypted_key, salt, is_verified FROM users WHERE hashed_email = %s", (hashed_email,))
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "Invalid email or password"}), 401

            encrypted_key, salt, is_verified = user

            if not is_verified:
                 jsonify({"error": "Email not verified"}), 401

            password_hash = hash_password(hashed_email + password, salt)
            tkey = decrypt(encrypted_key, password_hash)
            verifypass, key = tkey.split(".", 1)

            if verifypass != local_salt:
                return jsonify({"error": "Invalid email or password"}), 401

            token = create_jwt_token(hashed_email,tkey)
            return jsonify({"token": token}), 200
    finally:
        db_pool.putconn(conn)

@app.route("/add", methods=['POST']) # Can be used to add or update a Column
@limiter.limit("30 per minute")
def add():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    user_email, tkey = verify_jwt_token(token)
    if not user_email:
        return jsonify({"error": "Invalid or expired token"}), 401
    verifypass, key = tkey.split(".", 1)

    if verifypass != local_salt:
        return jsonify({"error": "Invalid or expired token"}), 401

    data = request.json
    website = encrypt(data.get('website'),tkey)
    username = encrypt(data.get('username'),tkey)
    password = encrypt(data.get('password'),tkey)

    if not website or not username:
        return jsonify({"error": "Website, username are required"}), 400
    
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:

            cursor.execute(""" 
                INSERT INTO stored_credentials (user_email, website, username, password)
                VALUES (%s, %s, %s, %s)
            """, (user_email, website, username, password))# Update/insert the credential
            conn.commit()

            return jsonify({"message": "Credential updated successfully"}), 200
    finally:
        db_pool.putconn(conn)

@app.route("/delete", methods=['POST'])
@limiter.limit("10 per minute")
def delete():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    user_email, tkey = verify_jwt_token(token)
    if not user_email:
        return jsonify({"error": "Invalid or expired token"}), 401
    verifypass, key = tkey.split(".", 1)

    if verifypass != local_salt:
        return jsonify({"error": "Invalid or expired token"}), 401

    data = request.json
    website = data.get('website')
    username = data.get('username')

    if not website:
        return jsonify({"error": "Website is required"}), 400
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:

            cursor.execute("DELETE FROM stored_credentials WHERE user_email = %s AND website = %s AND username = %s", (user_email, encrypt(website, tkey), encrypt(username,tkey)))
            conn.commit()

            if cursor.rowcount == 0:
                return jsonify({"message": "No credential found for the given website"}), 404

            return jsonify({"message": "Credential deleted successfully"}), 200
    finally:
        db_pool.putconn(conn)

@app.route("/deleteaccount", methods=['POST'])
@limiter.limit("3 per hour")
def deleteaccount():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    user_email, tkey = verify_jwt_token(token)
    if not user_email:
        return jsonify({"error": "Invalid or expired token"}), 401
    verifypass, key = tkey.split(".", 1)

    if verifypass != local_salt:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_id = verify_jwt_token(token)
    if not user_id:
        return jsonify({"error": "Invalid or expired token"}), 401
    
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:

            cursor.execute("DELETE FROM stored_credentials WHERE user_email = %s", (user_email,)) # Delete user's credentials

            cursor.execute("DELETE FROM users WHERE hashed_email = %s", (user_email,)) # Delete user
            conn.commit()

            return jsonify({"message": "Account deleted successfully"}), 200
    finally:
        db_pool.putconn(conn)

@app.route("/setnewpassword", methods=['POST'])
@limiter.limit("5 per hour")
def setnewpassword():
    data = request.json
    password = data.get('password')
    new_password = data.get('new_password')
    
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    user_email, tkey = verify_jwt_token(token)
    
    if not user_email:
        return jsonify({"error": "Invalid or expired token"}), 401
    verifypass, key = tkey.split(".", 1)

    if verifypass != local_salt:
        return jsonify({"error": "Invalid or expired token"}), 401

    if not new_password:
        return jsonify({"error": "Email and new password are required"}), 400
    
    if len(new_password) < 8: # Password strength check
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:

            cursor.execute("SELECT encrypted_key, salt FROM users WHERE hashed_email = %s", (user_email,))
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "Invalid or expired token"}), 401
            
            encrypted_key, salt = user
            
            password_hash = hash_password(user_email + password, salt)
            tkey = decrypt(encrypted_key, password_hash)
            verifypass, key = tkey.split(".", 1)

            if verifypass != local_salt:
                return jsonify({"error": "Invalid email or password"}), 401


            new_salt = generate_salt()
            new_password_hash = hash_password(user_email + new_password, new_salt)
            new_encrypted_key = encrypt(local_salt + '.' + key, new_password_hash)

            cursor.execute("UPDATE users SET encrypted_key = %s, salt = %s WHERE hashed_email = %s", # Update password
                        (new_encrypted_key, new_salt, user_email))
            conn.commit()

            return jsonify({"message": "Password reset successfully"}), 200
    finally:
        db_pool.putconn(conn)

@app.route("/setnewemail", methods=['POST'])
@limiter.limit("3 per hour")
def setnewemail():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    user_email, tkey = verify_jwt_token(token)
    if not user_email:
        return jsonify({"error": "Invalid or expired token"}), 401
    verifypass, key = tkey.split(".", 1)

    if verifypass != local_salt:
        return jsonify({"error": "Invalid or expired token"}), 401
    
    data = request.json
    new_email = data.get('new_email')
    password = data.get('password')

    if not new_email or not password:
        return jsonify({"error": "New email and password are required"}), 400
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email): # Email format validation
        return jsonify({"error": "Invalid email format"}), 400
    
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:

            cursor.execute("SELECT encrypted_key, salt, verification_code FROM users WHERE hashed_email = %s", (user_email,)) # Verify password
            user = cursor.fetchone()
            encrypted_key, salt, verification_code  = user

            password_hash = hash_password(user_email + password, salt)
            tkey = decrypt(encrypted_key, password_hash)
            verifypass, key = tkey.split(".", 1)

            if verifypass != local_salt:
                return jsonify({"error": "Invalid email or password"}), 401

            
            new_user_email = hash_password(new_email,local_salt)
            cursor.execute("SELECT hashed_email FROM users WHERE hashed_email = %s", (new_user_email,)) # Check if new email is already in use
            verify = cursor.fetchone()
            if verify is not None:
                return jsonify({"error": "Email already in use"}), 
            
            if verification_code is None:
                verification_code = randint(100000, 999999) # Generate verification code
                code = new_email + " " + str(verification_code)
                cursor.execute("UPDATE users SET verification_code = %s WHERE hashed_email = %s", (code, user_email)) # Update email
                conn.commit()
                send_email(new_email, "Verification Code", f"Your verification code is: {verification_code}")
                return jsonify({"message": "Please check your new email for verification code."}), 201
            
            verification = data.get('code')
            if verification_code == new_email + ' ' + verification:
                new_salt = generate_salt()
                new_password_hash = hash_password(new_user_email + password, new_salt)
                new_encrypted_key = encrypt(local_salt + '.' + key, new_password_hash)
                cursor.execute("UPDATE users SET hashed_email = %s, encrypted_key = %s, salt = %s, verification_code = NULL WHERE hashed_email = %s", (new_user_email, new_encrypted_key, new_salt, user_email)) # Update email
                conn.commit()
                return jsonify({"message": "Email successfully verified and changed. You can now log in."}), 200
            else:
                return jsonify({"error": "Code is invalid"}), 400
    finally:
        db_pool.putconn(conn)

@app.route("/retrieve", methods=['POST'])
@limiter.limit("60 per minute")
def retrieve():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    user_email, tkey = verify_jwt_token(token)
    if not user_email:
        return jsonify({"error": "Invalid or expired token"}), 401
    verifypass, key = tkey.split(".", 1)

    if verifypass != local_salt:
        return jsonify({"error": "Invalid or expired token"}), 401
    
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
    
            cursor.execute("SELECT website, username, password FROM stored_credentials WHERE user_email = %s", (user_email,))
            credentials = cursor.fetchall()


            result = []
            for cred in credentials:
                website, username, password = cred
                result.append({
                    "website": decrypt(website, tkey),
                    "username": decrypt(username, tkey),
                    "password": decrypt(password, tkey)
                })

            return jsonify({"credentials": result}), 200
    finally:
        db_pool.putconn(conn)



"""
-- Users table
CREATE TABLE users (
    hashed_email VARCHAR(255) UNIQUE NOT NULL PRIMARY KEY,
    encrypted_key VARCHAR(255) NOT NULL,  -- encrypted key gets unecrypted from the email + password + salt then the key can encrypt/decrypt the stored_credentials
    salt VARCHAR(255) NOT NULL, 
    verification_code varchar(50),
    is_verified BOOLEAN DEFAULT FALSE
);

-- Stored credentials table
CREATE TABLE stored_credentials (
    user_email VARCHAR(255) REFERENCES users(hashed_email),
    website VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255)
);

-- Add indexes for performance
CREATE INDEX idx_users_hashed_email ON users(hashed_email);
CREATE INDEX idx_stored_credentials_user_email ON stored_credentials(user_email);
alter table stored_credentials
drop constraint stored_credentials_user_email_fkey,
add constraint stored_credentials_user_email_fkey foreign key (user_email) references users (hashed_email) on update cascade;
add constraint stored_credentials_user_email_fkey foreign key (user_email) references users (hashed_email) on drop cascade;
add constraint stored_credentials_user_email_fkey foreign key (user_email) references users (hashed_email) on delete cascade;
"""