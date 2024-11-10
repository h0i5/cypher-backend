from dotenv import load_dotenv
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bcrypt import gensalt, hashpw
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask_cors import CORS, cross_origin

import jwt
load_dotenv()

app = Flask(__name__)
cors = CORS(app) # allow CORS for all domains on all routes.
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
app.config['CORS_HEADERS'] = 'Content-Type'

# Set up MongoDB connection
uri = os.getenv("MONGO_URI") 
client = MongoClient(uri, server_api=ServerApi('1'))
db = client['Cipher']
users_collection = db['users']

# JWT Secret key
SECRET_KEY = os.getenv("JWT_SECRET_KEY")


@app.route('/register', methods=['POST'])
@cross_origin()
def register():
    data = request.json
    username = data.get("username")
    master_password = data.get("master_password")
    encryption_password = data.get("encryption_password")
    email = data.get("email")
    # vault is an object with aes256 is the part 
    vault = data.get("vault")
    aesString = vault.get("aesString")
    derivedKey = vault.get("derivedKey")
    salt = vault.get("salt")
    sha256key = vault.get("sha256key")

    # Check for required fields
    if not username or not master_password or not encryption_password or not email:
        return jsonify({"error": "Username, password, and email are required"}), 400

    if username.strip()== "" or master_password == "" or encryption_password == "" or email == "":
        return jsonify({"error": "Username, password, and email cannot be empty"}), 400

    # Check if user already exists
    if users_collection.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 409 

    # Hash the password

    # Insert user data into MongoDB
    users_collection.insert_one({
        "username": username,
        "master_password": master_password,
        "encryption_password": encryption_password,
        "email": email,
        "aesString": aesString, 
        "derivedKey": derivedKey,
        "salt":salt,
        "derivedKey": derivedKey,
        "sha256key": sha256key,
    })

    return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    master_password = data.get("master_password")

    # Check for required fields
    if not username or not master_password:
        return jsonify({"error": "Username and password are required"}), 400

    # Check if user exists
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    # Check if password is correct
    if not master_password == user["master_password"]:
        return jsonify({"error": "Invalid username or password"}), 401

   # generate the JWT 


    encoded_jwt = jwt.encode({"username": user["username"]},SECRET_KEY, algorithm="HS256")


    return jsonify({"message": "Login successful", "token": encoded_jwt}), 200

@app.route('/getVault', methods=['POST'])
def getVault():
    data = request.json
    # Take username from JWT

    token = data.get("token")

    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

   
    except jwt.ExpiredSignatureError: 
        return jsonify({"error": "Token has expired"}), 401

    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    username = decoded_token["username"]

    # Check for required fields
    if not username:
        return jsonify({"error": "Username is required"}), 400

    # Check if user exists
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "Invalid username"}), 401

    return jsonify({
        "message": "Vault fetched successfully",
        "username": user["username"], 
        "aesString": user["aesString"],  
        "salt" : user["salt"]
    }), 200


@app.route('/updateVault', methods=['POST'])
def updateVault():
    data = request.json
    # Take username from JWT

    token = data.get("token")
    aesString = data.get("aesString")
    salt = data.get("salt")

    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

   
    except jwt.ExpiredSignatureError: 
        return jsonify({"error": "Token has expired"}), 401

    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    username = decoded_token["username"]

    # Check for required fields
    if not username:
        return jsonify({"error": "Username is required"}), 400

    # Check if user exists
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "Invalid username"}), 401

    # Update the user's vault
    users_collection.update_one({"username": username}, {"$set": {
        "aesString": aesString,
        "salt": salt
    }})

    return jsonify({"message": "Vault updated successfully"}), 200

@app.route('/verifyEncryptionPassword', methods=['POST'])
def verifyEncryptionPassword():
    data = request.json
    token = data.get("token")
    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

   
    except jwt.ExpiredSignatureError: 
        return jsonify({"error": "Token has expired"}), 401

    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


    username = decoded_token["username"]

    encryption_password = data.get("encryption_password")

    # Check for required fields
    if not username or not encryption_password:
        return jsonify({"error": "Username and encryption password are required"}), 400

    # Check if user exists
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "Invalid username"}), 401

    # Check if password is correct
    if not encryption_password == user["encryption_password"]:
        return jsonify({"error": "Invalid encryption password"}), 401

    return jsonify({"message": "Encryption password verified successfully"}), 200


if __name__ == '__main__':
    app.run(port=4000)
