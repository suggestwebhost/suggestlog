from flask import Flask, request, jsonify
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

app = Flask(__name__)

# Replace this with your actual MongoDB Atlas connection string from your cloud console
# Example format: mongodb+srv://<username>:<password>@cluster0.xxxxxx.mongodb.net/?retryWrites=true&w=majority
MONGO_URI = os.getenv("MONGO_URI")

try:
    # Initialize MongoDB Client
    client = MongoClient(MONGO_URI)
    # Define/select Database Name
    db = client['auth_service_db']
    # Define/select Collection Name (equivalent to a table)
    users_collection = db['users']
    
    # Simple check to see if connection works
    client.admin.command('ping')
    print("Successfully connected to MongoDB Cloud!")
except (ConnectionFailure, Exception) as e:
    print(f"Could not connect to MongoDB. Error: {e}")

@app.route('/register', methods=['POST'])
def register_user():
    """
    Creates a new user account and saves it straight to the cloud MongoDB instance.
    """
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing username or password"}), 400
        
    username = data['username']
    
    # Check MongoDB cloud to see if user already exists
    if users_collection.find_one({"login_info.username": username}):
        return jsonify({"error": "Username already taken"}), 400

    # 1. Generate unique user ID
    user_id = str(uuid.uuid4())
    
    # 2. Get current system date and time
    current_time = datetime.now()
    
    # 3. Structure user record document
    user_document = {
        "user_id": user_id,
        "login_info": {
            "username": username,
            "password_hash": generate_password_hash(data['password'])
        },
        "user_info": {
            "email": data.get('email', ''),
            "full_name": data.get('full_name', '')
        },
        "created_at": {
            "date": current_time.strftime("%Y-%m-%d"),
            "time": current_time.strftime("%H:%M:%S"),
            "iso_timestamp": current_time.isoformat()
        },
        "last_login": None
    }
    
    # Insert document into cloud database collection
    users_collection.insert_one(user_document)
    
    # Remove sensitive data and MongoDB internal ID ('_id') before responding
    del user_document['_id']
    del user_document['login_info']['password_hash']
    
    return jsonify({
        "message": "User created successfully in Cloud NoSQL",
        "data": user_document
    }), 201


@app.route('/login', methods=['POST'])
def login_user():
    """
    Validates login credentials against MongoDB and records login timestamps.
    """
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing login credentials"}), 400
        
    username = data['username']
    password = data['password']
    
    # Find user documentation inside database matching the username
    user = users_collection.find_one({"login_info.username": username})
    
    # Cross check hashed credentials
    if not user or not check_password_hash(user['login_info']['password_hash'], password):
        return jsonify({"error": "Invalid username or password"}), 401
        
    # Update last login data and time dynamically
    login_time = datetime.now()
    last_login_data = {
        "date": login_time.strftime("%Y-%m-%d"),
        "time": login_time.strftime("%H:%M:%S")
    }
    
    # Perform atomic update inside MongoDB
    users_collection.update_one(
        {"user_id": user['user_id']},
        {"$set": {"last_login": last_login_data}}
    )
    
    return jsonify({
        "message": "Login successful",
        "user_id": user['user_id'],
        "login_time": last_login_data
    }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
