from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient


app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Use MongoDB Atlas connection string
client = MongoClient("mongodb+srv://Bhilled:8121KVM6oMsCX6gu@bhilled.22x1v.mongodb.net/?retryWrites=true&w=majority&appName=Bhilled")

# Choose your database
db = client['invoice_db']
users_collection = db['users']

# Sign-Up Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if users_collection.find_one({"email": data['email']}):
        return jsonify({"message": "Email already registered"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    users_collection.insert_one({"name": data['name'], "email": data['email'], "password": hashed_password})
    return jsonify({"message": "User registered successfully"}), 201

# Sign-In Route
@app.route('/signin', methods=['POST'])
def signin():
    data = request.json
    user = users_collection.find_one({"email": data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=user['email'])
        return jsonify({"token": access_token, "message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

# CRUD - Create Invoice
@app.route('/invoices', methods=['POST'])
@jwt_required()
def create_invoice():
    current_user = get_jwt_identity()
    data = request.json
    invoice = {
        "user": current_user,
        "client": data['client'],
        "amount": data['amount'],
        "date": data['date']
    }
    invoices_collection.insert_one(invoice)
    return jsonify({"message": "Invoice created successfully"}), 201

# Read Invoices
@app.route('/invoices', methods=['GET'])
@jwt_required()
def get_invoices():
    current_user = get_jwt_identity()
    invoices = list(invoices_collection.find({"user": current_user}, {"_id": 0}))
    return jsonify(invoices), 200

# Update Invoice
@app.route('/invoices/<string:invoice_id>', methods=['PUT'])
@jwt_required()
def update_invoice(invoice_id):
    data = request.json
    invoices_collection.update_one({"_id": invoice_id}, {"$set": data})
    return jsonify({"message": "Invoice updated successfully"}), 200

# Delete Invoice
@app.route('/invoices/<string:invoice_id>', methods=['DELETE'])
@jwt_required()
def delete_invoice(invoice_id):
    invoices_collection.delete_one({"_id": invoice_id})
    return jsonify({"message": "Invoice deleted successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True)
