from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
import datetime

app = Flask(__name__)
CORS(app)

# Configure MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/campusdash"
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Change this in production
mongo = PyMongo(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Home Route
@app.route("/")
def home():
    return jsonify({"message": "Welcome to CampusDash API"}), 200

# User Signup
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
    user_id = mongo.db.users.insert_one({
        "name": data["name"],
        "student_id": data["student_id"],
        "email": data["email"],
        "password": hashed_pw,
        "payment_info": data.get("payment_info", {}),
        "degree_type": data.get("degree_type", "Undeclared"),
        "role": data.get("role", "user")
    }).inserted_id
    return jsonify({"message": "User registered successfully", "user_id": str(user_id)}), 201

# User Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = mongo.db.users.find_one({"email": data["email"]})
    
    if user and bcrypt.check_password_hash(user["password"], data["password"]):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify({"message": "Login successful", "token": access_token}), 200
    return jsonify({"error": "Invalid email or password"}), 401

# Post a Job
@app.route("/jobs", methods=["POST"])
@jwt_required()
def post_job():
    data = request.json
    user_id = get_jwt_identity()
    job_id = mongo.db.jobs.insert_one({
        "place": data["place"],
        "time": data["time"],
        "fee": data["fee"],
        "job_details": data["job_details"],
        "user_info": {"id": user_id, "name": data["user_info"]["name"], "student_id": data["user_info"]["student_id"]},
        "respondent_info": None,
        "job_type": data["job_type"]
    }).inserted_id
    return jsonify({"message": "Job posted", "job_id": str(job_id)}), 201

# Accept a Job
@app.route("/jobs/<string:job_id>/accept", methods=["PUT"])
@jwt_required()
def accept_job(job_id):
    respondent_id = get_jwt_identity()
    data = request.json
    result = mongo.db.jobs.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"respondent_info": {"id": respondent_id, "name": data["respondent"]["name"], "student_id": data["respondent"]["student_id"]}, "status": "accepted"}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({"message": "Job accepted", "job_id": job_id}), 200

# Complete an Order
@app.route("/orders/complete", methods=["POST"])
@jwt_required()
def complete_order():
    data = request.json
    job_id = data["job_id"]
    job = mongo.db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        return jsonify({"error": "Job not found"}), 404
    mongo.db.completed_orders.insert_one({
        "place": job["place"],
        "time": job["time"],
        "order_details": job["job_details"],
        "photo_verification": data["photo_verification"],
        "respondent_info": job["respondent_info"],
        "user_info": job["user_info"]
    })
    mongo.db.jobs.delete_one({"_id": ObjectId(job_id)})
    return jsonify({"message": "Order completed", "job_id": job_id}), 200

if __name__ == "__main__":
    app.run(debug=True)