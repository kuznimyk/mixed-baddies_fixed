from flask import Flask, jsonify, request, render_template, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configure MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/campusdash"
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Change this in production
app.config["SECRET_KEY"] = "anothersecretkey"  # For session management
mongo = PyMongo(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Home Route
@app.route("/")
def home():
    return render_template('index.html')

# Signup page route
@app.route("/signup", methods=["GET"])
def signup_page():
    return render_template('signup.html')

# Login page route
@app.route("/login", methods=["GET"])
def login_page():
    return render_template('login.html')

# Dashboard route (protected)
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session.get('user_id')
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    return render_template('dashboard.html', user=user)

# Process signup form
@app.route("/process_signup", methods=["POST"])
def process_signup():
    # Check if email already exists
    existing_user = mongo.db.users.find_one({"email": request.form.get("email")})
    if existing_user:
        flash("Email already registered")
        return redirect(url_for('signup_page'))
    
    # Check if student ID already exists
    existing_student = mongo.db.users.find_one({"student_id": request.form.get("student_id")})
    if existing_student:
        flash("Student ID already registered")
        return redirect(url_for('signup_page'))
    
    # Hash password
    hashed_pw = bcrypt.generate_password_hash(request.form.get("password")).decode('utf-8')
    
    # Insert new user
    user_id = mongo.db.users.insert_one({
        "name": request.form.get("name"),
        "student_id": request.form.get("student_id"),
        "email": request.form.get("email"),
        "password": hashed_pw,
        "payment_info": {},
        "degree_type": request.form.get("degree_type", "Undeclared"),
        "role": "user"
    }).inserted_id
    
    flash("Registration successful! Please log in.")
    return redirect(url_for('login_page'))

# Process login form
@app.route("/process_login", methods=["POST"])
def process_login():
    user = mongo.db.users.find_one({"email": request.form.get("email")})
    
    if user and bcrypt.check_password_hash(user["password"], request.form.get("password")):
        session['user_id'] = str(user["_id"])
        session['user_name'] = user["name"]
        return redirect(url_for('dashboard'))
    
    flash("Invalid email or password")
    return redirect(url_for('login_page'))

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))

# User Signup API (original)
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

# User Login API (original)
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = mongo.db.users.find_one({"email": data["email"]})
    
    if user and bcrypt.check_password_hash(user["password"], data["password"]):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify({"message": "Login successful", "token": access_token}), 200
    return jsonify({"error": "Invalid email or password"}), 401

# Keep the rest of your routes as they were...
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