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

# Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/campusdash"
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Change this in production
app.config["SECRET_KEY"] = "anothersecretkey"  # For session management

# Initialize extensions
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Context processors
@app.context_processor
def inject_user():
    """Make current user available to all templates"""
    if 'user_id' in session:
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
        return {'current_user': user}
    return {'current_user': None}

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

# Public routes
@app.route("/")
def home():
    tasks = mongo.db.jobs.find({"status": "open"}).limit(10)
    return render_template('index.html', tasks=tasks)

# Authentication routes
@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == "GET":
        return render_template('signup.html')
        
    # POST request handling
    existing_user = mongo.db.users.find_one({"email": request.form.get("email")})
    if existing_user:
        flash("Email already registered", "danger")
        return redirect(url_for('signup_page'))

    existing_student = mongo.db.users.find_one({"student_id": request.form.get("student_id")})
    if existing_student:
        flash("Student ID already registered", "danger")
        return redirect(url_for('signup_page'))

    try:
        # Hash password
        hashed_pw = bcrypt.generate_password_hash(request.form.get("password")).decode('utf-8')

        # Insert new user
        user_data = {
            "name": request.form.get("name"),
            "student_id": request.form.get("student_id"),
            "email": request.form.get("email"),
            "password": hashed_pw,
            "payment_info": {},
            "degree_type": request.form.get("degree_type", "Undeclared"),
            "degree": request.form.get("degree", ""),
            "balance": 0.0,
            "role": "user",
            "created_at": datetime.datetime.utcnow()
        }
        
        user_id = mongo.db.users.insert_one(user_data).inserted_id
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login_page'))
        
    except Exception as e:
        flash("An error occurred during registration. Please try again.", "danger")
        return redirect(url_for('signup_page'))

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == "GET":
        return render_template('login.html')
        
    # POST request handling
    try:
        user = mongo.db.users.find_one({"email": request.form.get("email")})
        
        if user and bcrypt.check_password_hash(user["password"], request.form.get("password")):
            session['user_id'] = str(user["_id"])
            session['user_name'] = user["name"]
            session['access_token'] = create_access_token(identity=str(user["_id"]))
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid email or password", "danger")
        return redirect(url_for('login_page'))
        
    except Exception as e:
        flash("An error occurred during login. Please try again.", "danger")
        return redirect(url_for('login_page'))

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been successfully logged out.", "success")
    return redirect(url_for('home'))

# Protected routes
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session.get('user_id')
    try:
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        posted_jobs = mongo.db.jobs.find({"user_info.id": user_id})
        accepted_jobs = mongo.db.jobs.find({"respondent_info.id": user_id})
        completed_jobs = mongo.db.completed_jobs.find({
            "$or": [
                {"user_info.id": user_id},
                {"respondent_info.id": user_id}
            ]
        }).limit(10)
        
        return render_template('dashboard.html', 
                             user=user, 
                             posted_jobs=posted_jobs,
                             accepted_jobs=accepted_jobs,
                             completed_jobs=completed_jobs)
                             
    except Exception as e:
        flash("An error occurred while loading your dashboard.", "danger")
        return redirect(url_for('home'))

# API routes - Jobs
@app.route("/api/jobs", methods=["GET", "POST"])
@jwt_required()
def jobs():
    if request.method == "GET":
        try:
            jobs = list(mongo.db.jobs.find({"status": "open"}))
            for job in jobs:
                job["_id"] = str(job["_id"])
            return jsonify(jobs), 200
        except Exception as e:
            return jsonify({"error": "Failed to fetch jobs"}), 500
            
    # POST request
    try:
        data = request.json
        user_id = get_jwt_identity()
        
        job_data = {
            "place": data["place"],
            "meet_place": data.get("meet_place", "IN PERSON"),
            "post_time": datetime.datetime.utcnow(),
            "meet_time": data.get("meet_time"),
            "job_price": float(data.get("job_price", 0)),
            "job_details": data["job_details"],
            "user_info": {
                "id": user_id,
                "name": data["user_info"]["name"],
                "student_id": data["user_info"]["student_id"]
            },
            "respondent_info": None,
            "job_type": data["job_type"],
            "status": "open"
        }
        
        job_id = mongo.db.jobs.insert_one(job_data).inserted_id
        return jsonify({"message": "Job posted successfully", "job_id": str(job_id)}), 201
        
    except Exception as e:
        return jsonify({"error": "Failed to create job"}), 500

@app.route("/api/jobs/<string:job_id>", methods=["GET", "PUT"])
@jwt_required()
def job_operations(job_id):
    try:
        if request.method == "GET":
            job = mongo.db.jobs.find_one({"_id": ObjectId(job_id)})
            if not job:
                return jsonify({"error": "Job not found"}), 404
            job["_id"] = str(job["_id"])
            return jsonify(job), 200
            
        # PUT request - Accept job
        if request.method == "PUT":
            data = request.json
            respondent_id = get_jwt_identity()
            
            result = mongo.db.jobs.update_one(
                {"_id": ObjectId(job_id), "status": "open"},
                {
                    "$set": {
                        "respondent_info": {
                            "id": respondent_id,
                            "name": data["respondent"]["name"],
                            "student_id": data["respondent"]["student_id"]
                        },
                        "status": "accepted"
                    }
                }
            )
            
            if result.matched_count == 0:
                return jsonify({"error": "Job not found or already accepted"}), 404
                
            return jsonify({"message": "Job accepted successfully"}), 200
            
    except Exception as e:
        return jsonify({"error": "An error occurred"}), 500

# API routes - Users
@app.route("/api/users/me/balance", methods=["GET"])
@jwt_required()
def get_user_balance():
    try:
        user_id = get_jwt_identity()
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"balance": user.get("balance", 0)}), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch balance"}), 500

@app.route("/api/users/me/payment-info", methods=["PUT"])
@jwt_required()
def update_payment_info():
    try:
        user_id = get_jwt_identity()
        data = request.json
        
        result = mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"payment_info": data}}
        )
        
        if result.matched_count == 0:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({"message": "Payment information updated successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": "Failed to update payment information"}), 500

@app.route("/api/complete-job", methods=["POST"])
@jwt_required()
def complete_job():
    try:
        data = request.json
        job_id = data["job_id"]
        
        # Fetch the job
        job = mongo.db.jobs.find_one({"_id": ObjectId(job_id)})
        if not job:
            return jsonify({"error": "Job not found"}), 404
            
        # Create completed job record
        completed_job = {
            "original_job_id": job_id,
            "place": job["place"],
            "meet_place": job.get("meet_place", "IN PERSON"),
            "post_time": job.get("post_time"),
            "meet_time": job.get("meet_time"),
            "job_details": job["job_details"],
            "job_price": float(job.get("job_price", 0)),
            "job_type": job["job_type"],
            "user_info": job["user_info"],
            "respondent_info": job["respondent_info"],
            "completion_time": datetime.datetime.utcnow(),
            "photo_verification": data.get("photo_verification"),
            "user_confirmation": data.get("user_confirmation", False),
            "respondent_confirmation": data.get("respondent_confirmation", False)
        }
        
        # Insert completed job and remove original
        mongo.db.completed_jobs.insert_one(completed_job)
        mongo.db.jobs.delete_one({"_id": ObjectId(job_id)})
        
        # Handle payment
        job_price = float(job.get("job_price", 0))
        if job_price > 0:
            # Deduct from requester
            mongo.db.users.update_one(
                {"_id": ObjectId(job["user_info"]["id"])},
                {"$inc": {"balance": -job_price}}
            )
            
            # Add to respondent
            if job["respondent_info"] and "id" in job["respondent_info"]:
                mongo.db.users.update_one(
                    {"_id": ObjectId(job["respondent_info"]["id"])},
                    {"$inc": {"balance": job_price}}
                )
                
        return jsonify({"message": "Job completed successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": "Failed to complete job"}), 500

if __name__ == "__main__":
    app.run(debug=True)