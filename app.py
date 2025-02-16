from flask import Flask, jsonify, request, render_template, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
import datetime
from functools import wraps
import os
from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder='static', static_url_path='/')
CORS(app)

# Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/campusdash"
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Change this in production
app.config["SECRET_KEY"] = "anothersecretkey"  # For session management
app.config["UPLOAD_FOLDER"] = "static/uploads"
UPLOAD_FOLDER = 'static/img/Profile'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize extensions
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Create the upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Create indices for faster querying
def setup_database_indices():
    # Users collection indices
    mongo.db.users.create_index("email", unique=True)
    mongo.db.users.create_index("student_id", unique=True)
    
    # Job type collections indices
    mongo.db.creative_work.create_index("user_id")
    mongo.db.academic_help.create_index("user_id")
    mongo.db.food_delivery.create_index("user_id")
    
    # Create TTL index for completed jobs (auto-delete after 90 days)
    mongo.db.completed_jobs.create_index("completion_time", expireAfterSeconds=7776000)

# Sample document structures
user_schema = {
    "_id": ObjectId(),
    "name": "string",
    "student_id": "string",
    "email": "string",
    "password": "string (hashed)",
    "payment_info": {
        "card_number": "string (encrypted)",
        "card_name": "string",
        "expiry_date": "string",
        "cvv": "string (encrypted)"
    },
    "degree_type": "string",
    "degree": "string",
    "profile_image": "string (default.jpg)",
    "balance": float,
    "role": "string",
    "created_at": datetime
}

creative_work_schema = {
    "_id": ObjectId(),
    "user_id": ObjectId(),  # Reference to user who posted
    "job_title": "string",
    "job_description": "string",
    "fee": float,
    "meetup_type": "string (IN_PERSON/ONLINE)",
    "location": "string",
    "datetime": datetime,
    "status": "string (open/accepted/completed)",
    "completion_image": "string (path)",
    "respondent_id": ObjectId(),  # Reference to user who accepted
    "created_at": datetime,
    "updated_at": datetime
}

academic_help_schema = {
    "_id": ObjectId(),
    "user_id": ObjectId(),
    "subject": "string",
    "problem_description": "string",
    "fee": float,
    "meetup_type": "string (IN_PERSON/ONLINE)",
    "location": "string",
    "datetime": datetime,
    "status": "string (open/accepted/completed)",
    "completion_image": "string (path)",
    "respondent_id": ObjectId(),
    "created_at": datetime,
    "updated_at": datetime
}

food_delivery_schema = {
    "_id": ObjectId(),
    "user_id": ObjectId(),
    "restaurant_name": "string",
    "order_description": "string",
    "fee": float,
    "datetime": datetime,
    "status": "string (open/accepted/completed)",
    "respondent_id": ObjectId(),
    "created_at": datetime,
    "updated_at": datetime
}

# Helper functions for job operations
def create_job(job_type, job_data):
    """Create a new job of specified type"""
    job_data["created_at"] = datetime.datetime.utcnow()
    job_data["updated_at"] = datetime.datetime.utcnow()
    job_data["status"] = "open"
    
    collection_map = {
        "creative_work": mongo.db.creative_work,
        "academic_help": mongo.db.academic_help,
        "food_delivery": mongo.db.food_delivery
    }
    
    collection = collection_map.get(job_type)
    if not collection:
        raise ValueError("Invalid job type")
        
    return collection.insert_one(job_data)

def get_user_jobs(user_id, job_type=None):
    """Get all jobs posted by a user, optionally filtered by type"""
    jobs = []
    
    if job_type:
        collection = mongo.db[job_type]
        jobs = list(collection.find({"user_id": ObjectId(user_id)}))
    else:
        # Get jobs from all collections
        for collection_name in ["creative_work", "academic_help", "food_delivery"]:
            collection_jobs = list(mongo.db[collection_name].find({"user_id": ObjectId(user_id)}))
            for job in collection_jobs:
                job["job_type"] = collection_name
                jobs.append(job)
    
    return jobs

def update_user_profile(user_id, profile_data):
    """Update user profile including profile image"""
    update_fields = {
        "name": profile_data.get("name"),
        "degree_type": profile_data.get("degree_type"),
        "degree": profile_data.get("degree")
    }
    
    # Only update profile image if provided
    if "profile_image" in profile_data:
        update_fields["profile_image"] = profile_data["profile_image"]
    
    return mongo.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_fields}
    )

# Job completion and payment handling
def complete_job(job_id, data):
    job = mongo.db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise ValueError("Job not found")

    completed_job = {
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

# Context processors
@app.context_processor
def inject_user():
    """Make current user available to all templates"""
    if 'user_id' in session:
        user = mongo.db.users.find_one({"_id": ObjectId(session['user_id'])})
        return {'current_user': user}
    return {'current_user': None}

# Public routes
@app.route("/")
def home():
    tasks = mongo.db.jobs.find({"status": "open"}).limit(10)
    return render_template('index.html', tasks=tasks, logged_in= 'user_id' in session)

# Authentication routes
@app.route("/signup", methods=["GET", "POST"])
def signup_page():
        
    if request.method == "GET":
        return render_template('signup.html', logged_in= 'user_id' in session)
        
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
        
    if request.method == "GET":
        return render_template('login.html', logged_in= 'user_id' in session)
        
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
                             completed_jobs=completed_jobs, logged_in= 'user_id' in session)
                             
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

# Example: Creating a new creative work job
@app.route("/create_job", methods=["POST"])
@login_required
def create_new_job():
    current_user_id = session.get('user_id')
    job_data = {
        "user_id": ObjectId(current_user_id),
        "job_title": request.form.get("job_title"),
        "job_description": request.form.get("job_description"),
        "fee": float(request.form.get("fee")),
        "meetup_type": request.form.get("meetup_type"),
        "datetime": datetime.datetime.utcnow()
    }
    create_job("creative_work", job_data)
    flash("Job created successfully!", "success")
    return redirect(url_for('dashboard'))

# In your signup route
@app.route("/signup", methods=["POST"])
def signup():
    email = request.form.get("email")
    password = request.form.get("password")
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    if "profile_image" not in request.files:
        profile_image = "default.jpg"
    else:
        profile_image_file = request.files["profile_image"]
        profile_image = profile_image_file.filename
        profile_image_file.save(os.path.join(app.config["UPLOAD_FOLDER"], profile_image))
    
    user_data = {
        "name": request.form.get("name"),
        "student_id": request.form.get("student_id"),
        "email": email,
        "password": hashed_password,
        "degree_type": request.form.get("degree_type"),
        "degree": request.form.get("degree"),
        "profile_image": profile_image,
        "balance": 0.0,
        "role": "user",
        "created_at": datetime.datetime.utcnow()
    }
    
    mongo.db.users.insert_one(user_data)
    flash("Signup successful! Please log in.", "success")
    return redirect(url_for('login_page'))

# New route for updating profile image
@app.route("/api/users/me/profile-image", methods=["POST"])
@jwt_required()
def update_profile_image():
    if 'profile_image' not in request.files:
        return jsonify({"error": "No file provided"}), 400
        
    file = request.files['profile_image']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        user_id = get_jwt_identity()
        mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"profile_image": filename}}
        )
        
        return jsonify({"message": "Profile image updated successfully"}), 200
    
    return jsonify({"error": "Invalid file type"}), 400

if __name__ == "__main__":
    setup_database_indices()
    app.run(debug=True)