from flask import Flask, jsonify, request, render_template, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
import datetime
from functools import wraps
import os
from rapidfuzz import process, fuzz

from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder='static', static_url_path='/')
CORS(app)

# Configuration
app.config["MONGO_URI"] = "mongodb+srv://root:Qwerty%2B1@cluster0.q3gur.mongodb.net/CampusGig?retryWrites=true&w=majority&appName=Cluster0"
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
    "status": "string (Not Accepted Yet/Accepted/completed)",
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
    "status": "string (Not Accepted Yet/Accepted/completed)",
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
    "status": "string (Not Accepted Yet/Accepted/completed)",
    "respondent_id": ObjectId(),
    "created_at": datetime,
    "updated_at": datetime
}

# Helper functions for job operations



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
        "completion_time": datetime.now(),
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

        try:
            jobs = get_all_jobs()
            formatted_jobs = [format_job_for_display(job) for job in jobs]
            print(formatted_jobs)
            return render_template('index.html', jobs=formatted_jobs, logged_in='user_id' in session)
        except Exception as e:
            print("Error loading jobs:", str(e))
            flash("Error loading jobs.", "danger")
            return render_template('index.html', jobs=[], logged_in='user_id' in session)


@app.route("/search", methods=['GET'])
def search_result():
    query = request.args.get("query", "").strip()
    category = request.args.get("category", "").strip()

    print(category)
    print(query)


    if category == "Food Delivery":
        results = list(mongo.db.food_delivery.find())
    elif category == "Creative Work":
        results = list(mongo.db.creative_work.find())
    elif category == "Academic Help":
        results = list(mongo.db.academic_help.find())
    else:
        results = []

    # print(results)
    if query:
        job_titles = [job["job_title"] for job in results]

        best_matches = process.extract(query, job_titles, limit=10, scorer=fuzz.WRatio)

        matched_jobs = [job for job in results if job["job_title"] in [match[0] for match in best_matches]]
    else:
        matched_jobs = results
    print(matched_jobs)
    return render_template('index.html', jobs=matched_jobs, logged_in='user_id' in session)

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
            "created_at": datetime.now()
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
        posted_jobs = list(mongo.db.creative_work.find({"user_id": ObjectId(user_id)}))
        posted_jobs += list(mongo.db.food_delivery.find({"user_id": ObjectId(user_id)}))
        posted_jobs += list(mongo.db.academic_help.find({"user_id": ObjectId(user_id)}))
        accepted_jobs = list(mongo.db.creative_work.find({"respondent_id": ObjectId(user_id)}))
        accepted_jobs += list(mongo.db.food_delivery.find({"respondent_id": ObjectId(user_id)}))
        accepted_jobs += list(mongo.db.academic_help.find({"respondent_id": ObjectId(user_id)}))
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
        print("Error loading jobs:", str(e))
        flash("An error occurred while loading your dashboard.", "danger")
        return redirect(url_for('home'))

# API routes - Jobs
@app.route("/api/jobs", methods=["GET", "POST"])
@jwt_required()
def jobs():
    if request.method == "GET":
        try:
            jobs = list(mongo.db.jobs.find({"status": "Not Accepted Yet"}))
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
            "post_time": datetime.now(),
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
            "status": "Not Accepted Yet"
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
                {"_id": ObjectId(job_id), "status": "Not Accepted Yet"},
                {
                    "$set": {
                        "respondent_info": {
                            "id": respondent_id,
                            "name": data["respondent"]["name"],
                            "student_id": data["respondent"]["student_id"]
                        },
                        "status": "Accepted"
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
            "completion_time": datetime.now(),
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
        "created_at": datetime.now()
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

# Update the create_job function in app.py
# Add this to your app.py

@app.route("/create_new_job", methods=["POST"])
@login_required
def create_new_job():
    try:
        # Debug: Print all form data

        job_type = request.form.get("job_type")
        if not job_type:
            flash("Job type is required", "danger")
            return redirect(url_for('dashboard'))

        # Debug: Print fee value specifically
        fee_str = request.form.get("fee")

        print(fee_str)
        # Parse and validate fee
        try:
            if fee_str and fee_str.strip():
                fee = float(fee_str)

                if fee < 0:
                    raise ValueError("Fee cannot be negative")
            else:
                fee = 0.0
                print("No fee provided, defaulting to 0.0")
        except ValueError as e:
            print(f"Fee conversion error: {str(e)}")
            flash(f"Invalid fee value: {str(e)}", "danger")
            return redirect(url_for('dashboard'))

        # Create job data with explicit fee
        job_data = {
            "user_id": session.get('user_id'),
            "fee": fee,  # Use the validated fee
            "datetime": request.form.get("datetime"),
            "meetup_type": request.form.get("meetup_type", "VIRTUAL")
        }




        # Add job type specific fields
        if job_type == "creative_work":
            if not request.form.get("job_title"):
                raise ValueError("Job title is required")
            if not request.form.get("job_description"):
                raise ValueError("Job description is required")
                
            job_data.update({
                "job_title": request.form.get("job_title"),
                "job_description": request.form.get("job_description"),
                "location": request.form.get("location") if request.form.get("meetup_type") == "IN_PERSON" else None
            })
        elif job_type == "academic_help":
            if not request.form.get("subject"):
                raise ValueError("Subject is required")
            if not request.form.get("problem_description"):
                raise ValueError("Problem description is required")
                
            job_data.update({
                "job_title": "Academic Help: " + request.form.get("subject"),
                "subject": request.form.get("subject"),
                "problem_description": request.form.get("problem_description"),
                "location": request.form.get("location") if request.form.get("meetup_type") == "IN_PERSON" else None
            })
        elif job_type == "food_delivery":
            if not request.form.get("restaurant_name"):
                raise ValueError("Restaurant name is required")
            if not request.form.get("order_description"):
                raise ValueError("Order description is required")
                
            job_data.update({
                "job_title": "Food Delivery From " + request.form.get("restaurant_name"),
                "restaurant_name": request.form.get("restaurant_name"),
                "order_description": request.form.get("order_description")
            })


        # Create the job with explicit fee value
        result = create_job(job_type, job_data)
        # Debug: Print the result

        if result:
            flash("Job created successfully!", "success")
        else:
            flash("Job creation failed - no ID returned", "danger")
            
        return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"Error in create_new_job: {str(e)}")
        print(f"Error type: {type(e)}")
        flash("An error occurred while creating the job.", "danger")
        return redirect(url_for('dashboard'))

def create_job(job_type, job_data):
    """Create a new job with explicit fee handling"""
    try:
        # Debug: Print incoming job data
        
        # Ensure fee is a float
        fee = float(job_data.get('fee', 0.0))

        # Create base job document with explicit fee
        base_job = {
            "user_id": ObjectId(job_data["user_id"]),
            "fee": fee,  # Explicitly set fee
            "status": "Not Accepted Yet",
            "created_at": datetime.datetime.now(),
            "updated_at": datetime.datetime.now(),
            "datetime": job_data.get("datetime", datetime.datetime.now())
        }
        
        print("Base job document:", base_job)
        
        # Add type-specific fields
        if job_type == "creative_work":
            collection = mongo.db.creative_work
            base_job.update({
                "job_title": job_data["job_title"],
                "job_description": job_data["job_description"],
                "meetup_type": job_data.get("meetup_type", "VIRTUAL"),
                "location": job_data.get("location")
            })
        elif job_type == "academic_help":
            collection = mongo.db.academic_help
            base_job.update({
                "job_title": "Academic Help: " + job_data["subject"],
                "subject": job_data["subject"],
                "problem_description": job_data["problem_description"],
                "meetup_type": job_data.get("meetup_type", "VIRTUAL"),
                "location": job_data.get("location")
            })
        elif job_type == "food_delivery":
            collection = mongo.db.food_delivery
            base_job.update({
                "job_title": "Food Delivery From " + job_data["restaurant_name"],
                "restaurant_name": job_data["restaurant_name"],
                "order_description": job_data["order_description"]
            })
        
        print("Final document to insert:", base_job)
        
        # Insert document and verify fee
        result = collection.insert_one(base_job)


        return str(result.inserted_id)
        
    except Exception as e:
        print(f"Error in create_job: {str(e)}")
        print(f"Error type: {type(e)}")
        raise

def get_all_jobs():
    """
    Retrieve all active jobs from all collections with type information
    Returns a list of jobs sorted by creation date
    """
    all_jobs = []
    
    # Collect jobs from each type
    job_types = ["creative_work", "academic_help", "food_delivery"]
    
    for job_type in job_types:
        jobs = list(mongo.db[job_type].find({"status": "Not Accepted Yet"}))
        for job in jobs:
            job["_id"] = str(job["_id"])
            job["user_id"] = str(job["user_id"])
            job["job_type"] = job_type
            all_jobs.append(job)
    
    # Sort by creation date (newest first)
    return sorted(all_jobs, key=lambda x: x["created_at"], reverse=True)

def format_job_for_display(job):
    """
    Format a job document for display in the template
    """
    formatted_job = {
        "id": str(job["_id"]),
        "fee": "{:.2f}".format(job["fee"]),
        "created_at": job["created_at"],
        "job_type": job.get("job_type", "unknown"),
        "status": job["status"]
    }
    
    # Add type-specific display fields
    if job["job_type"] == "creative_work":
        formatted_job.update({
            "job_title": job["job_title"],
            "job_description": job["job_description"],
            "location": job.get("location", "Online"),
            "meetup_type": job["meetup_type"]
        })
    elif job["job_type"] == "academic_help":
        formatted_job.update({
            "job_title": f"Help needed with {job['subject']}",
            "job_description": job["problem_description"],
            "location": job.get("location", "Online"),
            "meetup_type": job["meetup_type"]
        })
    elif job["job_type"] == "food_delivery":
        formatted_job.update({
            "job_title": f"Food Delivery from {job['restaurant_name']}",
            "job_description": job["order_description"]
        })
        
    return formatted_job


if __name__ == "__main__":
    setup_database_indices()
    app.run(debug=True)