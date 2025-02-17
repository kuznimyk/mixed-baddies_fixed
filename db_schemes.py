from bson.objectid import ObjectId
import datetime

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