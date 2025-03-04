from flask import Blueprint, request, jsonify
from pymongo import MongoClient

domain_api = Blueprint('domain_api', __name__)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")  # Replace with your MongoDB URI
db = client["security_db"]  # Database name
safe_domains_collection = db["safe_domains"]
malicious_domains_collection = db["malicious_domains"]

@domain_api.route("/domain_check", methods=["GET", "POST"])
def domain_check():
    if request.method == "POST":
        domain = request.form.get("domain")
        # Implement domain checking logic here
        # For now, let's assume we return a dummy result
        results = {"domain": domain, "status": "checked"}
        return jsonify(results)
    return "Domain check page"

@domain_api.route("/mark_as_safe", methods=["POST"])
def mark_as_safe():
    domain = request.json.get("domain")
    if domain:
        safe_domains_collection.insert_one({"domain": domain})
        return jsonify({"message": "Domain marked as safe successfully."}), 200
    return jsonify({"message": "Domain is required."}), 400

@domain_api.route("/mark_as_malicious", methods=["POST"])
def mark_as_malicious():
    domain = request.json.get("domain")
    if domain:
        malicious_domains_collection.insert_one({"domain": domain})
        return jsonify({"message": "Domain marked as malicious successfully."}), 200
    return jsonify({"message": "Domain is required."}), 400

@domain_api.route("/get_safe_domains", methods=["GET"])
def get_safe_domains():
    try:
        safe_domains = list(safe_domains_collection.find({}, {"_id": 0, "domain": 1}))
        return jsonify(safe_domains), 200
    except Exception as e:
        return str(e), 500

@domain_api.route("/get_malicious_domains", methods=["GET"])
def get_malicious_domains():
    try:
        malicious_domains = list(malicious_domains_collection.find({}, {"_id": 0, "domain": 1}))
        return jsonify(malicious_domains), 200
    except Exception as e:
        return str(e), 500