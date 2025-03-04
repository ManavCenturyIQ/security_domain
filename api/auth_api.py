from flask import Blueprint, request, redirect, url_for, session, flash, render_template
from flask_bcrypt import Bcrypt
from pymongo import MongoClient

auth_api = Blueprint('auth_api', __name__)

# Initialize Bcrypt for password hashing
bcrypt = Bcrypt()

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")  # Replace with your MongoDB URI
db = client["security_db"]  # Database name
users_collection = db["users"]  # User collection

@auth_api.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = users_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session['username'] = username
            flash("Login successful!", "success")
            return redirect(url_for('domain_check'))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html")

@auth_api.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if users_collection.find_one({"username": username}):
            flash("Username already exists", "danger")
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users_collection.insert_one({"username": username, "password": hashed_password})
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('auth_api.login'))

    return render_template("signup.html")

@auth_api.route("/logout")
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))