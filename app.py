from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)
import pytz
import logging
import requests
from flask_bcrypt import Bcrypt
from pymongo import MongoClient

import base64
import re
import time
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import random
import string
from datetime import datetime, timedelta
from io import BytesIO
import pandas as pd
from flask import Flask, request, send_file
import io
import os
from dotenv import load_dotenv
# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.common.by import By
dotenv_path = os.path.join(os.path.dirname(__file__), 'credentials', '.env')
load_dotenv(dotenv_path)
app = Flask(__name__)

# Secret Key for session management

app.secret_key = os.getenv("SECRET_KEY")
DOMAINR_API_KEY = os.getenv("DOMAINR_API_KEY")
MALICIOUS_API_KEY = os.getenv("MALICIOUS_API_KEY")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
# RapidAPI credentials

print("Secret Key:", os.getenv("SECRET_KEY"))
# Initialize Bcrypt for password hashing
bcrypt = Bcrypt(app)

# MongoDB connection
client = MongoClient("mongodb://admin:CenturyAi%40123@18.130.109.143:27017/?authSource=admin")  # Replace with MongoDB URI
db = client["security_db"]  # Database name
users_collection = db["users"]  # User collection
safe_domains_collection = db["safe_domains"]
malicious_domains_collection = db["malicious_domains"]
search_keywords_collection = db["search_keywords"]
manual_takedown_collection = db["manual_takedown"]
only_domain_collection = db["only_domain"]
godaddy_collection = db["godaddy"]
expiring_domains_collection = db["expiring_domains"]
trash_domain_collection = db["trash_domains"]
domain_provider_collection = db["domain_providers"]
logging.basicConfig(level=logging.DEBUG)
# Your AWS Access and Secret Keys


# SES Region (e.g., us-east-1, us-west-2, etc.)
AWS_REGION = "us-east-1"

# Email details
SENDER = "donotreply@cfc.ae"
# RECIPIENT = "manavajmera2003@gmail.com"
SUBJECT = "Domain Takedown Request"
BODY_TEXT_TEMPLATE = "A takedown request has been made for the domain: {}\n"
BODY_HTML_TEMPLATE = """
<html>
<head></head>
<body>
  <h1>Phishing website complaint</h1>
  <p>Kind Attention;</p>
  <p>We are reaching out to inform you of the emergence of a phishing website created by the same operators for whom we previously filed an abuse report. These individuals or group has launched a new phishing site under a different domain registered with namesilo(dynamic).</p>
  <p>The site, currently active at https://{}, features identical content to the previously taken-down site. It is a deceptive copy of our official Century Financial website https://www.century.ae/en/ and poses a serious threat to unsuspecting individuals looking for a legitimate financial services. Before any individuals fall for their scams, we are looking forward on taking down the phishing website.</p>
  <p>Given the ongoing threat posed by these fraudulent sites, we urgently request immediate action to protect innocent customers from being misled and potentially suffering financial harm. We ask that you promptly investigate this matter and take necessary steps to deactivate the phishing website.

We remain committed to protecting our clients and preserving the integrity of our services. Your prompt action is critical to preventing further damage.</p>
  <p>Thank you for addressing this urgent issue. We look forward to hearing from you soon regarding the steps taken to resolve it.

 </p>
</body>
</html>
"""
CHARSET = "UTF-8"


@app.route("/send_email_takedown", methods=["POST"])
def send_email_takedown():
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        return jsonify({"message": "Domain is required"}), 400

    # Check if the domain exists in the malicious_domains collection
    domain_entry = malicious_domains_collection.find_one({"domain": domain})

    if not domain_entry:
        return jsonify({"message": "Domain is missing from the database."}), 404

    # Fetch the recipient email from the domain entry
    recipient_email = domain_entry.get("email")

    if not recipient_email:
        # Insert the domain entry into the manual_takedown collection
        manual_takedown_collection.insert_one(
            {
                "domain": domain,
                "manual_takedown": "yes",
                "timestamp": time.time(),  # Optional: Add a timestamp for when it was marked
            }
        )
        return (
            jsonify(
                {
                    "message": "Email ID is missing for the domain. Moved to manual takedown collection."
                }
            ),
            404,
        )

    body_text = BODY_TEXT_TEMPLATE.format(domain)
    body_html = BODY_HTML_TEMPLATE.format(domain)

    try:
        # Initialize the SES client
        ses_client = boto3.client(
            "ses",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
        )

        # Send the email
        response = ses_client.send_email(
            Source=SENDER,
            Destination={"ToAddresses": [recipient_email]},
            Message={
                "Subject": {"Data": SUBJECT, "Charset": CHARSET},
                "Body": {
                    "Text": {"Data": body_text, "Charset": CHARSET},
                    "Html": {"Data": body_html, "Charset": CHARSET},
                },
            },
        )

        return jsonify({"message": f"Email sent! Message ID: {response['MessageId']}"})

    except NoCredentialsError:
        logging.error("NoCredentialsError: AWS credentials not available.")
        return (
            jsonify(
                {
                    "message": "Credentials not available. Please check your AWS access and secret keys."
                }
            ),
            500,
        )
    except PartialCredentialsError:
        logging.error("PartialCredentialsError: Incomplete AWS credentials provided.")
        return jsonify({"message": "Incomplete credentials provided."}), 500
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        return jsonify({"message": f"Error sending email: {str(e)}"}), 500


@app.route("/delete_domain", methods=["POST"])
def delete_domain():
    data = request.get_json()
    domain_name = data.get("domain")

    # Try to find and remove the domain from the only_domain collection
    domain = only_domain_collection.find_one_and_delete({"Domain Name": domain_name})
    if not domain:
        # If not found, try to find and remove it from the godaddy collection
        domain = godaddy_collection.find_one_and_delete({"Domain Name": domain_name})

    if domain:
        # Insert the domain into the trash_domain collection
        trash_domain_collection.insert_one(domain)
        return jsonify(
            {"success": True, "message": "Domain moved to trash successfully."}
        )
    else:
        return jsonify({"success": False, "message": "Domain not found."}), 404


@app.route("/add_provider", methods=["POST"])
def add_provider():
    data = request.json
    provider_name = data.get("providerName")

    if provider_name:
        # Insert the new provider into the collection
        domain_provider_collection.insert_one({"Provider Name": provider_name})
        return jsonify({"success": True, "message": "Provider added successfully!"})
    else:
        return jsonify({"success": False, "message": "Provider name is required."})


@app.route("/add_domain_form")
def add_domain_form():
    # Fetch all providers from the collection
    providers = list(
        domain_provider_collection.find({}, {"_id": 0, "Provider Name": 1})
    )
    provider_names = [provider["Provider Name"] for provider in providers]
    return render_template("add_domain_form.html", providers=provider_names)


def check_malicious(domain):
    """
    Check the safety status of a given domain using the Malicious Scanner API.
    This function extracts specific keys like 'status', 'message', and 'category' from the JSON response.
    """
    url = "https://malicious-scanner.p.rapidapi.com/rapid/url"
    querystring = {"url": domain}
    headers = {
        "x-rapidapi-key": MALICIOUS_API_KEY,
        "x-rapidapi-host": "malicious-scanner.p.rapidapi.com",
    }

    try:
        logging.debug(f"Sending request to Malicious Scanner API for domain: {domain}")
        response = requests.get(url, headers=headers, params=querystring)
        logging.debug(
            f"Malicious Scanner response for {domain} - Status Code: {response.status_code}"
        )
        logging.debug(f"Raw response for {domain}: {response.text}")  # Added debug log

        if response.status_code != 200:
            logging.error(f"Malicious Scanner Error - {response.text}")
            return {
                "status": "Error",
                "message": f"Request failed with status code {response.status_code}",
                "category": "N/A",
            }

        try:
            data = response.json()
            logging.debug(f"Malicious Scanner JSON data for {domain} - {data}")

            if "data" in data:
                result = data["data"]
                return {
                    "status": result.get("status", "N/A"),
                    "message": result.get("message", "N/A"),
                    "category": result.get("category", "N/A"),
                    "details": result,  # Optional: Include all details if needed
                }

            logging.warning(f"No 'data' field found in response for {domain}")
            return {
                "status": "Error",
                "message": "No 'data' field found in response",
                "category": "N/A",
            }

        except ValueError as e:
            logging.error(f"Malicious Scanner JSON parsing error for {domain} - {e}")
            return {
                "status": "Error",
                "message": "Invalid JSON response",
                "category": "N/A",
            }
    except requests.exceptions.RequestException as e:
        logging.error(f"Malicious Scanner RequestException for {domain} - {e}")
        return {
            "status": "Error",
            "message": f"Request failed: {e}",
            "category": "N/A",
        }


@app.route("/domain_check", methods=["GET", "POST"])
def domain_check():
    if "username" not in session:
        return redirect(url_for("login"))

    results = []

    if request.method == "POST":
        keyword = request.form.get("keyword")
        logging.debug(f"Received keyword: {keyword}")
        if keyword:
            try:
                domain_results = fetch_domain_results(keyword)
                logging.debug(f"Domain results: {domain_results}")
                if domain_results:
                    results.append(
                        {
                            "keyword": keyword,
                            "results": [
                                {
                                    "domain": result.get("domain"),
                                    "zone": result.get("zone"),
                                    "host": result.get("host"),
                                    "subdomain": result.get("subdomain"),
                                    "registerURL": result.get("registerURL"),
                                    "safety_status": result.get(
                                        "malicious_data", {}
                                    ).get("status"),
                                    "message": result.get("malicious_data", {}).get(
                                        "message"
                                    ),
                                    "category": result.get("malicious_data", {}).get(
                                        "category"
                                    ),
                                }
                                for result in domain_results
                            ],
                        }
                    )
                    store_results_in_db(keyword, domain_results)
                else:
                    flash("No valid domains found for the given keyword.", "error")
            except Exception as e:
                logging.error(f"Error processing keyword '{keyword}': {e}")
                flash("An error occurred while processing your request.", "error")
        else:
            flash("Keyword cannot be empty. Please enter a valid search term.", "error")

    return render_template("domain_check.html", results=results)


def fetch_domain_results(keyword):
    """
    Fetch domain details from the Domainr API and check safety status for each domain.
    """
    domainr_url = "https://domainr.p.rapidapi.com/v2/search"
    headers = {
        "x-rapidapi-key": DOMAINR_API_KEY,
        "x-rapidapi-host": "domainr.p.rapidapi.com",
    }
    querystring = {"query": keyword}

    try:
        response = requests.get(
            domainr_url, headers=headers, params=querystring, timeout=10
        )
        logging.debug(f"Domainr API response - Status Code: {response.status_code}")

        if response.status_code != 200:
            logging.error(f"Domainr API Error - {response.text}")
            return []

        domains = response.json().get("results", [])
        logging.debug(f"Fetched domains: {domains}")

        results = []
        for domain in domains:
            domain_details = {
                "domain": domain.get("domain", "Unknown domain"),
                "zone": domain.get("zone", "Unknown zone"),
                "host": domain.get("host", "Unknown host"),
                "subdomain": domain.get("subdomain", ""),
                "path": domain.get("path", ""),
                "registerURL": domain.get("registerURL", ""),
            }

            malicious_data = check_malicious(f"https://{domain_details['domain']}")
            logging.debug(
                f"Malicious data for {domain_details['domain']}: {malicious_data}"
            )
            domain_details["malicious_data"] = malicious_data

            results.append(domain_details)

        return results

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching domain results: {e}")
        return []


@app.route("/mark_as_safe", methods=["POST"])
def mark_as_safe():
    data = request.get_json()
    domain = data.get("domain")

    # Check if the domain is already marked as safe
    existing_domain = safe_domains_collection.find_one({"domain": domain})
    if existing_domain:
        return jsonify({"message": "Domain is already marked as safe."}), 400

    # Insert the domain into the safe_domains_collection
    safe_domains_collection.insert_one({"domain": domain})
    return jsonify({"message": "Domain marked as safe successfully."}), 200


@app.route("/mark_as_malicious", methods=["POST"])
def mark_as_malicious():
    data = request.get_json()
    domain = data.get("domain")

    # Check if the domain is already marked as malicious
    existing_domain = malicious_domains_collection.find_one({"domain": domain})
    if existing_domain:
        return jsonify({"message": "Domain is already marked as malicious."}), 400

    # Insert the domain into the malicious_domains_collection
    malicious_domains_collection.insert_one({"domain": domain})
    return jsonify({"message": "Domain marked as malicious successfully."}), 200

BODY_TEXT_TEMPLATE_renew = "Renew this domain: {}"
BODY_HTML_TEMPLATE_renew = """
<html>
<head></head>
<body>
  <p>Renew this domain: <span style="font-weight:bold;">{}</span></p>
</body>
</html>
"""
@app.route("/send-email", methods=["POST"])
def send_email():
    data = request.get_json()
    domain = data.get("domain")
    message = data.get("message")

    # Logic to send email using AWS SES
    try:
        # Initialize the SES client
        ses_client = boto3.client(
            'ses',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY
        )

        # Send the email
        response = ses_client.send_email(
            Source=SENDER,
            Destination={
                'ToAddresses': ["manav.ajmera@centuryiq.in","neeraj@century.ae"]
            },
            Message={
                'Subject': {
                    'Data': "Renew Domain Request",
                    'Charset': CHARSET
                },
                'Body': {
                    'Text': {
                        'Data': "Please Renew this domain: {domain}",
                        'Charset': CHARSET
                    },
                    'Html': {
                        'Data': BODY_TEXT_TEMPLATE_renew.format(domain),
                        'Charset': CHARSET
                    }
                }
            }
        )

        return jsonify({"message": f"Email sent successfully! Message ID: {response['MessageId']}"}), 200

    except NoCredentialsError:
        logging.error("NoCredentialsError: AWS credentials not available.")
        return jsonify({"message": "Credentials not available. Please check your AWS access and secret keys."}), 500
    except PartialCredentialsError:
        logging.error("PartialCredentialsError: Incomplete AWS credentials provided.")
        return jsonify({"message": "Incomplete credentials provided."}), 500
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        return jsonify({"message": f"Error sending email: {str(e)}"}), 500
BODY_HTML_TEMPLATE_donotrenew = """
<html>
<head></head>
<body>
  <p>Do not Renew this domain: <span style="font-weight:bold;">{}</span></p>
</body>
</html>
"""
@app.route("/send_email_dontrenew", methods=["POST"])
def send_email_dontrenew():
    data = request.get_json()
    domain = data.get("domain")
    message2 = data.get("message")

    # Logic to send email using AWS SES
    try:
        # Initialize the SES client
        ses_client = boto3.client(
            'ses',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY
        )

        # Send the email
        response = ses_client.send_email(
            Source=SENDER,
            Destination={
                'ToAddresses': ["manav.ajmera@centuryiq.in","neeraj@century.ae"]
            },
            Message={
                'Subject': {
                    'Data': "Do not Renew Domain Request",
                    'Charset': CHARSET
                },
                'Body': {
                    'Text': {
                        'Data': "Don't Renew this domain: {domain}",
                        'Charset': CHARSET
                    },
                    'Html': {
                        'Data': BODY_HTML_TEMPLATE_donotrenew.format(domain),
                        'Charset': CHARSET
                    }
                }
            }
        )

        return jsonify({"message": f"Email sent successfully! Message ID: {response['MessageId']}"}), 200

    except NoCredentialsError:
        logging.error("NoCredentialsError: AWS credentials not available.")
        return jsonify({"message": "Credentials not available. Please check your AWS access and secret keys."}), 500
    except PartialCredentialsError:
        logging.error("PartialCredentialsError: Incomplete AWS credentials provided.")
        return jsonify({"message": "Incomplete credentials provided."}), 500
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        return jsonify({"message": f"Error sending email: {str(e)}"}), 500

@app.route("/renew-domain", methods=["POST"])
def renew_domain():
    data = request.get_json()
    domain = data.get("domain")

    try:
        # Determine the provider by checking both collections
        domain_data = only_domain_collection.find_one({"Domain Name": domain})
        if domain_data:
            provider = "Only Domains"
            collection = only_domain_collection
            expiry_field = "Expiry Renewal Date"
        else:
            domain_data = godaddy_collection.find_one({"Domain Name": domain})
            if domain_data:
                provider = "GoDaddy"
                collection = godaddy_collection
                expiry_field = "Expiration Date"
            else:
                logging.error("Domain not found in any provider's collection.")
                return jsonify({"message": "Domain not found."}), 404

        # Fetch the current expiry date from the selected collection
        current_expiry_date = domain_data.get(expiry_field)
        if not current_expiry_date:
            logging.error("Expiry date not found for the domain.")
            return jsonify({"message": "Expiry date not found for the domain."}), 404

        # Convert the expiry date to a datetime object
        try:
            current_expiry_date = datetime.strptime(current_expiry_date, "%d-%m-%Y")
        except ValueError as e:
            logging.error(f"Error parsing expiry date: {e}")
            return jsonify({"message": "Invalid expiry date format."}), 400

        # Add one year to the current expiry date
        new_expiry_date = current_expiry_date + timedelta(days=365)

        # Update the expiry date in the selected collection
        result = collection.update_one(
            {"Domain Name": domain},
            {"$set": {expiry_field: new_expiry_date.strftime("%d-%m-%Y")}}
        )

        if result.modified_count == 0:
            logging.error("Failed to update the expiry date.")
            return jsonify({"message": "Failed to update the expiry date."}), 500

        # Remove the domain from the expired_domains collection if it exists
        expiring_domains_collection.delete_one({"Domain Name": domain})

        logging.info("Domain renewed successfully!")
        return jsonify({"message": "Domain renewed successfully!"}), 200
    except Exception as e:
        logging.error(f"Error renewing domain: {str(e)}")
        return jsonify({"message": f"Error renewing domain: {str(e)}"}), 500

@app.route("/get_safe_domains", methods=["GET"])
def get_safe_domains():
    try:
        # Fetch safe domains from the safe_domains_collection
        safe_domains = list(safe_domains_collection.find())

        # Construct the safe_domains list with the required format
        safe_domains_list = [{"domain": domain["domain"]} for domain in safe_domains]

        return jsonify(safe_domains_list)
    except Exception as e:
        return str(e), 500


@app.route("/get_malicious_domains", methods=["GET"])
def get_malicious_domains():
    try:
        # Fetch malicious domains from the malicious_domains_collection
        malicious_domains = list(malicious_domains_collection.find())

        # Construct the malicious_domains list with the required format
        malicious_domains_list = [
            {"domain": domain["domain"]} for domain in malicious_domains
        ]

        return jsonify(malicious_domains_list)
    except Exception as e:
        return str(e), 500


def store_expiring_domains():
    # Fetch data from the existing collections
    only_domains = list(
        only_domain_collection.find(
            {}, {"Domain Name": 1, "Expiry Renewal Date": 1, "_id": 0}
        )
    )

    # Add provider information
    for domain in only_domains:
        domain["Provider"] = "Only Domains"

    godaddy_domains = list(
        godaddy_collection.find({}, {"Domain Name": 1, "Expiration Date": 1, "_id": 0})
    )

    # Add provider information
    for domain in godaddy_domains:
        domain["Provider"] = "GoDaddy"

    # Combine the data
    all_domains = only_domains + godaddy_domains

    # Get today's date and the date two days from now
    today = datetime.now().date()
    two_days_from_now = today + timedelta(days=0)

    # Check for domains that are expired or expiring in 2 days
    for domain in all_domains:
        expiry_date_str = domain.get("Expiry Renewal Date") or domain.get(
            "Expiration Date"
        )
        if expiry_date_str:
            expiry_date = datetime.strptime(expiry_date_str, "%d-%m-%Y").date()
            if expiry_date <= two_days_from_now:
                # Use upsert to avoid duplicates
                expiring_domains_collection.update_one(
                    {"Domain Name": domain["Domain Name"]},
                    {"$set": domain},
                    upsert=True,
                )


# Call this function where appropriate in your application
store_expiring_domains()


@app.route("/", methods=["GET"])
def home():
    return render_template("welcome.html")


@app.route("/only_domain")
def only_domain():
    # Fetch specific fields from the only_domain collection
    domains = list(
        only_domain_collection.find(
            {},
            {
                "Domain Name": 1,
                "Registrant": 1,
                "Expiry Renewal Date": 1,
                "Status  DNS": 1,  # Adjusted field name to match the CSV
                "Nameserver1": 1,
                "Nameserver2": 1,
                "Nameserver3": 1,
                "_id": 0,
            },
        )
    )
    logging.debug(f"Fetched domains: {domains}")
    return render_template("only_domain.html", domains=domains)


@app.route("/godaddy", methods=["GET"])
def godaddy():
    # Fetch specific fields from the godaddy collection
    domains = list(
        godaddy_collection.find(
            {},
            {
                "Domain Name": 1,
                "TLD": 1,
                "Create Date": 1,
                "Ownership Date": 1,
                "Expiration Date": 1,
                "Auto-renew": 1,
                "Status": 1,
                "ListingStatus": 1,
                "Type": 1,
                "Nameserver1": 1,
                "Nameserver2": 1,
                "_id": 0,
            },
        )
    )
    logging.debug(f"Fetched GoDaddy domains: {domains}")
    return render_template("godaddy.html", domains=domains)


@app.route("/keywords", methods=["GET"])
def keywords():
    page = request.args.get("page", 1, type=int)
    per_page = 25
    total_keywords = search_keywords_collection.count_documents({})
    keywords_data = list(
        search_keywords_collection.find({}, {"_id": 0, "keyword": 1, "timestamp": 1})
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    return render_template(
        "keywords.html",
        keywords_data=keywords_data,
        page=page,
        total_keywords=total_keywords,
        per_page=per_page,
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    # Check if the user is logged in and has the admin role
    if 'role' not in session or session['role'] != 'admin':
        flash("You must be an admin to access the signup page.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]  # Get the role from the form

        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            flash('User already exists! <a href="/login">Login here</a>', "error")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        users_collection.insert_one({
            "username": username,
            "password": hashed_password,
            "role": role  # Store the role in the database
        })
        flash("Sign-up successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = users_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["username"] = username
            session["role"] = user["role"]  # Store the user's role in the session
            flash("Login successful!", "success")
            return redirect(url_for("list_of_domains"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


@app.route("/safe_page", methods=["GET"])
def safe_page():
    page = request.args.get("page", 1, type=int)
    per_page = 25
    total_safe_domains = safe_domains_collection.count_documents({})
    safe_domains = list(
        safe_domains_collection.find({}, {"_id": 0, "domain": 1})
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    return render_template(
        "safe_page.html",
        safe_domains=safe_domains,
        page=page,
        total_safe_domains=total_safe_domains,
        per_page=per_page,
    )


@app.route("/malicious_page", methods=["GET"])
def malicious_page():
    page = request.args.get("page", 1, type=int)
    per_page = 25
    total_malicious_domains = malicious_domains_collection.count_documents({})
    malicious_domains = list(
        malicious_domains_collection.find({}, {"_id": 0, "domain": 1})
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    return render_template(
        "malicious_page.html",
        malicious_domains=malicious_domains,
        page=page,
        total_malicious_domains=total_malicious_domains,
        per_page=per_page,
    )


@app.route("/manual_takedown", methods=["GET"])
def manual_takedown():
    page = request.args.get("page", 1, type=int)
    per_page = 25
    total_manual_takedowns = manual_takedown_collection.count_documents({})
    manual_takedowns = list(
        manual_takedown_collection.find({}, {"_id": 0, "domain": 1})
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    return render_template(
        "manual_takedown.html",
        manual_takedowns=manual_takedowns,
        page=page,
        total_manual_takedowns=total_manual_takedowns,
        per_page=per_page,
    )


@app.route("/list_of_domains", methods=["GET"])
def list_of_domains():
    # Fetch safe domains
    safe_domains = list(safe_domains_collection.find({}, {"_id": 0, "domain": 1}))
    safe_count = len(safe_domains)
    username = session.get("username")  # Retrieve the username from the session
    logging.debug(f"Username retrieved: {username}")
    # Fetch malicious domains
    malicious_domains = list(
        malicious_domains_collection.find({}, {"_id": 0, "domain": 1})
    )
    malicious_count = len(malicious_domains)

    # Fetch manual takedown domains
    manual_takedowns = list(
        manual_takedown_collection.find({}, {"_id": 0, "domain": 1, "timestamp": 1})
    )
    manual_takedown_count = len(manual_takedowns)

    # Fetch keywords count
    keywords_count = search_keywords_collection.count_documents({})
    expiring_domains_count = expiring_domains_collection.count_documents({})
    return render_template(
        "list_of_domains.html",
        username=username,  # Pass the username to the template
        safe_domains=safe_domains,
        malicious_domains=malicious_domains,
        manual_takedowns=manual_takedowns,
        keywords_count=keywords_count,
        safe_count=safe_count,
        malicious_count=malicious_count,
        manual_takedown_count=manual_takedown_count,
        expiring_domains_count=expiring_domains_count,
    )


@app.route("/owned_domains")
def owned_domains():
    # logging.basicConfig(level=logging.DEBUG)
    # Fetch data from both collections
    only_domains = list(
        only_domain_collection.find(
            {},
            {
                "Domain Name": 1,
                "Registrant": 1,
                "Expiry Renewal Date": 1,
                "Status": 1,
                "Nameserver1": 1,
                "Nameserver2": 1,
                "Nameserver3": 1,
                "Provider Name": 1,  # Ensure Provider Name is fetched
                "_id": 0,
            },
        )
    )
    # Add provider information
    for domain in only_domains:
        domain["Provider"] = domain.get("Provider Name", "Only Domains")

    godaddy_domains = list(
        godaddy_collection.find(
            {},
            {
                "Domain Name": 1,
                "TLD": 1,
                "Create Date": 1,
                "Ownership Date": 1,
                "Expiration Date": 1,
                "Auto-renew": 1,
                "Status": 1,
                "ListingStatus": 1,
                "Type": 1,
                "Nameserver1": 1,
                "Nameserver2": 1,
                "Renewal Price": 1,
                "Provider Name": 1,  # Ensure Provider Name is fetched
                "_id": 0,
            },
        )
    )
    # Add provider information
    for domain in godaddy_domains:
        domain["Provider"] = domain.get("Provider Name", "GoDaddy")

    # Fetch provider information from domain_providers collection
    domain_providers = list(
        domain_provider_collection.find({}, {"_id": 0, "Provider Name": 1})
    )
    provider_names = [provider["Provider Name"] for provider in domain_providers]

    # Combine the data
    all_domains = only_domains + godaddy_domains

    # Extract unique providers
    providers = list(
        set(domain["Provider"] for domain in all_domains) | set(provider_names)
    )
    logging.debug(f"Fetched GoDaddy domains: {godaddy_domains}")
    return render_template(
        "owned_domains.html", domains=all_domains, providers=providers
    )


@app.route("/add_domain", methods=["POST"])
def add_domain():
    data = request.json
    domain_name = data.get("domainName")
    domain_provider = data.get("domainProvider")
    expiry_date = data.get("expiryDate")
    status = data.get("status")
    renewal_price = data.get("renewalPrice", "Not Available")

    if domain_provider == "Only Domains":
        only_domain_collection.insert_one(
            {
                "Domain Name": domain_name,
                "Registrant": "Unknown",  # You can modify this as needed
                "Expiry Renewal Date": expiry_date,
                "Status": status,
                "Nameserver1": "ns1.onlydomains.com",  # Default values
                "Nameserver2": "ns2.onlydomains.com",
                "Nameserver3": "ns3.onlydomains.com",
            }
        )
    elif domain_provider == "GoDaddy":
        godaddy_collection.insert_one(
            {
                "Domain Name": domain_name,
                "TLD": domain_name.split(".")[-1],
                "Create Date": "Unknown",  # You can modify this as needed
                "Ownership Date": "Unknown",
                "Expiration Date": expiry_date,
                "Auto-renew": "Unknown",
                "Status": status,
                "ListingStatus": "Unknown",
                "Type": "Unknown",
                "Nameserver1": "ns1.godaddy.com",  # Default values
                "Nameserver2": "ns2.godaddy.com",
                "Renewal Price": renewal_price,
            }
        )

    return jsonify({"success": True, "message": "Domain added successfully!"})

# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
# logging.basicConfig(level=logging.DEBUG)
def send_expiring_domains_email():
    try:
        # Fetch all domains from the expiring_domains_collection
        expiring_domains = list(
            expiring_domains_collection.find(
                {},  # No filter to fetch all documents
                {"Domain Name": 1, "Expiry Renewal Date": 1, "Provider": 1, "_id": 0},
            )
        )

        if not expiring_domains:
            return "No domains found in the expiring domains collection."

        # Create a DataFrame from the expiring domains
        df = pd.DataFrame(expiring_domains)
        # Save the DataFrame to an Excel file in memory
        excel_buffer = BytesIO()
        with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="Expiring Domains")

        # Get the Excel file content
        excel_content = excel_buffer.getvalue()

        # Initialize the SES client
        ses_client = boto3.client(
            "ses",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
        )

        # Send the email with the Excel attachment
        response = ses_client.send_raw_email(
            Source="donotreply@cfc.ae",
            Destinations=["manav.ajmera@centuryiq.in","neeraj@century.ae"],
            RawMessage={
                "Data": f"""From: {"donotreply@cfc.ae"}
To: {"manavajmera03@gmail.com"}
Subject: Expiring Domains Notification
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="NextPart"

--NextPart
Content-Type: text/plain; charset="utf-8"

Please find attached the list of domains expiring within the next 30 days.

--NextPart
Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; name="expiring_domains.xlsx"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="expiring_domains.xlsx"

{base64.b64encode(excel_content).decode('utf-8')}
--NextPart--
"""
            },
        )

        return f"Email sent! Message ID: {response['MessageId']}"

    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        return f"Error sending email: {str(e)}"



@app.route("/send_expiry_alert", methods=["POST"])
def send_expiry_alert():
    message = send_expiring_domains_email()
    return jsonify({"message": message})


@app.route("/export_to_excel", methods=["POST"])
def export_to_excel():
    data = request.get_json()

    # Assuming data is a list of dictionaries representing the table rows
    df = pd.DataFrame(data)

    # Create a BytesIO object to hold the Excel file
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Sheet1")

    # Seek to the beginning of the stream
    output.seek(0)

    # Send the file to the client
    return send_file(
        output,
        as_attachment=True,
        download_name="report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/get_manual_domains", methods=["GET"])
def get_manual_domains():
    try:
        # Fetch manual takedown domains from the database
        manual_domains = list(
            manual_takedown_collection.find({}, {"_id": 0, "domain": 1})
        )
        if manual_domains:
            flash("Records have been moved to manual takedown.", "success")
        return jsonify(manual_domains), 200
    except Exception as e:
        return (str(e),)


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            logging.debug("New passwords do not match.")
            return redirect(url_for("forgot_password"))

        user = users_collection.find_one({"email": email})
        if not user:
            flash("Email not found.", "error")
            logging.debug(f"Email not found: {email}")
            return redirect(url_for("forgot_password"))

        if not bcrypt.check_password_hash(user["password"], old_password):
            flash("Old password is incorrect.", "error")
            logging.debug("Old password is incorrect.")
            return redirect(url_for("forgot_password"))

        hashed_new_password = bcrypt.generate_password_hash(new_password).decode(
            "utf-8"
        )
        users_collection.update_one(
            {"email": email}, {"$set": {"password": hashed_new_password}}
        )
        flash("Password updated successfully.", "success")
        logging.debug("Password updated successfully for email: {email}")
        return redirect(url_for("login"))

    return render_template("forget_password.html")


def store_results_in_db(keyword, domain_results):
    sanitized_keyword = keyword.replace(" ", "_").lower()
    new_collection = db[sanitized_keyword]
    new_collection.insert_one({"keyword": keyword, "results": domain_results})

    # Insert the keyword into the search_keywords_collection with a timestamp
    search_keywords_collection.insert_one(
        {
            "keyword": keyword,
            "timestamp": datetime.utcnow(),  # Store the current UTC time
        }
    )


if __name__ == "__main__":
    app.run(debug=True)