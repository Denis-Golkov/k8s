import logging
import logging.handlers
import os
from flask import Flask, request, jsonify
import json
import ssl
import socket
import yaml
from flask_apscheduler import APScheduler
from datetime import datetime
import requests
from urllib.parse import urlparse
from elasticapm.contrib.flask import ElasticAPM
import psycopg2


class TPPDb():
    def __init__(self):
        DB_PARAMS ={
            'dbname': 'postgres',
            'user': 'postgres',
            'password': 'password',
            'host': 'localhost',
            'port': 5432
        }
        self.conn = psycopg2.connect(**DB_PARAMS)

    def add_user(self, username, password):
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO users (user_name, password) VALUES (%s, %s);", (username, password))
            self.conn.commit()


    def add_domain(self,domain,status,ssl_expiration,ssl_issuer):
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO domains (domain,status,ssl_expiration,ssl_issuer) VALUES (%s, %s, %s, %s);", (domain,status,ssl_expiration,ssl_issuer))
            self.conn.commit()

    def relation(self,user,domain):
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT user_id FROM users WHERE user_name='{user}'")
            user_id = cur.fetchone()
            cur.execute(f"SELECT domain_id FROM domains WHERE domain='{domain}'")
            domain_id = cur.fetchall()
            cur.execute("INSERT INTO relation (user_id,domain_id) VALUES (%s, %s);", (user_id[0], domain_id[-1]))
            # print(type(domain_id[0]))

    def login(self,user):
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT password FROM users WHERE user_name='{user}'")
            db_password = cur.fetchone()
            if db_password is None:
                return jsonify({"error": "Username does not exists"}), 400
            password = db_password[0]
            return password

tpp_db_obj = TPPDb()

# --- Load Configuration ---
with open('be_config.yaml', 'r') as f:
    config = yaml.safe_load(f)

APP_NAME = config['app_name']
LOG_DIRECTORY = config['log_directory']
DOMAIN_FILE = config['domain_file']
USERS_FILE = config['users_file']

# --- Setup Logging ---
os.makedirs(LOG_DIRECTORY, exist_ok=True)
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.DEBUG)

file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIRECTORY, 'be_app.log'),
    maxBytes=10*1024*1024,
    backupCount=5
)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

app = Flask(__name__)
app.logger = logger

app.config['ELASTIC_APM'] = {
  'SERVICE_NAME': 'test',
  'API_KEY': 'Qm9MV0Q1VUJSQXhxN0pZbVZfcVM6MzFIcWhFYW9DS3o1QWlTLUR1X0U4UQ==',
  'SERVER_URL': 'https://test-fcd1e6.apm.us-east-1.aws.elastic.cloud:443',
  'ENVIRONMENT': 'test',
  'DEBUG': True
}
apm = ElasticAPM(app)

# Initialize APScheduler
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

SEARCH_JOB_ID = "search_domains"
DEFAULT_INTERVAL = 3600  # 1 hour in seconds

# --- Data Management Functions ---
def load_users():
    """Load users from JSON file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
    return []

def save_users(users):
    """Save users to JSON file."""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving users file: {e}")

def load_domains(username):
    """Load domains for a specific user."""
    user_file = f"{username}_domain.json"
    if os.path.exists(user_file):
        try:
            with open(user_file, "r") as file:
                return json.load(file)
        except Exception as e:
            logger.error(f"Error loading domain file for user {username}: {e}")
    return []

def save_domains(domains, username):
    """Save domains for a specific user."""
    user_file = f"{username}_domain.json"
    try:
        with open(user_file, "w") as file:
            json.dump(domains, file, indent=4)
    except Exception as e:
        logger.error(f"Error saving domain file for user {username}: {e}")
    tpp_db_obj.relation(username,domains)
# --- Domain Monitoring Functions ---
def get_ssl_info(domain):
    """Retrieve SSL expiration and issuer information for a domain."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_expiration = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                ssl_issuer = dict(x[0] for x in cert['issuer'])
                return {
                    "ssl_expiration": ssl_expiration.strftime("%Y-%m-%d"),
                    "ssl_issuer": ssl_issuer.get("organizationName", "Unknown")
                }
    except Exception as e:
        logger.exception(f"Error retrieving SSL info for {domain}: {e}")
        return {
            "ssl_expiration": "N/A",
            "ssl_issuer": "Unknown"
        }

def check_domain_status(domain):
    """Check if a domain is alive or down."""
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return "Up" if response.status_code == 200 else f"Down ({response.status_code})"
    except Exception as e:
        logger.exception(f"Error checking domain status for {domain}: {e}")
        return "Down"

def create_user_search_job(username):
    """Create a scheduled job for a specific user's domain monitoring."""
    def user_domain_search():
        logger.info(f"Starting domain monitoring for user: {username}")
        domains = load_domains(username)
        
        for domain in domains:
            try:
                domain["status"] = check_domain_status(domain["domain"])
                ssl_info = get_ssl_info(domain["domain"])
                domain["ssl_expiration"] = ssl_info["ssl_expiration"]
                domain["ssl_issuer"] = ssl_info["ssl_issuer"]
            except Exception as e:
                logger.error(f"Error checking domain {domain['domain']}: {e}")
        
        save_domains(domains, username)
        
    return user_domain_search

# --- API Endpoints ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400
    
    db_password = tpp_db_obj.login(username)
    if db_password == password:
        return jsonify({"message": "Login successful!"}), 200
    
    return jsonify({"message": "Invalid username or password!"}), 401

    # users = load_users()
    # user = next((u for u in users if u["username"] == username and u["password"] == password), None)

    # if user:
    #     return jsonify({"message": "Login successful!"}), 200
    # return jsonify({"message": "Invalid username or password!"}), 401



@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    
    tpp_db_obj.add_user(username, password)
    # users = load_users()
    # if any(u["username"] == username for u in users):
    #     return jsonify({"message": "Username already exists!"}), 409

    # users.append({"username": username, "password": password})
    # save_users(users)
    return jsonify({"message": "Registration successful!"}), 201

@app.route('/api/domains', methods=['GET'])
def get_domains():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Username is required"}), 400
    return jsonify(load_domains(username))

@app.route('/api/domains', methods=['POST'])
def add_domain():
    data = request.get_json()
    domain = data.get("domain")
    username = data.get("username")

    if not domain or not username:
        return jsonify({"error": "Domain and username are required."}), 400

    # Clean domain
    parsed_url = urlparse(domain)
    clean_domain = parsed_url.netloc or parsed_url.path
    clean_domain = clean_domain.lstrip("www.")

    domains = load_domains(username)
    if any(d["domain"] == clean_domain for d in domains):
        return jsonify({"error": "Domain already exists."}), 400

    try:
        status = check_domain_status(clean_domain)
        ssl_info = get_ssl_info(clean_domain)
        
        domain_entry = {
            "domain": clean_domain,
            "status": status,
            "ssl_expiration": ssl_info["ssl_expiration"],
            "ssl_issuer": ssl_info["ssl_issuer"]
        }
        tpp_db_obj.add_domain(clean_domain,status,ssl_info["ssl_expiration"],ssl_info["ssl_issuer"])
        tpp_db_obj.relation(username,clean_domain)
        domains.append(domain_entry)
        save_domains(domains, username)
        return jsonify(domain_entry)
    except Exception as e:
        logger.exception(f"Error adding domain: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/domains', methods=['DELETE'])
def remove_domain():
    data = request.get_json()
    domain = data.get("domain")
    username = data.get("username")

    if not domain or not username:
        return jsonify({"error": "Domain and username are required."}), 400

    domains = load_domains(username)
    updated_domains = [d for d in domains if d["domain"] != domain]
    
    if len(updated_domains) == len(domains):
        return jsonify({"error": "Domain not found."}), 404

    save_domains(updated_domains, username)
    return jsonify({"message": f"Domain {domain} removed successfully."})

@app.route('/api/upload_domains', methods=['POST'])
def upload_domains():
    data = request.get_json()
    domains_list = data.get("domains", [])
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username is required."}), 400

    domains = load_domains(username)
    added_count = 0

    for domain in domains_list:
        domain = domain.strip()
        if not domain:
            continue

        # Clean domain
        parsed_url = urlparse(domain)
        clean_domain = parsed_url.netloc or parsed_url.path
        clean_domain = clean_domain.lstrip("www.")

        # Skip if domain already exists
        if any(d["domain"] == clean_domain for d in domains):
            continue

        try:
            status = check_domain_status(clean_domain)
            ssl_info = get_ssl_info(clean_domain)
            
            domain_entry = {
                "domain": clean_domain,
                "status": status,
                "ssl_expiration": ssl_info["ssl_expiration"],
                "ssl_issuer": ssl_info["ssl_issuer"]
            }
            
            domains.append(domain_entry)
            added_count += 1
        except Exception as e:
            logger.error(f"Error processing domain {clean_domain}: {e}")
            continue

    if added_count > 0:
        save_domains(domains, username)
    
    return jsonify({"message": f"Successfully added {added_count} domains."}), 200

@app.route('/api/update_schedule', methods=['POST'])
def update_schedule():
    """Update the search frequency or schedule."""
    data = request.get_json()
    frequency_type = data.get("frequency_type")
    value = data.get("value")
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username is required."}), 400

    try:
        # Remove existing job if it exists
        job_id = f"{SEARCH_JOB_ID}_{username}"
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
            logger.info(f"Removed existing job for user: {username}")

        # Create user-specific search function
        user_search_func = create_user_search_job(username)

        # Add new job based on the schedule type
        if frequency_type == "interval":
            interval_seconds = max(int(value), 3600)  # Minimum interval: 1 hour
            scheduler.add_job(
                id=job_id,
                func=user_search_func,
                trigger="interval",
                seconds=interval_seconds,
            )
            logger.info(f"Created interval job for user {username} with {interval_seconds}s interval")
        elif frequency_type == "time":
            schedule_time = datetime.strptime(value, "%H:%M").time()
            scheduler.add_job(
                id=job_id,
                func=user_search_func,
                trigger="cron",
                hour=schedule_time.hour,
                minute=schedule_time.minute,
            )
            logger.info(f"Created cron job for user {username} at {schedule_time}")

        return jsonify({"message": "Schedule updated successfully"}), 200
    except Exception as e:
        logger.error(f"Failed to update schedule for user {username}: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logger.info(f"Starting BE application: {APP_NAME}")
    app.run(debug=True, port=5001, host='0.0.0.0')