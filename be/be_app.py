import logging
import logging.handlers
import os
from flask import Flask, request, jsonify
import ssl
import socket
import yaml
from flask_apscheduler import APScheduler
from datetime import datetime
import requests
from urllib.parse import urlparse
# from elasticapm.contrib.flask import ElasticAPM
import psycopg2
import yaml
import os



# Load configuration
if  os.getenv('ENVIRONMENT') == 'prod':
    dbuser = os.getenv('DB_USER')
    dbhost = os.getenv('DB_HOST')
    dbport = os.getenv('DB_PORT')
    dbpassword = os.getenv('DB_PASSWORD')
    dbname = os.getenv('DB_NAME')
else:
    with open('configuration.yaml', 'r') as f:
        config = yaml.safe_load(f)
    config = config['dev']
    dbuser = config['db']['user']
    dbhost = config['db']['host']
    dbport = config['db']['port']
    dbpassword = config['db']['password']
    dbname = config['db']['dbname']

class TPPDb():
    def __init__(self):
        DB_PARAMS = {
            'dbname': dbname,
            'user': dbuser,
            'password': dbpassword,
            'host': dbhost,
            'port': dbport,
        }
        self.conn = psycopg2.connect(**DB_PARAMS)

    def add_user(self, username, password):
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO users (user_name, password) VALUES (%s, %s);", (username, password))
            self.conn.commit()

    def user_exists(self, username):
        with self.conn.cursor() as cur:
            cur.execute("SELECT user_id FROM users WHERE user_name = %s", (username,))
            return cur.fetchone() is not None

    def add_domain(self, domain, status, ssl_expiration, ssl_issuer):
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO domains (domain, status, ssl_expiration, ssl_issuer) VALUES (%s, %s, %s, %s) RETURNING domain_id;", 
                      (domain, status, ssl_expiration, ssl_issuer))
            domain_id = cur.fetchone()[0]
            self.conn.commit()
            return domain_id

    def domain_exists(self, domain):
        with self.conn.cursor() as cur:
            cur.execute("SELECT domain_id FROM domains WHERE domain = %s", (domain,))
            return cur.fetchone() is not None

    def get_domain_id(self, domain):
        with self.conn.cursor() as cur:
            cur.execute("SELECT domain_id FROM domains WHERE domain = %s", (domain,))
            result = cur.fetchone()
            return result[0] if result else None

    def get_user_id(self, username):
        with self.conn.cursor() as cur:
            cur.execute("SELECT user_id FROM users WHERE user_name = %s", (username,))
            result = cur.fetchone()
            return result[0] if result else None

    def relation(self, username, domain):
        user_id = self.get_user_id(username)
        domain_id = self.get_domain_id(domain)
        
        if not user_id:
            raise ValueError(f"User '{username}' not found")
        if not domain_id:
            raise ValueError(f"Domain '{domain}' not found")
            
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO relation (user_id, domain_id) VALUES (%s, %s)", 
                      (user_id, domain_id))
            self.conn.commit()

    def add_multiple_domains_to_user(self, username, domains_list):
        """
        Associate multiple domains with a single user
        
        Parameters:
        - username (str): Username to associate domains with
        - domains_list (list): List of domain names to associate with the user
        """
        user_id = self.get_user_id(username)
        if not user_id:
            raise ValueError(f"User '{username}' not found")
            
        with self.conn.cursor() as cur:
            for domain in domains_list:
                domain_id = self.get_domain_id(domain)
                if not domain_id:
                    continue
                
                # Check if relation already exists
                cur.execute("SELECT 1 FROM relation WHERE user_id = %s AND domain_id = %s", 
                          (user_id, domain_id))
                if cur.fetchone() is None:  # Only insert if relation doesn't exist
                    cur.execute("INSERT INTO relation (user_id, domain_id) VALUES (%s, %s)", 
                              (user_id, domain_id))
            
            self.conn.commit()

    def login(self, username):
        with self.conn.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE user_name = %s", (username,))
            db_password = cur.fetchone()
            if db_password is None:
                return None
            return db_password[0]
    
    def get_user_domains(self, username):
        user_id = self.get_user_id(username)
        if not user_id:
            return []
            
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT d.domain, d.status, d.ssl_expiration, d.ssl_issuer 
                FROM domains d
                JOIN relation r ON d.domain_id = r.domain_id
                WHERE r.user_id = %s
            """, (user_id,))
            
            domains = []
            for row in cur.fetchall():
                domains.append({
                    "domain": row[0],
                    "status": row[1],
                    "ssl_expiration": row[2],
                    "ssl_issuer": row[3]
                })
            return domains
    
    def update_domain(self, domain, status, ssl_expiration, ssl_issuer):
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE domains 
                SET status = %s, ssl_expiration = %s, ssl_issuer = %s
                WHERE domain = %s
            """, (status, ssl_expiration, ssl_issuer, domain))
            self.conn.commit()
    
    def delete_domain_relation(self, username, domain):
        user_id = self.get_user_id(username)
        domain_id = self.get_domain_id(domain)
        
        if not user_id or not domain_id:
            return False
            
        with self.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM relation
                WHERE user_id = %s AND domain_id = %s
            """, (user_id, domain_id))
            rows_deleted = cur.rowcount
            self.conn.commit()
            return rows_deleted > 0


# Initialize database connection
tpp_db_obj = TPPDb()

# --- Load Configuration ---
with open('be_config.yaml', 'r') as f:
    config = yaml.safe_load(f)

APP_NAME = config['app_name']
LOG_DIRECTORY = config['log_directory']

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

# app.config['ELASTIC_APM'] = {
#   'SERVICE_NAME': 'test',
#   'API_KEY': 'Qm9MV0Q1VUJSQXhxN0pZbVZfcVM6MzFIcWhFYW9DS3o1QWlTLUR1X0U4UQ==',
#   'SERVER_URL': 'https://test-fcd1e6.apm.us-east-1.aws.elastic.cloud:443',
#   'ENVIRONMENT': 'test',
#   'DEBUG': True
# }
# apm = ElasticAPM(app)

# Initialize APScheduler
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

SEARCH_JOB_ID = "search_domains"
DEFAULT_INTERVAL = 3600  # 1 hour in seconds

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
        domains = tpp_db_obj.get_user_domains(username)
        
        for domain_data in domains:
            try:
                domain = domain_data["domain"]
                status = check_domain_status(domain)
                ssl_info = get_ssl_info(domain)
                
                # Update domain in database
                tpp_db_obj.update_domain(
                    domain, 
                    status,
                    ssl_info["ssl_expiration"],
                    ssl_info["ssl_issuer"]
                )
            except Exception as e:
                logger.error(f"Error checking domain {domain}: {e}")
        
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
    if db_password is None:
        return jsonify({"message": "Invalid username or password!"}), 401
        
    if db_password == password:
        return jsonify({"message": "Login successful!"}), 200
    
    return jsonify({"message": "Invalid username or password!"}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    if tpp_db_obj.user_exists(username):
        return jsonify({"message": "Username already exists!"}), 409
    
    tpp_db_obj.add_user(username, password)
    return jsonify({"message": "Registration successful!"}), 201

@app.route('/api/domains', methods=['GET'])
def get_domains():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Username is required"}), 400
        
    domains = tpp_db_obj.get_user_domains(username)
    return jsonify(domains)

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

    # Check if domain already exists for this user
    existing_domains = tpp_db_obj.get_user_domains(username)
    if any(d["domain"] == clean_domain for d in existing_domains):
        return jsonify({"error": "Domain already exists for this user."}), 400

    try:
        status = check_domain_status(clean_domain)
        ssl_info = get_ssl_info(clean_domain)
        
        domain_entry = {
            "domain": clean_domain,
            "status": status,
            "ssl_expiration": ssl_info["ssl_expiration"],
            "ssl_issuer": ssl_info["ssl_issuer"]
        }
        
        # Add domain if it doesn't exist yet
        if not tpp_db_obj.domain_exists(clean_domain):
            tpp_db_obj.add_domain(clean_domain, status, ssl_info["ssl_expiration"], ssl_info["ssl_issuer"])
        
        # Create relation between user and domain
        tpp_db_obj.relation(username, clean_domain)
        
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

    if tpp_db_obj.delete_domain_relation(username, domain):
        return jsonify({"message": f"Domain {domain} removed successfully."})
    else:
        return jsonify({"error": "Domain not found."}), 404

@app.route('/api/upload_domains', methods=['POST'])
def upload_domains():
    data = request.get_json()
    domains_list = data.get("domains", [])
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username is required."}), 400

    # Get existing domains for user to avoid duplicates
    existing_domains = tpp_db_obj.get_user_domains(username)
    existing_domain_names = [d["domain"] for d in existing_domains]
    
    added_domains = []
    added_count = 0

    for domain in domains_list:
        domain = domain.strip()
        if not domain:
            continue

        # Clean domain
        parsed_url = urlparse(domain)
        clean_domain = parsed_url.netloc or parsed_url.path
        clean_domain = clean_domain.lstrip("www.")

        # Skip if domain already exists for this user
        if clean_domain in existing_domain_names:
            continue

        try:
            status = check_domain_status(clean_domain)
            ssl_info = get_ssl_info(clean_domain)
            
            # Add domain if it doesn't exist yet
            if not tpp_db_obj.domain_exists(clean_domain):
                tpp_db_obj.add_domain(clean_domain, status, ssl_info["ssl_expiration"], ssl_info["ssl_issuer"])
            
            added_domains.append(clean_domain)
            added_count += 1
        except Exception as e:
            logger.error(f"Error processing domain {clean_domain}: {e}")
            continue

    if added_count > 0:
        # Associate all added domains with the user
        tpp_db_obj.add_multiple_domains_to_user(username, added_domains)
    
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