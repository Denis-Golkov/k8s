import logging
import logging.handlers
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import yaml
import requests


# --- Load Configuration ---
with open('fe_config.yaml', 'r') as f:
    config = yaml.safe_load(f)

APP_NAME = config['app_name']
LOG_DIRECTORY = config['log_directory']
SECRET_KEY = config['secret_key']

if os.getenv('ENVIRONMENT') == 'prod':
    BACKEND_URL = os.getenv('BACKEND_URL')
else:
    BACKEND_URL = config['backend_url']




# --- Setup Logging ---


os.makedirs(LOG_DIRECTORY, exist_ok=True)
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.DEBUG)

file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIRECTORY, 'fe_app.log'),
    maxBytes=10*1024*1024,
    backupCount=5
)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# --- Flask App ---
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.logger = logger

# --- Routes ---
@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        response = requests.post(f"{BACKEND_URL}/api/login", json=data)
        if response.status_code == 200:
            session["user"] = data.get("username")
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.exception(f"Login error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        response = requests.post(f"{BACKEND_URL}/api/register", json=data)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.exception(f"Registration error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('home'))
    return render_template('domain.html', username=session['user'])

@app.route('/get_domains', methods=['GET'])
def get_domains():
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/domains",
            params={"username": session.get("user")}
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.exception(f"Error getting domains: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/add_domain', methods=['POST'])
def add_domain():
    try:
        data = request.get_json()
        data["username"] = session.get("user")
        response = requests.post(f"{BACKEND_URL}/api/domains", json=data)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.exception(f"Error adding domain: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/add_domain_page')
def add_domain_page():
    if 'user' not in session:
        return redirect(url_for('home'))
    return render_template('add_domain.html', username=session['user'])

@app.route('/domain_files')
def domain_files():
    if 'user' not in session:
        return redirect(url_for('home'))
    return render_template('domain_files.html', username=session['user'])

@app.route('/remove_domain', methods=['POST'])
def remove_domain():
    try:
        data = request.get_json()
        data["username"] = session.get("user")
        response = requests.delete(f"{BACKEND_URL}/api/domains", json=data)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.exception(f"Error removing domain: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/upload_domains', methods=['POST'])
def upload_domains():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided."}), 400
            
        file = request.files['file']
        if not file.filename.endswith('.txt'):
            return jsonify({"error": "Please upload a .txt file."}), 400

        # Read file content and send to backend
        file_content = file.stream.read().decode('utf-8')
        data = {
            "domains": file_content.splitlines(),
            "username": session.get("user")
        }
        
        response = requests.post(f"{BACKEND_URL}/api/upload_domains", json=data)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.exception(f"Error uploading domains: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/update_schedule', methods=['POST'])
def update_schedule():
    try:
        data = request.get_json()
        data["username"] = session.get("user")
        response = requests.post(f"{BACKEND_URL}/api/update_schedule", json=data)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.exception(f"Error updating schedule: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logger.info(f"Starting FE application: {APP_NAME}")
    app.run(debug=True, port=8081, host='0.0.0.0')