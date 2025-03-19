from locust import HttpUser, task, between
import uuid
import time
import random
import string
import io

class MyUser(HttpUser):
    wait_time = between(1, 5)
    auth_token = None
    username = None
    password = "password123"  # Define a fixed password

    def on_start(self):
        """Register and then log in the user."""
        if not self.auth_token:
            # Only register and log in if there is no auth token
            self.register_user()
            self.login()

    def register_user(self):
        """Register a new user and return the username."""
        self.username = f"user_{uuid.uuid4().hex[:8]}"  # Generate a unique username
        payload = {"username": self.username, "password": self.password}
        headers = {"Content-Type": "application/json"}  # Add headers if required
        response = self.client.post("/register", json=payload, headers=headers)

        print(f"Attempting to register user with payload: {payload}")
        print(f"Response status: {response.status_code}, Response text: {response.text}")

        if response.status_code == 201:  # Assuming 201 means user creation success
            print(f"User registration successful: {self.username}")
        else:
            print(f"User registration failed: {response.status_code}, {response.text}")
            raise Exception("User registration failed")

    def login(self):
        """Login and store the authentication token."""
        payload = {"username": self.username, "password": self.password}
        headers = {"Content-Type": "application/json"}  # Ensure correct headers are added
        print(f"Attempting login with payload: {payload}")
        
        response = self.client.post("/login", json=payload, headers=headers)

        # Log full response content for debugging
        print(f"Response status: {response.status_code}, Response text: {response.text}")
        print(f"Response headers: {response.headers}")

        if response.status_code == 200:
            self.auth_token = response.json().get("token")
            print(f"Login successful. Token: {self.auth_token}")
        else:
            print(f"Login failed: {response.status_code}, {response.text}")
            if response.status_code == 500:
                print("Server error details:", response.text)  # Add more error details if available
            raise Exception("Authentication failed")

    def post_request(self, endpoint, payload, success_status=(200, 201)):
        """Helper for POST requests with authentication."""
        headers = {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        response = self.client.post(endpoint, json=payload, headers=headers)
        print(f"POST to {endpoint} with payload: {payload}, Response: {response.status_code}, {response.text}")
        
        # Check for 400 error and print detailed information
        if response.status_code == 400:
            print(f"Bad Request details: {response.text}")  # Log details for debugging
        return response

    def get_request(self, endpoint, success_status=200):
        """Helper for GET requests with assertions and debug logs."""
        headers = {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        response = self.client.get(endpoint, headers=headers)
        if response.status_code != success_status:
            print(f"GET {endpoint} failed: {response.status_code}, {response.text}")
        assert response.status_code == success_status, f"GET {endpoint} failed: {response.status_code}, {response.text}"
        return response

    @task(3)
    def homepage(self):
        self.get_request("/")  # Load the homepage

    @task(2)
    def register_page(self):
        time.sleep(3)
        self.register_user()  # Register a new user first
        time.sleep(3)
        self.login()  # Then log in with the same user

    @task(1)
    def dashboard_page(self):
        self.get_request("/dashboard")  # Load the dashboard page

    @task(2)
    def domain_add_page(self):
        self.get_request("/add_domain_page")
        for i in range(10):
            payload = {"domain": f"domain{i}.com"}  # Payload for adding domain
            self.post_request("/add_domain", payload)  # Try adding domain

    @task(1)
    def add_domain_file_page(self):
        """Upload a file containing domains."""
        # First visit the domain files page with proper path
        self.get_request("/domain_files")  # This matches the Flask route exactly
        
        # Generate random domains
        domains = [f"domain{i}.com" for i in range(1, 101)]
        domain_content = '\n'.join(domains)
        
        # Create file-like object
        temp_file = io.BytesIO(domain_content.encode('utf-8'))
        
        # Prepare the multipart form-data
        files = {
            'file': ('domains.txt', temp_file, 'text/plain')
        }
        
        # Prepare headers with authentication
        headers = {}
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        
        try:
            # Send the file upload request
            response = self.client.post(
                "/upload_domains",
                files=files,
                headers=headers
            )
            
            print(f"File upload response status: {response.status_code}")
            if response.status_code != 200:
                print(f"Upload failed with status {response.status_code}: {response.text}")
            else:
                print("Upload successful")
                
        except Exception as e:
            print(f"Error uploading file: {e}")
        finally:
            temp_file.close()
