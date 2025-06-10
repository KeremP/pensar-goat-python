import sqlite3
import yaml  # Vulnerable to arbitrary code execution
import flask  # Vulnerable Flask version
import requests  # Vulnerable requests version
import paramiko  # Vulnerable to RCE in older versions
import lxml.etree as ET  # Vulnerable to XXE attacks
from urllib.parse import urlparse  # Added for URL validation

app = flask.Flask(__name__)

# Define allowed domains for the fetch function
ALLOWED_DOMAINS = ['api.example.com', 'data.example.org', 'public-api.com']

# ======== 1. SQL Injection Vulnerability ========
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
cursor.execute(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
)
cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")


@app.route("/login")
def login():
    """Fixed SQL Injection vulnerability by using parameterized query"""
    username = flask.request.args.get("username")
    password = flask.request.args.get("password")

    # Use parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()

    if user:
        return f"Welcome {user[1]}!"
    return "Invalid credentials."


# ======== 2. XSS Vulnerability ========
@app.route("/")
def home():
    """Vulnerable to XSS"""
    user_input = flask.request.args.get("name", "")
# ======== 3. Arbitrary Code Execution via YAML ========
def load_config():
    """Vulnerable to Arbitrary Code Execution"""
    with open("config.yaml", "r") as file:
        data = yaml.safe_load(file)  # Using safe yaml.safe_load()
    return data


# ======== 4. External XML Entity (XXE) Attack ========
    """Loads configuration safely"""
    with open("config.yaml", "r") as file:
        data = yaml.safe_load(file)  # Using safe YAML loading
    return data


# ======== 4. External XML Entity (XXE) Attack ========
@app.route("/upload_xml", methods=["POST"])
def upload_xml():
    """Protected against XXE"""
    xml_data = flask.request.data
    parser = ET.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)  # XXE disabled

# ======== 5. Insecure Request Handling ========
@app.route("/fetch")
def fetch():
    """Protected against SSRF attacks"""
    url = flask.request.args.get("url")

    # Validate URL
    if not url or not isinstance(url, str):
        return "Invalid URL", 400

    # Parse the URL to validate protocol and domain
    try:
        parsed_url = urlparse(url)

        # Ensure the scheme is http or https
        if parsed_url.scheme not in ("http", "https"):
            return "Invalid URL scheme. Only http and https are allowed.", 400

        # Ensure the domain is whitelisted
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return f"Domain not in whitelist. Allowed domains: {', '.join(ALLOWED_DOMAINS)}", 403

        # Make the request with redirects disabled
        response = requests.get(url, allow_redirects=False)

        # Check if the response is a redirect
        if response.status_code in [301, 302, 303, 307, 308]:
            return "Redirects are not allowed", 403

        return response.text
    except Exception as e:
        return f"Error processing URL: {str(e)}", 400


# ======== 6. Remote Code Execution via Paramiko ========
def run_ssh_command():

# ======== 6. Remote Code Execution via Paramiko ========
def run_ssh_command():
    """Connects to an SSH server with proper host key verification."""
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()  # Load system host keys
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())  # Reject unknown servers
    return stdout.read()


if __name__ == "__main__":
    app.run(debug=True)