import sqlite3
import yaml  # Vulnerable to arbitrary code execution
import flask  # Vulnerable Flask version
import requests  # Vulnerable requests version
import paramiko  # Vulnerable to RCE in older versions
import lxml.etree as ET  # Vulnerable to XXE attacks
import re
from urllib.parse import urlparse

app = flask.Flask(__name__)

# ======== 1. SQL Injection Vulnerability ========
# ======== 1. SQL Injection Vulnerability ========
# ======== 1. SQL Injection Vulnerability ========
# ======== 1. SQL Injection Vulnerability ========
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
cursor.execute(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
)
cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
conn.commit()


@app.route("/login")
def login():
    """Fixed SQL Injection vulnerability using parameterized queries"""
    username = flask.request.args.get("username")
    password = flask.request.args.get("password")

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
    """Secure YAML loading"""
    with open("config.yaml", "r") as file:
        data = yaml.safe_load(file)  # Using safe_load instead of unsafe yaml.load()
    return data


# ======== 4. External XML Entity (XXE) Attack ========


# ======== 4. External XML Entity (XXE) Attack ========
@app.route("/upload_xml", methods=["POST"])
def upload_xml():
    """Secured against XXE"""
    xml_data = flask.request.data
    parser = ET.XMLParser(resolve_entities=False)  # XXE disabled
    tree = ET.fromstring(xml_data, parser)
    return ET.tostring(tree)

# ======== 5. Insecure Request Handling ========
@app.route("/fetch")
def fetch():
    """Secured against credential leakage in redirects"""
    url = flask.request.args.get("url")
    
    # Validate the URL to prevent SSRF and accessing internal resources
    if not url:
        return "URL parameter is required", 400
    
    # Parse the URL to validate it
    try:
        parsed_url = urlparse(url)
        
        # Check if URL scheme is http or https (no file:// or other protocols)
        if parsed_url.scheme not in ['http', 'https']:
            return "Access to internal networks is not allowed", 403
        
        # Disable redirects to prevent unintended access to sensitive endpoints
        response = requests.get(url, allow_redirects=False, timeout=10)
        
        # Check if there was a redirect and inform the user
        if response.status_code in [301, 302, 303, 307, 308]:
            return "Request resulted in a redirect which was not followed for security reasons.", 200
        
        return response.text
    
    except requests.exceptions.RequestException as e:
        return f"Error fetching URL: {str(e)}", 400


# ======== 6. Remote Code Execution via Paramiko ========
def run_ssh_command():
    """Execute a command via SSH with proper host key verification
    
    Args:
        hostname (str): SSH server hostname or IP
        username (str): SSH username
        password (str): SSH password
        command (str): Command to execute on the server
        
    Raises:
        ValueError: If parameters are invalid
        paramiko.SSHException: If SSH connection fails
    """
    if not hostname or not username:
        raise ValueError("Hostname and username are required")
    
    # Basic command validation
    if not isinstance(command, str) or any(c in command for c in [';', '&', '|', '`']):
        raise ValueError("Invalid command format")
    
    ssh = paramiko.SSHClient()
    
    # Load system host keys
    ssh.load_system_host_keys()
    
    if auto_add_key:
        # This is insecure but sometimes needed in trusted environments
        print("WARNING: Automatically adding unknown host keys. This is insecure!")
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        # Use RejectPolicy which will reject connections to unknown servers
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    
    try:
        ssh.connect(hostname, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        return stdout.read()
    finally:
        ssh.close()


if __name__ == "__main__":
    app.run(debug=False)