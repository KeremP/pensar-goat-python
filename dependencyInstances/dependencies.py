import sqlite3
import yaml  # Vulnerable to arbitrary code execution
import flask  # Vulnerable Flask version
import requests  # Vulnerable requests version
import paramiko  # Vulnerable to RCE in older versions
import lxml.etree as ET  # Vulnerable to XXE attacks
from urllib.parse import urlparse
import ipaddress

app = flask.Flask(__name__)

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
    """Secure against SQL Injection using parameterized queries"""
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
    """XSS protection added"""
    user_input = flask.request.args.get("name", "")
    return f"<h1>Welcome, {escape(user_input)}!</h1>"  # Sanitized user input

# ======== 3. Arbitrary Code Execution via YAML ========
def load_config():
    """Vulnerable to Arbitrary Code Execution"""
    with open("config.yaml", "r") as file:
        data = yaml.safe_load(file)  # Using safe yaml.safe_load()
    return data


# ======== 4. External XML Entity (XXE) Attack ========
@app.route("/upload_xml", methods=["POST"])
def upload_xml():
    """Previously vulnerable to XXE, now secure"""
    xml_data = flask.request.data
    parser = ET.XMLParser(resolve_entities=False)  # Disable external entity resolution
    tree = ET.fromstring(xml_data, parser)
    return ET.tostring(tree)
    tree = ET.fromstring(xml_data, parser)
    return ET.tostring(tree)


# Function to validate URLs and prevent SSRF
def is_valid_url(url):
    """Validate URL to prevent SSRF attacks."""
    try:
        # Check if URL is properly formatted
        parsed = urlparse(url)
        
        # Ensure scheme is http or https
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Check if hostname is provided
        if not parsed.netloc:
            return False
            
        hostname = parsed.hostname

        # Prevent localhost and private IPs
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
                return False
        except ValueError:
            # Not an IP address, continue with other checks
            pass
            
        # Domain allowlist - uncomment and customize based on application needs
        # allowed_domains = ['api.example.com', 'data.example.org', 'trusted-source.com']
        # if not any(hostname == domain or hostname.endswith('.' + domain) for domain in allowed_domains):
        #     return False
            
        return True
    except Exception:
        return False


# ======== 5. Insecure Request Handling ========
@app.route("/fetch")
def fetch():
    """SECURE: Fetch content from external URLs and safely return as plain text"""
    url = flask.request.args.get("url")
    
    if not url or not is_valid_url(url):
        return "Invalid or disallowed URL", 400

    try:
        response = requests.get(url, allow_redirects=True, timeout=5, stream=True)
        # Only allow 'safe' content-types, e.g. plain text or JSON, never serve as HTML
        content_type = response.headers.get('Content-Type', '').split(';')[0].strip()
        allowed_types = [
            'text/plain',
            'application/json',
            'application/octet-stream',
        ]
        if content_type not in allowed_types:
            # Always serve response as plain text to the client, never as HTML
            # Redact dangerous types (like text/html, application/xhtml+xml, image/svg+xml, etc.)
            safe_content_type = 'text/plain'
        else:
            safe_content_type = content_type

        # Stream response to prevent DoS via giant files
        def generate():
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk

        # Always force download for binary types, otherwise return as plain text
        if safe_content_type == 'application/octet-stream':
            headers = {
                'Content-Type': safe_content_type,
                'Content-Disposition': 'attachment; filename="downloaded_content"'
            }
            return flask.Response(generate(), headers=headers)
        else:
            headers = {'Content-Type': safe_content_type}
            return flask.Response(generate(), headers=headers)
    except requests.RequestException:
        return "Error fetching URL", 400


# ======== 6. Remote Code Execution via Paramiko ========
def run_ssh_command():
    ssh = paramiko.SSHClient()
    # Load system host keys
    ssh.load_system_host_keys()
    # Set policy to reject unknown host keys
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    
    return stdout.read()
    return stdout.read()


if __name__ == "__main__":
    app.run(debug=True)
    finally:
        ssh.close()


if __name__ == "__main__":
    app.run(debug=True)
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)