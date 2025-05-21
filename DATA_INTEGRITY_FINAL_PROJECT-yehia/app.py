from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, send_file, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_session import Session
from werkzeug.utils import secure_filename
import os
import io
import pyotp
import qrcode
from datetime import datetime, timedelta
import traceback
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import re

from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github

from crypto_utils import encrypt_file, decrypt_file, hash_file
from error_handlers import init_error_handlers

# Add imports for cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Session Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'securedocs-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Sessions last 7 days
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

# Initialize Session
Session(app)

# Initialize error handlers
init_error_handlers(app)

# Configure logging to a file
log_file_path = os.path.join(app.root_path, 'application.log')
file_handler = RotatingFileHandler(log_file_path, maxBytes=10240, backupCount=10, delay=True)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)

# Remove any existing handlers to prevent duplicates
for handler in app.logger.handlers[:]:
    app.logger.removeHandler(handler)

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Add a stream handler for console output
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
console_handler.setLevel(logging.INFO)
app.logger.addHandler(console_handler)

# Disable werkzeug's default logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# MySQL config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'securedocs_db')

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Create necessary directories
os.makedirs(os.path.join(os.getcwd(), 'flask_session'), exist_ok=True)
os.makedirs(os.getenv('UPLOAD_FOLDER', 'uploads'), exist_ok=True)

# File upload config
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# OAuth Blueprints
google_bp = make_google_blueprint(
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    redirect_to="google_login",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
)
app.register_blueprint(google_bp, url_prefix="/login")

github_bp = make_github_blueprint(
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    redirect_to="github_login",
    scope="user:email"
)
app.register_blueprint(github_bp, url_prefix="/login")

def is_logged_in():
    """Check if user is logged in and session is valid"""
    return 'username' in session and 'role' in session

def login_required(f):
    """Decorator to require login for routes"""
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for routes"""
    def decorated_function(*args, **kwargs):
        if not is_logged_in() or session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.before_request
def before_request():
    """Run before each request to check session validity"""
    # If the logging out flag is set, briefly bypass the full session check
    if session.pop('_logging_out', False):
        # This request is likely part of the logout sequence or immediate redirect
        return # Allow the request to proceed without full session check

    # List of endpoints that should NOT trigger the session check
    # These are typically login, registration, and OAuth callback endpoints
    allowed_endpoints = [
        'login', 'register', 'qr_page', 'show_qr', 'two_factor',
        'google.login', 'google.authorized', 'github.login', 'github.authorized',
        'google_login', # Add exemption for the google_login route
        'static' # Allow access to static files (CSS, JS, images)
    ]

    # Check if the requested endpoint is one of the allowed endpoints
    if request.endpoint in allowed_endpoints or request.endpoint is None:
        # If endpoint is None, it might be the favicon or other non-routed request
        return # Allow the request to proceed without session check

    # Now perform the session validity check only for other endpoints
    if 'username' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        if not cur.fetchone():
            session.clear() # Clear the whole session if user not found in DB
            flash('Your session has expired. Please log in again', 'warning')
            return redirect(url_for('login'))
        cur.close()
    # If 'username' is not in session, login_required decorator will handle redirection for protected routes

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        # Server-side validation
        if not username or not email or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            log_action(username, 'register_failed', 'Registration failed: Missing fields.')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            log_action(username, 'register_failed', 'Registration failed: Passwords do not match.')
            return redirect(url_for('register'))

        # Basic format validation (can be enhanced with regex if needed)
        if len(username) < 3 or len(username) > 20 or not re.match("^[a-zA-Z0-9_-]+$", username):
             flash('Invalid username format.', 'danger')
             log_action(username, 'register_failed', 'Registration failed: Invalid username format.')
             return redirect(url_for('register'))

        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
             flash('Invalid email format.', 'danger')
             log_action(username, 'register_failed', 'Registration failed: Invalid email format.')
             return redirect(url_for('register'))

        if len(password) < 8 or not re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password):
             flash('Invalid password format.', 'danger')
             log_action(username, 'register_failed', 'Registration failed: Invalid password format.')
             return redirect(url_for('register'))

        cur = mysql.connection.cursor()
        try:
            # Check if username or email already exists
            cur.execute("SELECT COUNT(*) FROM users WHERE username = %s OR email = %s", (username, email,))
            if cur.fetchone()[0] > 0:
                flash('Username or email already exists.', 'danger')
                log_action(username, 'register_failed', 'Registration failed: Username or email already exists.')
                return redirect(url_for('register'))

            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            totp_secret = pyotp.random_base32()

            cur.execute("""
                INSERT INTO users (username, email, password, 2fa_secret)
                VALUES (%s, %s, %s, %s)
            """, (username, email, hashed_pw, totp_secret))
            mysql.connection.commit()
            cur.close()

            log_action(username, 'register_success', 'User registered successfully.')
            flash('Registration successful! Please set up your two-factor authentication.', 'success')

            # Redirect to QR page
            app.logger.info(f"Redirecting registered user {username} to QR page.")
            return redirect(url_for('qr_page', username=username))

        except Exception as e:
            mysql.connection.rollback()
            app.logger.error(f"Database error during registration for user {username}: {e}\\n{traceback.format_exc()}")
            log_action(username, 'register_error', f'Database error during registration: {e}')
            flash('An error occurred during registration. Please try again.', 'danger')
            cur.close()
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/qr/<username>')
def qr_page(username):
    app.logger.info(f"Accessing QR page for user: {username}")
    # You might want to add a check here to ensure the username exists and is the user who just registered
    # This prevents arbitrary access to the QR page
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    if not user:
        app.logger.warning(f"QR page accessed for non-existent or invalid user: {username}")
        flash('Invalid user or page access.', 'danger')
        return redirect(url_for('register')) # Or login page

    return render_template('qr_page.html', username=username)

@app.route('/qrcode/<username>')
def show_qr(username):
    app.logger.info(f"Generating QR code for user: {username}")
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT 2fa_secret FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()

        if not result:
            app.logger.error(f"2FA secret not found for user {username} during QR generation.")
            log_action(username, 'qr_code_failed', f'2FA secret not found for user {username}.')
            return "Error generating QR code: User not found or secret missing.", 404

        secret = result[0]

        totp = pyotp.TOTP(secret)
        otp_uri = totp.provisioning_uri(name=username, issuer_name="SecureDocs")
        app.logger.info(f"Generated TOTP URI for {username}: {otp_uri}")

        img = qrcode.make(otp_uri)

        buf = io.BytesIO()
        img.save(buf, 'PNG') # Specify format explicitly
        buf.seek(0)

        log_action(username, 'qr_code_success', f'Generated QR code for 2FA for user {username}')
        app.logger.info(f"Successfully generated and sending QR code image for user {username}.")

        return send_file(buf, mimetype='image/png')

    except Exception as e:
        app.logger.error(f"Error generating or serving QR code for user {username}: {e}\\n{traceback.format_exc()}")
        log_action(username, 'qr_code_error', f'Error generating or serving QR code: {e}')
        cur.close() # Ensure cursor is closed even on error
        return "An error occurred while generating the QR code.", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session['pre_2fa_user'] = user[1]
            # Log successful password verification, pending 2FA
            log_action(username, 'login_manual_password_success', f'Password verified for user {username}. Proceeding to 2FA.')
            return redirect(url_for('two_factor'))
        
        # Log failed login attempt
        log_action(username, 'login_manual_failed', f'Failed login attempt for user {username}')
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form['token']
        username = session['pre_2fa_user']

        cur = mysql.connection.cursor()
        cur.execute("SELECT 2fa_secret, role FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()

        if not result:
            session.clear()
            flash('User not found', 'danger')
            return redirect(url_for('login'))

        secret, role = result
        totp = pyotp.TOTP(secret)

        if totp.verify(token):
            session.pop('pre_2fa_user')
            session['username'] = username
            session['role'] = role
            session.permanent = True  # Make session permanent
            log_action(username, 'login_manual_2fa_success', f'User {username} successfully completed 2FA and logged in manually.')
            flash('Successfully logged in', 'success')
            return redirect(url_for('home'))
        else:
            # Log failed 2FA attempt
            log_action(username, 'login_manual_2fa_failed', f'User {username} failed 2FA. Invalid code.')
            flash('Invalid 2FA code. Please try again.', 'danger')
            return render_template('2fa.html')

    return render_template('2fa.html')

@app.route('/google-login')
def google_login():
    # If the user is already logged in, redirect them
    if is_logged_in():
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    # Log initiation of Google login
    log_action(session.get('username', 'anonymous'), 'login_google_initiate', 'Initiated Google login process')
    return redirect(url_for("google.login")) # This redirects to the Google OAuth flow

@app.route('/login/google/authorized')
def google_authorized():
    if not google.authorized:
        # Log failed Google login
        log_action(session.get('username', 'anonymous'), 'login_google_failed', 'Google login failed or was denied')
        flash('Google login failed.', 'danger')
        return redirect(url_for('login'))

    try:
        resp = google.get("/oauth2/v2/userinfo")
        resp.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        user_info = resp.json()
        google_id = user_info['id']
        email = user_info.get('email')
        username = user_info.get('name', email)

        cur = mysql.connection.cursor()

        # Check if user exists by Google ID
        cur.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
        user = cur.fetchone()

        if user:
            # User exists, log them in
            session['username'] = user[1] # username
            session['role'] = user[5] # Assuming role is at index 5
            session.permanent = True
            log_action(session['username'], 'login_google_success', f'User {session["username"]} logged in successfully with Google.')
            flash('Successfully logged in with Google', 'success')
        else:
            # New user, register them
            # Check if email already exists for a non-Google user
            cur.execute("SELECT * FROM users WHERE email = %s AND google_id IS NULL", (email,))
            existing_user_with_email = cur.fetchone()

            if existing_user_with_email:
                # Email exists but is not linked to Google, inform user
                flash('An account with this email already exists. Please log in with your existing method or link your Google account in profile settings.', 'warning')
                log_action(username or 'anonymous', 'login_google_failed_email_exists', f'Google login failed for email {email}. Email already registered.')
                return redirect(url_for('login'))

            # Generate a random password (not used for login, just to satisfy DB schema if password is NOT NULL)
            # and a 2FA secret (can be null for OAuth users or generated)
            import secrets
            random_password = secrets.token_urlsafe(16)
            totp_secret = None # Or generate one if 2FA is mandatory

            cur.execute("""
                INSERT INTO users (username, email, password, google_id, 2fa_secret, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, email, random_password, google_id, totp_secret, 'user'))
            mysql.connection.commit()
            
            session['username'] = username
            session['role'] = 'user'
            session.permanent = True
            log_action(username, 'register_google', f'New user {username} registered and logged in with Google.')
            flash('Successfully registered and logged in with Google', 'success')

        cur.close()
        return redirect(url_for('home'))

    except Exception as e:
        app.logger.error(f"Error during Google login: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        log_action(session.get('username', 'anonymous'), 'login_google_error', f'Error during Google login: {str(e)}')
        flash('An error occurred during Google login', 'danger')
        return redirect(url_for('login'))

@app.route('/github-login')
def github_login():
    # If the user is already logged in, redirect them
    if is_logged_in():
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    # Log initiation of GitHub login
    log_action(session.get('username', 'anonymous'), 'login_github_initiate', 'Initiated GitHub login process')
    return redirect(url_for("github.login")) # This redirects to the GitHub OAuth flow

@app.route('/login/github/authorized')
def github_authorized():
    if not github.authorized:
        # Log failed GitHub login
        log_action(session.get('username', 'anonymous'), 'login_github_failed', 'GitHub login failed or was denied')
        flash('GitHub login failed.', 'danger')
        return redirect(url_for('login'))

    try:
        resp = github.get("/user")
        resp.raise_for_status()
        github_user_info = resp.json()
        github_id = str(github_user_info['id'])
        username = github_user_info.get('login')
        email = github_user_info.get('email')

        cur = mysql.connection.cursor()

        # Check if user exists by GitHub ID
        cur.execute("SELECT * FROM users WHERE github_id = %s", (github_id,))
        user = cur.fetchone()

        if user:
            # User exists, log them in
            session['username'] = user[1] # username
            session['role'] = user[5] # Assuming role is at index 5
            session.permanent = True
            log_action(session['username'], 'login_github_success', f'User {session["username"]} logged in successfully with GitHub.')
            flash('Successfully logged in with GitHub', 'success')
        else:
             # New user, register them
            # Check if email already exists for a non-GitHub user
            if email:
                cur.execute("SELECT * FROM users WHERE email = %s AND github_id IS NULL", (email,))
                existing_user_with_email = cur.fetchone()

                if existing_user_with_email:
                    # Email exists but is not linked to GitHub, inform user
                    flash('An account with this email already exists. Please log in with your existing method or link your GitHub account in profile settings.', 'warning')
                    log_action(username or 'anonymous', 'login_github_failed_email_exists', f'GitHub login failed for email {email}. Email already registered.')
                    return redirect(url_for('login'))

            # Generate a random password and a 2FA secret (can be null for OAuth users)
            import secrets
            random_password = secrets.token_urlsafe(16)
            totp_secret = None # Or generate one if 2FA is mandatory

            cur.execute("""
                INSERT INTO users (username, email, password, github_id, 2fa_secret, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, email, random_password, github_id, totp_secret, 'user'))
            mysql.connection.commit()

            session['username'] = username
            session['role'] = 'user'
            session.permanent = True
            log_action(username, 'register_github', f'New user {username} registered and logged in with GitHub.')
            flash('Successfully registered and logged in with GitHub', 'success')

        cur.close()
        return redirect(url_for('home'))

    except Exception as e:
        app.logger.error(f"Error during GitHub login: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        log_action(session.get('username', 'anonymous'), 'login_github_error', f'Error during GitHub login: {str(e)}')
        flash('An error occurred during GitHub login', 'danger')
        return redirect(url_for('login'))

@app.route('/documents')
@login_required
def documents():
    try:
        # Get user_id and role from session
        username = session.get('username')
        role = session.get('role')

        if not username or not role:
            # This case should ideally be caught by @login_required, but as a fallback
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))

        cur = mysql.connection.cursor()

        # Get search, sort, and filter parameters
        search = request.args.get('search', '')
        sort = request.args.get('sort', 'newest')
        filter_type = request.args.get('filter', 'all')

        # Base query
        base_query = """
            SELECT d.*, u.username 
            FROM documents d 
            JOIN users u ON d.user_id = u.id 
        """

        # Add search condition if search term is provided
        search_condition = ""
        if search:
            search_condition = " WHERE d.original_filename LIKE %s"

        # Add user filter for non-admin users
        user_condition = ""
        if role != 'admin':
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                session.clear()
                flash('User not found. Please log in again.', 'danger')
                return redirect(url_for('login'))
            user_id = user[0]
            user_condition = " WHERE d.user_id = %s" if not search_condition else " AND d.user_id = %s"

        # Add date filter
        date_condition = ""
        if filter_type != 'all':
            if filter_type == 'today':
                date_condition = " AND DATE(d.upload_time) = CURDATE()"
            elif filter_type == 'week':
                date_condition = " AND YEARWEEK(d.upload_time) = YEARWEEK(CURDATE())"
            elif filter_type == 'month':
                date_condition = " AND MONTH(d.upload_time) = MONTH(CURDATE()) AND YEAR(d.upload_time) = YEAR(CURDATE())"

        # Add sorting
        sort_condition = ""
        if sort == 'newest':
            sort_condition = " ORDER BY d.upload_time DESC"
        elif sort == 'oldest':
            sort_condition = " ORDER BY d.upload_time ASC"
        elif sort == 'name_asc':
            sort_condition = " ORDER BY d.original_filename ASC"
        elif sort == 'name_desc':
            sort_condition = " ORDER BY d.original_filename DESC"

        # Construct the final query
        query = base_query
        params = []

        if search:
            query += search_condition
            params.append(f'%{search}%')

        if role != 'admin':
            query += user_condition
            params.append(user_id)

        if date_condition:
            query += date_condition

        query += sort_condition

        # Execute the query
        cur.execute(query, tuple(params))
        documents = cur.fetchall()
        cur.close()

        # Convert to list of dictionaries for easier template access
        docs = []
        for doc in documents:
            docs.append({
                'id': doc[0],
                'user_id': doc[1],
                'filename': doc[2],
                'original_filename': doc[3],
                'upload_time': doc[4],
                'file_hash': doc[5],
                'signature': doc[6],
                'username': doc[7]
            })

        return render_template('documents.html', documents=docs)
    except Exception as e:
        app.logger.error(f"Error in documents route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while fetching documents', 'danger')
        return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        app.logger.info("Upload request received")

        try:
            # Check if file was uploaded
            if 'file' not in request.files:
                app.logger.error("No file part in request")
                flash('No file selected', 'danger')
                return redirect(request.url)
            
            file = request.files['file']
            app.logger.info(f"File received: {file.filename}")
            
            # Check if file name is empty
            if file.filename == '':
                app.logger.error("No selected file")
                flash('No file selected', 'danger')
                return redirect(request.url)

            # Check if file type is allowed
            if not allowed_file(file.filename):
                app.logger.error(f"Invalid file type: {file.filename}")
                flash('File type not allowed. Supported formats: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG', 'danger')
                return redirect(request.url)

            # Create uploads directory if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
                app.logger.info(f"Created uploads directory: {app.config['UPLOAD_FOLDER']}")

            # Secure the filename
            original_filename = file.filename
            filename = secure_filename(file.filename)
            # Add username prefix to filename
            username = session['username']
            filename = f"{username}_{filename}.enc"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            app.logger.info(f"Saving file to: {file_path}")
            
            # Save the file
            try:
                file.save(file_path)
                app.logger.info("File saved successfully")
            except Exception as e:
                app.logger.error(f"Error saving file: {str(e)}")
                flash('Error saving file. Please try again.', 'danger')
                return redirect(request.url)
            
            # Calculate file hash
            try:
                file_hash = hash_file(file_path)
                app.logger.info(f"File hash calculated: {file_hash}")
            except Exception as e:
                app.logger.error(f"Error calculating file hash: {str(e)}")
                # Clean up the uploaded file
                try:
                    os.remove(file_path)
                except:
                    pass
                flash('Error processing file. Please try again.', 'danger')
                return redirect(request.url)
            
            # Get user_id from username
            cur = mysql.connection.cursor()
            cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
            user = cur.fetchone()
            if not user:
                raise Exception("User not found")
            user_id = user[0]
            
            # Store in database
            try:
                cur.execute("""
                    INSERT INTO documents (user_id, filename, original_filename, file_hash)
                    VALUES (%s, %s, %s, %s)
                """, (user_id, filename, original_filename, file_hash))
                mysql.connection.commit()
                app.logger.info("File information stored in database successfully")
            except Exception as e:
                app.logger.error(f"Database error: {str(e)}")
                app.logger.error(f"Error details: {traceback.format_exc()}")
                # Try to clean up the uploaded file
                try:
                    os.remove(file_path)
                except:
                    pass
                flash(f'Error saving file information: {str(e)}', 'danger')
                return redirect(request.url)
            finally:
                cur.close()

            # Log the action
            try:
                log_action(session['username'], 'upload', f'Uploaded file: {original_filename}')
            except Exception as e:
                app.logger.error(f"Error logging action: {str(e)}")
                # Don't return error for logging failure

            flash('File uploaded successfully', 'success')
            return redirect(url_for('documents'))

        except Exception as e:
            # Log the error
            app.logger.error(f"Upload error: {str(e)}")
            app.logger.error(f"Error details: {traceback.format_exc()}")
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template('upload.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_action(username, action_type, message):
    try:
        # Log to database
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO logs (username, action_type, message)
            VALUES (%s, %s, %s)
        """, (username, action_type, message))
        mysql.connection.commit()

        # Log to file
        app.logger.info(f'Action: {action_type}, User: {username}, Details: {message}')

    except Exception as e:
        app.logger.error(f"Error logging action to database: {str(e)}")
        # Still attempt to log to file even if DB logging fails
        try:
             app.logger.error(f'Failed DB Log - Action: {action_type}, User: {username}, Details: {message} - Error: {str(e)}')
        except Exception as file_log_error:
             print(f"Critical error: Failed to log to both database and file. {file_log_error}")

    finally:
        if 'cur' in locals() and cur:
            cur.close()

@app.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    try:
        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')
        
        cur = mysql.connection.cursor()

        if role == 'admin':
            # Admins can download any document
            cur.execute("""
                SELECT d.*, u.username 
                FROM documents d 
                JOIN users u ON d.user_id = u.id 
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only download their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.*, u.username 
                FROM documents d 
                JOIN users u ON d.user_id = u.id 
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))
            
        doc = cur.fetchone()
        cur.close()

        if not doc:
            flash('Document not found', 'danger')
            return redirect(url_for('documents'))

        # Convert to dictionary for easier access
        document = {
            'id': doc[0],
            'user_id': doc[1],
            'filename': doc[2],
            'original_filename': doc[3],
            'upload_time': doc[4],
            'file_hash': doc[5],
            'signature': doc[6],
            'username': doc[7]
        }

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        
        if not os.path.exists(file_path):
            flash('File not found on server', 'danger')
            return redirect(url_for('documents'))

        # Log the download
        log_action(session['username'], 'download', f'Downloaded file: {document["original_filename"]}')

        return send_file(
            file_path,
            as_attachment=True,
            download_name=document['original_filename']
        )

    except Exception as e:
        app.logger.error(f"Error in download route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while downloading the file', 'danger')
        return redirect(url_for('documents'))

@app.route('/verify/<int:doc_id>')
@login_required
def verify(doc_id):
    try:
        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')

        cur = mysql.connection.cursor()

        if role == 'admin':
            # Admins can verify any document
             cur.execute("""
                SELECT d.*, u.username 
                FROM documents d 
                JOIN users u ON d.user_id = u.id 
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only verify their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.*, u.username 
                FROM documents d 
                JOIN users u ON d.user_id = u.id 
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))

        doc = cur.fetchone()
        cur.close()

        if not doc:
            flash('Document not found', 'danger')
            return redirect(url_for('documents'))

        # Convert to dictionary for easier access
        document = {
            'id': doc[0],
            'user_id': doc[1],
            'filename': doc[2],
            'original_filename': doc[3],
            'upload_time': doc[4],
            'file_hash': doc[5],
            'signature': doc[6],
            'username': doc[7]
        }

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        
        if not os.path.exists(file_path):
            flash('File not found on server', 'danger')
            return redirect(url_for('documents'))

        # Calculate current hash
        current_hash = hash_file(file_path)
        
        # Compare with stored hash
        if current_hash == document['file_hash']:
            flash('Document integrity verified successfully', 'success')
            log_action(session['username'], 'verify', f'Verified file: {document["original_filename"]}')
        else:
            flash('Document integrity check failed! File may have been modified.', 'danger')
            log_action(session['username'], 'verify_failed', f'Verification failed for file: {document["original_filename"]}')

        return redirect(url_for('documents'))

    except Exception as e:
        app.logger.error(f"Error in verify route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while verifying the file', 'danger')
        return redirect(url_for('documents'))

@app.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    cur = None
    try:
        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')

        cur = mysql.connection.cursor()

        if role == 'admin':
            # Admins can delete any document
            cur.execute("""
                SELECT d.*, u.username 
                FROM documents d 
                JOIN users u ON d.user_id = u.id 
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only delete their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.*, u.username 
                FROM documents d 
                JOIN users u ON d.user_id = u.id 
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))

        doc = cur.fetchone()

        if not doc:
            flash('Document not found or you do not have permission to delete it.', 'danger')
            return redirect(url_for('documents'))

        # Convert to dictionary for easier access
        document = {
            'id': doc[0],
            'user_id': doc[1],
            'filename': doc[2],
            'original_filename': doc[3],
            'upload_time': doc[4],
            'file_hash': doc[5],
            'signature': doc[6],
            'username': doc[7]
        }

        # Delete file from filesystem
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                app.logger.info(f"File deleted from filesystem: {file_path}")
        except Exception as e:
            app.logger.error(f"Error deleting file: {str(e)}")
            # Continue with database deletion even if file deletion fails

        # Delete from database
        try:
            # First delete from logs if any related to this original filename
            # Note: This assumes the original filename is unique enough in logs, which might not always be true.
            # A more robust approach might involve linking logs directly to documents or using doc ID in log messages.
            cur.execute("DELETE FROM logs WHERE message LIKE %s", (f'%{document["original_filename"]}%',))
            
            # Then delete the document based on role
            if role == 'admin':
                 # Admins can delete any document
                 cur.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
            else:
                 # Regular users can only delete their own documents
                 # We already fetched user_id at the beginning for regular users if needed
                 # Re-fetch user_id just in case session changed (unlikely but safer)
                 cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                 user = cur.fetchone()
                 if not user:
                      # Should not happen with @login_required and initial checks, but as fallback
                      flash('User not found during deletion process.', 'danger')
                      log_action(session['username'], 'delete_document_user_not_found', f'User {username} not found during deletion attempt for doc ID {doc_id}.')
                      return redirect(url_for('documents'))
                 user_id = user[0]
                 cur.execute("DELETE FROM documents WHERE id = %s AND user_id = %s", (doc_id, user_id))

            mysql.connection.commit()
            flash('Document deleted successfully', 'success')
            # Log successful deletion
            log_action(session['username'], 'delete_success', f'Deleted file: {document["original_filename"]}')
        except Exception as e:
            app.logger.error(f"Error deleting document from database: {str(e)}")
            app.logger.error(f"Error details: {traceback.format_exc()}")
            flash('Error deleting document from database', 'danger')
            # Log database deletion failure
            log_action(session['username'], 'delete_db_failed', f'Failed to delete file from database: {document["original_filename"]}')
        finally:
            if cur:
                cur.close()

        return redirect(url_for('documents'))

    except Exception as e:
        app.logger.error(f"Error in delete route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        if cur:
            cur.close()
        flash('An error occurred while deleting the file', 'danger')
        return redirect(url_for('documents'))

@app.route('/logout')
def logout():
    # Set a flag to temporarily disable session check in before_request
    session['_logging_out'] = True

    # Clear only the application-specific session keys
    session.pop('username', None)
    session.pop('role', None)
    session.pop('pre_2fa_user', None)

    # After a short delay (or on the next request), the flag will be removed.
    # For simplicity, we'll handle the flag check in before_request.

    flash('You have been successfully logged out', 'success')
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        try:
            new_username = request.form['username']
            current_password = request.form['current_password']
            new_password = request.form.get('new_password')  # Optional new password
            confirm_password = request.form.get('confirm_password')  # Optional confirm password
            remove_photo = request.form.get('remove_photo') == 'true'  # Check if photo should be removed

            # Verify current password
            cur = mysql.connection.cursor()
            cur.execute("SELECT password FROM users WHERE username = %s", (session['username'],))
            user = cur.fetchone()
            
            if not user or not bcrypt.check_password_hash(user[0], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('edit_profile'))
            
            # Check if new username is already taken
            if new_username != session['username']:
                cur.execute("SELECT id FROM users WHERE username = %s", (new_username,))
                if cur.fetchone():
                    flash('Username is already taken', 'danger')
                    return redirect(url_for('edit_profile'))
            
            # Handle password change if requested
            if new_password:
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('edit_profile'))
                
                # Validate password strength
                if len(new_password) < 8 or not re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", new_password):
                    flash('Password must be at least 8 characters long and contain letters, numbers, and special characters', 'danger')
                    return redirect(url_for('edit_profile'))
                
                # Update password
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                cur.execute("UPDATE users SET password = %s WHERE username = %s", 
                           (hashed_password, session['username']))
                log_action(new_username, 'password_change', 'Password changed successfully')
            
            # Handle photo upload or removal
            if remove_photo:
                cur.execute("UPDATE users SET profile_photo = NULL WHERE username = %s", 
                           (session['username'],))
                log_action(new_username, 'profile_photo_removed', 'Profile photo removed')
            elif 'photo' in request.files:
                photo = request.files['photo']
                if photo.filename != '':
                    if allowed_file(photo.filename):
                        # Read the photo data
                        photo_data = photo.read()
                        
                        # Update the user's profile photo in the database
                        cur.execute("UPDATE users SET profile_photo = %s WHERE username = %s", 
                                   (photo_data, session['username']))
                        log_action(new_username, 'profile_photo_update', 'Profile photo updated')
                    else:
                        flash('Invalid file type. Please upload an image.', 'danger')
                        return redirect(url_for('edit_profile'))
            
            # Update username in database
            cur.execute("UPDATE users SET username = %s WHERE username = %s", 
                       (new_username, session['username']))
            
            mysql.connection.commit()
            
            # Update session
            session['username'] = new_username
            
            # Log the action
            log_action(new_username, 'profile_update', 'Updated profile information')
            
            flash('Profile updated successfully', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            app.logger.error(f"Error updating profile: {str(e)}")
            app.logger.error(f"Error details: {traceback.format_exc()}")
            flash('An error occurred while updating your profile', 'danger')
            return redirect(url_for('edit_profile'))
        finally:
            cur.close()

    return render_template('edit_profile.html')

@app.route('/profile-photo/<username>')
def get_profile_photo(username):
    """Serve the user's profile photo"""
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT profile_photo FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        
        if result and result[0]:
            # Create a response with the image data
            response = send_file(
                io.BytesIO(result[0]),
                mimetype='image/jpeg'
            )
            return response
        else:
            # Return a default profile photo
            default_photo_path = os.path.join(app.static_folder, 'images', 'default_profile.jpg')
            if os.path.exists(default_photo_path):
                return send_file(default_photo_path)
            else:
                # If default photo doesn't exist, return a 404
                return "Default profile photo not found", 404
    except Exception as e:
        app.logger.error(f"Error serving profile photo for {username}: {e}")
        return "Error serving profile photo", 500
    finally:
        cur.close()

@app.route('/admin')
@admin_required
def admin_dashboard():
    # This is the main admin dashboard route
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get search, sort, and filter parameters for users
        user_search = request.args.get('user_search', '')
        user_role = request.args.get('user_role', 'all')

        # Get search, sort, and filter parameters for files
        file_search = request.args.get('file_search', '')
        file_sort = request.args.get('file_sort', 'newest')
        file_filter = request.args.get('file_filter', 'all')

        # Construct user query
        user_query = "SELECT id, username, email, role FROM users"
        user_params = []

        if user_search or user_role != 'all':
            user_query += " WHERE"
            conditions = []

            if user_search:
                conditions.append(" (username LIKE %s OR email LIKE %s)")
                user_params.extend([f'%{user_search}%', f'%{user_search}%'])

            if user_role != 'all':
                conditions.append(" role = %s")
                user_params.append(user_role)

            user_query += " AND ".join(conditions)

        # Execute user query
        cur.execute(user_query, tuple(user_params))
        users = cur.fetchall()

        # Construct file query
        file_query = """
            SELECT d.id, d.original_filename, u.username, d.upload_time 
            FROM documents d 
            JOIN users u ON d.user_id = u.id
        """
        file_params = []

        if file_search or file_filter != 'all':
            file_query += " WHERE"
            conditions = []

            if file_search:
                conditions.append(" d.original_filename LIKE %s")
                file_params.append(f'%{file_search}%')

            if file_filter != 'all':
                if file_filter == 'today':
                    conditions.append(" DATE(d.upload_time) = CURDATE()")
                elif file_filter == 'week':
                    conditions.append(" YEARWEEK(d.upload_time) = YEARWEEK(CURDATE())")
                elif file_filter == 'month':
                    conditions.append(" MONTH(d.upload_time) = MONTH(CURDATE()) AND YEAR(d.upload_time) = YEAR(CURDATE())")

            file_query += " AND ".join(conditions)

        # Add sorting for files
        if file_sort == 'newest':
            file_query += " ORDER BY d.upload_time DESC"
        elif file_sort == 'oldest':
            file_query += " ORDER BY d.upload_time ASC"
        elif file_sort == 'name_asc':
            file_query += " ORDER BY d.original_filename ASC"
        elif file_sort == 'name_desc':
            file_query += " ORDER BY d.original_filename DESC"

        # Execute file query
        cur.execute(file_query, tuple(file_params))
        files = cur.fetchall()

        return render_template('admin.html', users=users, files=files)

    except Exception as e:
        app.logger.error(f"Error fetching data for admin dashboard: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the admin dashboard.', 'danger')
        return redirect(url_for('home'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Prevent deleting the last admin user (optional but recommended)
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cur.fetchone()[0]

        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        user_role = cur.fetchone()[0]

        if user_role == 'admin' and admin_count <= 1:
            flash('Cannot delete the last admin user.', 'danger')
            log_action(session['username'], 'admin_delete_user_failed', f'Attempted to delete the last admin user with ID {user_id}.')
            return redirect(url_for('admin_dashboard'))

        # Delete user's files first
        cur.execute("SELECT filename FROM documents WHERE user_id = %s", (user_id,))
        user_files = cur.fetchall()
        for file in user_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    app.logger.info(f"Admin deleted user file from filesystem: {file_path}")
                except Exception as e:
                    app.logger.error(f"Admin error deleting user file {file[0]}: {str(e)}")
                    # Log file deletion failure
                    log_action(session['username'], 'admin_delete_user_file_failed', f'Admin failed to delete file {file[0]} for user ID {user_id}: {str(e)}')

        cur.execute("DELETE FROM documents WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM logs WHERE username = (SELECT username FROM users WHERE id = %s)", (user_id,)) # Delete user's logs
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()

        flash('User and associated files deleted successfully.', 'success')
        log_action(session['username'], 'admin_delete_user_success', f'Admin deleted user with ID {user_id}.')

        return redirect(url_for('admin_dashboard'))

    except Exception as e:
        app.logger.error(f"Error deleting user from admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while deleting the user.', 'danger')
        log_action(session['username'], 'admin_delete_user_error', f'An error occurred while deleting user with ID {user_id}: {str(e)}')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/file/<int:file_id>/delete', methods=['POST'])
@admin_required
def admin_delete_file(file_id):
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get file information before deleting
        cur.execute("SELECT filename, original_filename FROM documents WHERE id = %s", (file_id,))
        file_info = cur.fetchone()

        if not file_info:
            flash('File not found.', 'danger')
            return redirect(url_for('admin_dashboard'))

        stored_filename, original_filename = file_info
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)

        # Delete file from filesystem
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                app.logger.info(f"Admin deleted file from filesystem: {file_path}")
            except Exception as e:
                app.logger.error(f"Admin error deleting file from filesystem {stored_filename}: {str(e)}")
                # Log file deletion failure
                log_action(session['username'], 'admin_delete_file_filesystem_failed', f'Admin failed to delete file from filesystem {stored_filename}: {str(e)}')

        # Delete from database
        cur.execute("DELETE FROM logs WHERE message LIKE %s", (f'%{original_filename}%',))
        cur.execute("DELETE FROM documents WHERE id = %s", (file_id,))
        mysql.connection.commit()

        flash('File deleted successfully.', 'success')
        log_action(session['username'], 'admin_delete_file_success', f'Admin deleted file with ID {file_id} ({original_filename}).')

        return redirect(url_for('admin_dashboard'))

    except Exception as e:
        app.logger.error(f"Error deleting file from admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while deleting the file.', 'danger')
        log_action(session['username'], 'admin_delete_file_error', f'An error occurred while deleting file with ID {file_id}: {str(e)}')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/logs')
@admin_required
def admin_logs():
    cur = None
    try:
        cur = mysql.connection.cursor()
        # Fetch all logs, ordered by timestamp
        cur.execute("SELECT timestamp, username, action_type, message FROM logs ORDER BY timestamp DESC")
        logs = cur.fetchall()

        return render_template('admin_logs.html', logs=logs)

    except Exception as e:
        app.logger.error(f"Error fetching logs for admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the logs.', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/edit_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    app.logger.info(f"Attempting to access edit_document route for doc ID: {doc_id}")
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')

        # Get document information
        if role == 'admin':
            # Admins can edit any document
            cur.execute("""
                SELECT d.id, d.original_filename, d.filename, d.upload_time, u.username
                FROM documents d JOIN users u ON d.user_id = u.id
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only edit their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.id, d.original_filename, d.filename, d.upload_time, u.username
                FROM documents d JOIN users u ON d.user_id = u.id
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))

        document = cur.fetchone()

        if not document:
            flash('Document not found or you do not have permission to edit it.', 'danger')
            log_action(session['username'], 'edit_document_failed', f'Attempted to edit document ID {doc_id} not found or without permission.')
            return redirect(url_for('documents'))
        
        doc_id, original_filename, stored_filename, upload_time, doc_owner_username = document # Get doc_owner_username

        if request.method == 'POST':
            # Handle file update logic here
            new_file = request.files.get('new_file')
            updated_original_filename = request.form.get('original_filename')

            if not updated_original_filename:
                 flash('Original filename is required.', 'danger')
                 log_action(username, 'edit_document_missing_filename', f'Attempted to update document ID {doc_id} with missing original filename.')
                 return redirect(url_for('edit_document', doc_id=doc_id))


            if new_file and new_file.filename != '':
                # Process the new file
                if not allowed_file(new_file.filename):
                    flash('Invalid file type for new file!', 'danger')
                    log_action(username, 'edit_document_invalid_type', f'Attempted to upload invalid file type for document ID {doc_id}: {new_file.filename}')
                    return redirect(url_for('edit_document', doc_id=doc_id))

                # Secure the filename and create stored filename with timestamp
                # Use the potentially updated original filename for logging and database
                secured_new_original_filename = secure_filename(updated_original_filename)
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                new_stored_filename = f'{timestamp}_{secured_new_original_filename}'
                new_file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_stored_filename)

                # Save the new file temporarily
                temp_new_file_path = new_file_path + '.temp'
                new_file.save(temp_new_file_path)

                # Calculate hash of the new file
                new_file_hash = hash_file(temp_new_file_path)

                # Encrypt the new file using the document owner's username for the key
                try:
                    with open(temp_new_file_path, 'rb') as f:
                        new_file_bytes = f.read()

                    # Use the document owner's username to derive the encryption key
                    encryption_key = hashlib.sha256(doc_owner_username.encode()).digest()
                    encrypted_bytes = encrypt_file(new_file_bytes, encryption_key)

                    with open(new_file_path, 'wb') as f:
                        f.write(encrypted_bytes)

                    # Remove temporary file
                    os.remove(temp_new_file_path)
                except Exception as e:
                    app.logger.error(f"Error encrypting new file for document ID {doc_id}: {str(e)}")
                    app.logger.error(f"Error details: {traceback.format_exc()}")
                    if os.path.exists(temp_new_file_path):
                        os.remove(temp_new_file_path)
                    flash(f'Error encrypting new file: {str(e)}', 'danger')
                    log_action(username, 'edit_document_encrypt_failed', f'Encryption failed for new file for document ID {doc_id}: {str(e)}')
                    return redirect(url_for('edit_document', doc_id=doc_id))

                # Delete the old file from filesystem
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
                if os.path.exists(old_file_path):
                    try:
                        os.remove(old_file_path)
                        app.logger.info(f"Old file deleted during edit: {old_file_path}")
                    except Exception as e:
                        app.logger.error(f"Error deleting old file during edit {stored_filename}: {str(e)}")
                        # Log old file deletion failure (non-critical for the edit process to continue)
                        log_action(username, 'edit_document_old_delete_failed', f'Failed to delete old file {stored_filename} for document ID {doc_id}: {str(e)}')

                # Update database entry with new file info and updated original filename
                cur.execute("""
                    UPDATE documents SET filename = %s, original_filename = %s, file_hash = %s, upload_time = %s
                    WHERE id = %s
                """, (new_stored_filename, updated_original_filename, new_file_hash, datetime.now(), doc_id))
                mysql.connection.commit()

                flash('Document and file updated successfully!', 'success')
                log_action(username, 'edit_document_success_with_file', f'Updated document ID {doc_id} with new file and name: {updated_original_filename}.')
                return redirect(url_for('documents'))

            # If no new file uploaded, only update the original filename
            else:
                # Check if the original filename has actually changed
                if updated_original_filename != original_filename:
                    cur.execute("""
                        UPDATE documents SET original_filename = %s
                        WHERE id = %s
                    """, (updated_original_filename, doc_id))
                    mysql.connection.commit()
                    flash('Document filename updated successfully.', 'success')
                    log_action(username, 'edit_document_success_filename_only', f'Updated filename for document ID {doc_id} to {updated_original_filename}.')
                else:
                    flash('No changes were made.', 'info')
                    log_action(username, 'edit_document_no_changes', f'Attempted to edit document ID {doc_id} but no changes were made.')

                return redirect(url_for('documents'))

        # For GET request, render the edit form
        # Convert document tuple to dictionary for easier template access (excluding stored_filename for template)
        doc_data = {
            'id': document[0],
            'original_filename': document[1],
            'upload_time': document[3], # Use original upload_time for display
            'username': document[4] # Document owner's username
        }
        return render_template('edit_document.html', document=doc_data)

    except Exception as e:
        app.logger.error(f"Error processing edit document for doc ID {doc_id}: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while updating the document.', 'danger')
        log_action(session['username'], 'edit_document_error', f'An error occurred while processing edit for document ID {doc_id}: {str(e)}')
        return redirect(url_for('documents'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get user information
        cur.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()

        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Convert user tuple to dictionary for easier template access
        user_data = {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3]
        }

        if request.method == 'POST':
            # Handle user update logic here
            new_username = request.form.get('username')
            new_email = request.form.get('email')
            new_role = request.form.get('role')

            # Basic validation
            if not new_username or not new_email or not new_role:
                flash('Username, email, and role are required.', 'danger')
                log_action(session['username'], 'admin_edit_user_failed', f'Admin attempted to edit user ID {user_id} with missing data.')
                return render_template('admin_edit_user.html', user=user_data) # Render with existing data and error

            # Check if username already exists (excluding the current user)
            cur.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, user_id))
            if cur.fetchone():
                flash('Username already exists.', 'danger')
                log_action(session['username'], 'admin_edit_user_failed', f'Admin attempted to change username to {new_username} for user ID {user_id}, but it already exists.')
                 # Update user_data with new values to pre-fill the form
                user_data['username'] = new_username
                user_data['email'] = new_email
                user_data['role'] = new_role
                return render_template('admin_edit_user.html', user=user_data)

            # Check if email already exists (excluding the current user)
            cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (new_email, user_id))
            if cur.fetchone():
                flash('Email already exists.', 'danger')
                log_action(session['username'], 'admin_edit_user_failed', f'Admin attempted to change email to {new_email} for user ID {user_id}, but it already exists.')
                 # Update user_data with new values to pre-fill the form
                user_data['username'] = new_username
                user_data['email'] = new_email
                user_data['role'] = new_role
                return render_template('admin_edit_user.html', user=user_data)

            # Update user in database
            cur.execute("""
                UPDATE users SET username = %s, email = %s, role = %s
                WHERE id = %s
            """, (new_username, new_email, new_role, user_id))
            mysql.connection.commit()

            flash('User updated successfully.', 'success')
            log_action(session['username'], 'admin_edit_user_success', f'Admin updated user ID {user_id} (Username: {new_username}, Email: {new_email}, Role: {new_role}).')

            return redirect(url_for('admin_dashboard'))

        # For GET request, render the edit form
        return render_template('admin_edit_user.html', user=user_data)

    except Exception as e:
        app.logger.error(f"Error editing user ID {user_id} from admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while editing the user.', 'danger')
        log_action(session['username'], 'admin_edit_user_error', f'An error occurred while editing user ID {user_id}: {str(e)}')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/user/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    cur = None
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')

            # Basic validation
            if not username or not email or not password or not role:
                flash('Username, email, password, and role are required.', 'danger')
                log_action(session['username'], 'admin_add_user_failed', f'Admin attempted to add user with missing data.')
                return render_template('admin_add_user.html', form_data=request.form) # Render with existing data and error

            cur = mysql.connection.cursor()

            # Check if username or email already exists
            cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            if cur.fetchone():
                flash('Username or email already exists.', 'danger')
                log_action(session['username'], 'admin_add_user_failed', f'Admin attempted to add user with existing username ({username}) or email ({email}).')
                return render_template('admin_add_user.html', form_data=request.form)

            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Generate a 2FA secret (optional for admin-added users, could be mandated)
            totp_secret = pyotp.random_base32() # Generate one by default

            # Insert new user into database
            cur.execute("""
                INSERT INTO users (username, email, password, role, 2fa_secret)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, hashed_password, role, totp_secret))
            mysql.connection.commit()

            flash('User added successfully.', 'success')
            log_action(session['username'], 'admin_add_user_success', f'Admin added new user: Username: {username}, Email: {email}, Role: {role}.')

            return redirect(url_for('admin_dashboard'))

        # For GET request, render the add user form
        return render_template('admin_add_user.html', form_data={})

    except Exception as e:
        app.logger.error(f"Error adding user from admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while adding the user.', 'danger')
        log_action(session['username'], 'admin_add_user_error', f'An error occurred while adding a user: {str(e)}')
        return render_template('admin_add_user.html', form_data=request.form)
    finally:
        if cur:
            cur.close()

@app.after_request
def add_security_headers(response):
    # Prevent caching of sensitive pages
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/sign_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def sign_document(doc_id):
    cur = None
    try:
        username = session.get('username')
        role = session.get('role')

        cur = mysql.connection.cursor()

        # Fetch document details and check authorization
        if role == 'admin':
            cur.execute("SELECT id, original_filename, filename, user_id FROM documents WHERE id = %s", (doc_id,))
        else:
            cur.execute("SELECT d.id, d.original_filename, d.filename, d.user_id FROM documents d JOIN users u ON d.user_id = u.id WHERE d.id = %s AND u.username = %s", (doc_id, username))

        document = cur.fetchone()

        if not document:
            flash('Document not found or you do not have permission to sign it.', 'danger')
            return redirect(url_for('documents'))

        doc_id, original_filename, stored_filename, doc_owner_user_id = document

        if request.method == 'GET':
            # Get the document owner's username to retrieve their private key
            cur.execute("SELECT username, private_key FROM users WHERE id = %s", (doc_owner_user_id,))
            owner_info = cur.fetchone()

            if not owner_info:
                flash('Document owner not found.', 'danger')
                log_action(username, 'sign_document_failed', f'Could not find owner info for document ID {doc_id}.')
                return redirect(url_for('documents'))

            doc_owner_username, private_key_pem = owner_info

            if not private_key_pem:
                flash(f'No private key found for document owner ({doc_owner_username}). Cannot sign.', 'danger')
                log_action(username, 'sign_document_failed', f'No private key found for document owner {doc_owner_username} for document ID {doc_id}.')
                return redirect(url_for('documents'))

            # Read the file content
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
            if not os.path.exists(file_path):
                flash('File not found on server.', 'danger')
                log_action(username, 'sign_document_failed', f'File {stored_filename} not found on server for document ID {doc_id}.')
                return redirect(url_for('documents'))

            with open(file_path, 'rb') as f:
                file_content = f.read()

            # Calculate the hash of the file content
            # Using SHA256 as in hash_file function
            digest = hashes.Hash(hashes.SHA256())
            digest.update(file_content)
            file_hash_bytes = digest.finalize()

            # Load the private key
            # Assuming the private key is stored in PEM format without encryption
            try:
                private_key = serialization.load_pem_private_key(
                    private_key_pem,
                    password=None, # Assuming no password for simplicity
                    backend=None
                )
            except Exception as e:
                app.logger.error(f"Error loading private key for user {doc_owner_username}: {e}\n{traceback.format_exc()}")
                flash('Error loading private key. Make sure it is in correct format.', 'danger')
                log_action(username, 'sign_document_failed', f'Error loading private key for document owner {doc_owner_username} for document ID {doc_id}.')
                return redirect(url_for('documents'))

            # Sign the hash
            try:
                signature = private_key.sign(
                    file_hash_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                app.logger.info(f"Successfully signed document ID {doc_id}")
            except Exception as e:
                app.logger.error(f"Error signing document ID {doc_id} for user {doc_owner_username}: {str(e)}\n{traceback.format_exc()}")
                flash('Error signing document.', 'danger')
                log_action(username, 'sign_document_failed', f'Error signing document ID {doc_id} for user {doc_owner_username}: {str(e)}')
                return redirect(url_for('documents'))

            # Store the signature in the database
            # The signature column type should be suitable for storing bytes (e.g., BLOB or VARBINARY)
            cur.execute("""
                UPDATE documents SET signature = %s WHERE id = %s
            """, (signature, doc_id))
            mysql.connection.commit()

            flash('Document signed successfully!', 'success')
            log_action(username, 'sign_document_success', f'Successfully signed document ID {doc_id} ({original_filename}).')

            return redirect(url_for('documents'))

        if request.method == 'POST':
            try:
                # Fetch document details again to be safe
                # Using the same query as the GET request to ensure consistency
                if role == 'admin':
                     cur.execute("SELECT id, original_filename, filename, user_id FROM documents WHERE id = %s", (doc_id,))
                else:
                     cur.execute("SELECT d.id, d.original_filename, d.filename, d.user_id FROM documents d JOIN users u ON d.user_id = u.id WHERE d.id = %s AND u.username = %s", (doc_id, username))

                document = cur.fetchone()

                if not document:
                     flash('Document not found or you do not have permission to sign it.', 'danger')
                     return redirect(url_for('documents'))

                doc_id, original_filename, stored_filename, doc_owner_user_id = document

                # Get the document owner's username to retrieve their private key
                cur.execute("SELECT username, private_key FROM users WHERE id = %s", (doc_owner_user_id,))
                owner_info = cur.fetchone()

                if not owner_info:
                     flash('Document owner not found.', 'danger')
                     log_action(username, 'sign_document_failed', f'Could not find owner info for document ID {doc_id}.')
                     return redirect(url_for('documents'))

                doc_owner_username, private_key_pem = owner_info

                if not private_key_pem:
                     flash(f'No private key found for document owner ({doc_owner_username}). Cannot sign.', 'danger')
                     log_action(username, 'sign_document_failed', f'No private key found for document owner {doc_owner_username} for document ID {doc_id}.')
                     return redirect(url_for('documents'))

                # Read the file content
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
                if not os.path.exists(file_path):
                     flash('File not found on server.', 'danger')
                     log_action(username, 'sign_document_failed', f'File {stored_filename} not found on server for document ID {doc_id}.')
                     return redirect(url_for('documents'))

                with open(file_path, 'rb') as f:
                     file_content = f.read()

                # Calculate the hash of the file content
                # Using SHA256 as in hash_file function
                digest = hashes.Hash(hashes.SHA256())
                digest.update(file_content)
                file_hash_bytes = digest.finalize()

                # Load the private key
                # Assuming the private key is stored in PEM format without encryption
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem,
                        password=None, # Assuming no password for simplicity
                        backend=None
                    )
                except Exception as e:
                    app.logger.error(f"Error loading private key for user {doc_owner_username}: {e}\n{traceback.format_exc()}")
                    flash('Error loading private key. Make sure it is in correct format.', 'danger')
                    log_action(username, 'sign_document_failed', f'Error loading private key for document owner {doc_owner_username} for document ID {doc_id}.')
                    return redirect(url_for('documents'))

                # Sign the hash
                try:
                    signature = private_key.sign(
                        file_hash_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    app.logger.info(f"Successfully signed document ID {doc_id}")
                except Exception as e:
                    app.logger.error(f"Error signing document ID {doc_id} for user {doc_owner_username}: {str(e)}\n{traceback.format_exc()}")
                    flash('Error signing document.', 'danger')
                    log_action(username, 'sign_document_failed', f'Error signing document ID {doc_id} for user {doc_owner_username}: {str(e)}')
                    return redirect(url_for('documents'))

                # Store the signature in the database
                # The signature column type should be suitable for storing bytes (e.g., BLOB or VARBINARY)
                cur.execute("""
                    UPDATE documents SET signature = %s WHERE id = %s
                """, (signature, doc_id))
                mysql.connection.commit()

                flash('Document signed successfully!', 'success')
                log_action(username, 'sign_document_success', f'Successfully signed document ID {doc_id} ({original_filename}).')

                return redirect(url_for('documents'))

            except Exception as e:
                app.logger.error(f"Error during document signing for doc ID {doc_id}: {str(e)}")
                app.logger.error(f"Error details: {traceback.format_exc()}")
                flash('An error occurred while signing the document.', 'danger')
                log_action(session['username'], 'sign_document_error', f'An error occurred while signing document ID {doc_id}: {str(e)}')
                return redirect(url_for('documents'))
            finally:
                if cur:
                    cur.close()

    except Exception as e:
        app.logger.error(f"Error accessing sign document route for doc ID {doc_id}: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred.', 'danger')
        return redirect(url_for('documents'))
    finally:
        if cur:
            cur.close()

@app.route('/remove-profile-photo', methods=['POST'])
@login_required
def remove_profile_photo():
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET profile_photo = NULL WHERE username = %s", (session['username'],))
        mysql.connection.commit()
        flash('Profile photo removed successfully', 'success')
        log_action(session['username'], 'profile_photo_removed', 'Profile photo removed')
    except Exception as e:
        app.logger.error(f"Error removing profile photo: {str(e)}")
        flash('Error removing profile photo', 'danger')
    finally:
        cur.close()
    return redirect(url_for('edit_profile'))

if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True,
        ssl_context=('cert.pem', 'key.pem')
    )