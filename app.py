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

from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github

from crypto_utils import encrypt_file, decrypt_file, hash_file
from error_handlers import init_error_handlers

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
file_handler = RotatingFileHandler(log_file_path, maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

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
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        totp_secret = pyotp.random_base32()

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO users (username, email, password, 2fa_secret)
            VALUES (%s, %s, %s, %s)
        """, (username, email, hashed_pw, totp_secret))
        mysql.connection.commit()
        cur.close()

        log_action(username, 'register', 'User registered successfully')

        return redirect(url_for('qr_page', username=username))

    return render_template('register.html')

@app.route('/qr/<username>')
def qr_page(username):
    return render_template('qr_page.html', username=username)

@app.route('/qrcode/<username>')
def show_qr(username):
    cur = mysql.connection.cursor()
    cur.execute("SELECT 2fa_secret FROM users WHERE username = %s", (username,))
    secret = cur.fetchone()[0]
    cur.close()

    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name="SecureDocs")
    img = qrcode.make(otp_uri)

    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    log_action(username, 'qr_code', f'Generated QR code for 2FA for user {username}')

    return send_file(buf, mimetype='image/png')

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
        # Get user_id from username
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        user = cur.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))
        user_id = user[0]

        # Get documents for the user
        cur.execute("""
            SELECT d.*, u.username 
            FROM documents d 
            JOIN users u ON d.user_id = u.id 
            WHERE d.user_id = %s 
            ORDER BY d.upload_time DESC
        """, (user_id,))
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
        # Get user_id from username
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        user = cur.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))
        user_id = user[0]

        # Get document
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
        # Get user_id from username
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        user = cur.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))
        user_id = user[0]

        # Get document
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
        # Get user_id from username
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        user = cur.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))
        user_id = user[0]

        # Get document
        cur.execute("""
            SELECT d.*, u.username 
            FROM documents d 
            JOIN users u ON d.user_id = u.id 
            WHERE d.id = %s AND d.user_id = %s
        """, (doc_id, user_id))
        doc = cur.fetchone()

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
            # First delete from logs if any
            cur.execute("DELETE FROM logs WHERE message LIKE %s", (f'%{document["original_filename"]}%',))
            
            # Then delete the document
            cur.execute("DELETE FROM documents WHERE id = %s AND user_id = %s", (doc_id, user_id))
            mysql.connection.commit()
            app.logger.info(f"Document deleted from database: {doc_id}")
            
            # Log the deletion
            log_action(session['username'], 'delete', f'Deleted file: {document["original_filename"]}')
            
            flash('Document deleted successfully', 'success')
        except Exception as e:
            mysql.connection.rollback()
            app.logger.error(f"Database error: {str(e)}")
            flash('Error deleting document from database', 'danger')
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
            
            # Handle photo upload
            if 'photo' in request.files:
                photo = request.files['photo']
                if photo.filename != '':
                    if allowed_file(photo.filename):
                        # Save the new photo
                        filename = secure_filename(new_username + '.jpg')
                        photo_path = os.path.join('static/profile_photos', filename)
                        photo.save(photo_path)
                        
                        # Delete old photo if it exists
                        old_photo = os.path.join('static/profile_photos', session['username'] + '.jpg')
                        if os.path.exists(old_photo):
                            os.remove(old_photo)
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

@app.route('/admin')
@admin_required
def admin_dashboard():
    # This is the main admin dashboard route
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Fetch all users
        cur.execute("SELECT id, username, email, role FROM users")
        users = cur.fetchall()

        # Fetch all files
        cur.execute("SELECT d.id, d.original_filename, u.username, d.upload_time FROM documents d JOIN users u ON d.user_id = u.id")
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

@app.after_request
def add_security_headers(response):
    # Prevent caching of sensitive pages
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=True)
