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
    if 'username' in session:
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        if not cur.fetchone():
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        cur.close()

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
            return redirect(url_for('two_factor'))
        
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
            flash('Successfully logged in', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')
            return render_template('2fa.html')

    return render_template('2fa.html')

@app.route('/google-login')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return "Failed to fetch user info from Google."

    info = resp.json()
    email = info.get("email")
    username = email.split("@")[0]

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, role FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if user:
        session['username'] = username
        session['role'] = user[1]
    else:
        cur.execute("""
            INSERT INTO users (username, email, password, role, 2fa_secret)
            VALUES (%s, %s, %s, %s, %s)
        """, (username, email, '', 'user', ''))
        mysql.connection.commit()
        session['username'] = username
        session['role'] = 'user'

    cur.close()
    return redirect(url_for('home'))

@app.route('/github-login')
def github_login():
    if not github.authorized:
        return redirect(url_for("github.login"))

    resp = github.get("/user")
    if not resp.ok:
        return "Failed to fetch user info from GitHub."

    info = resp.json()
    username = info.get("login")

    email_resp = github.get("/user/emails")
    if not email_resp.ok:
        return "Failed to fetch GitHub emails."

    emails = email_resp.json()
    primary_email = next((e["email"] for e in emails if e["primary"]), None)
    if not primary_email:
        return "Primary GitHub email not found."

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, role FROM users WHERE email = %s", (primary_email,))
    user = cur.fetchone()

    if user:
        session['username'] = username
        session['role'] = user[1]
    else:
        cur.execute("""
            INSERT INTO users (username, email, password, role, 2fa_secret)
            VALUES (%s, %s, %s, %s, %s)
        """, (username, primary_email, '', 'user', ''))
        mysql.connection.commit()
        session['username'] = username
        session['role'] = 'user'

    cur.close()
    return redirect(url_for('home'))

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
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO logs (username, action_type, message)
            VALUES (%s, %s, %s)
        """, (username, action_type, message))
        mysql.connection.commit()
    except Exception as e:
        app.logger.error(f"Error logging action: {str(e)}")
    finally:
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
    session.clear()
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

if __name__ == '__main__':
    app.run(debug=True)