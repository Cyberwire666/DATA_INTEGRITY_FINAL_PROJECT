from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, send_file, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_session import Session
from werkzeug.utils import secure_filename
import os
import io
import pyotp
import qrcode
from datetime import datetime
import traceback

from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github

from crypto_utils import encrypt_file, decrypt_file, hash_file
from error_handlers import init_error_handlers

app = Flask(__name__)
app.secret_key = 'securedocs-secret-key'

# Initialize error handlers
init_error_handlers(app)

# Session config
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# MySQL config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'securedocs_db'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# OAuth Blueprints
google_bp = make_google_blueprint(
    client_id="454134712390-7pt96fgokg003sedhskamrqfen4j4ej8.apps.googleusercontent.com",
    client_secret="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",
    redirect_to="google_login",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
)
app.register_blueprint(google_bp, url_prefix="/login")

github_bp = make_github_blueprint(
    client_id="Ov23liXj9tSOMWfOfPXH",
    client_secret="40e75129e4ba13506c137d19a95f96cbf70e185f",
    redirect_to="github_login",
    scope="user:email"
)
app.register_blueprint(github_bp, url_prefix="/login")

def log_action(username, action_type, message):
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO logs (username, action_type, message)
        VALUES (%s, %s, %s)
    """, (username, action_type, message))
    mysql.connection.commit()
    cur.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
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
    return f'''
        <h2>2FA Setup</h2>
        <p>Scan this QR code with Google Authenticator or Authy:</p>
        <img src="/qrcode/{username}" alt="QR Code"><br><br>
        <a href="/login">Continue to Login</a>
    '''

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
        return "Login Failed"
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

        secret, role = result
        totp = pyotp.TOTP(secret)

        if totp.verify(token):
            session.pop('pre_2fa_user')
            session['username'] = username
            session['role'] = role
            return redirect(url_for('home'))
        else:
            flash("Invalid 2FA code. Please try again.", "danger")
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
def documents():
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(dictionary=True)
    cur.execute("""
        SELECT * FROM documents 
        WHERE username = %s 
        ORDER BY upload_date DESC
    """, (session['username'],))
    documents = cur.fetchall()
    cur.close()

    return render_template('documents.html', documents=documents)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

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
            filename = secure_filename(file.filename)
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
            
            # Get file size
            try:
                file_size = os.path.getsize(file_path)
                app.logger.info(f"File size: {file_size} bytes")
            except Exception as e:
                app.logger.error(f"Error getting file size: {str(e)}")
                # Clean up the uploaded file
                try:
                    os.remove(file_path)
                except:
                    pass
                flash('Error processing file. Please try again.', 'danger')
                return redirect(request.url)
            
            # Store in database
            try:
                cur = mysql.connection.cursor()
                app.logger.info(f"Attempting to insert document: username={session['username']}, filename={filename}, file_path={file_path}, file_hash={file_hash}, file_size={file_size}")
                
                # First check if the user exists
                cur.execute("SELECT username FROM users WHERE username = %s", (session['username'],))
                if not cur.fetchone():
                    raise Exception(f"User {session['username']} not found in database")
                
                # Then insert the document
                cur.execute("""
                    INSERT INTO documents (username, filename, file_path, file_hash, file_size, upload_date, is_encrypted)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (session['username'], filename, file_path, file_hash, file_size, datetime.now(), False))
                mysql.connection.commit()
                cur.close()
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

            # Log the action
            try:
                log_action(session['username'], 'upload', f'Uploaded file: {filename}')
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

@app.route('/download/<int:doc_id>')
def download(doc_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(dictionary=True)
    cur.execute("""
        SELECT * FROM documents 
        WHERE id = %s AND username = %s
    """, (doc_id, session['username']))
    doc = cur.fetchone()
    cur.close()

    if doc:
        return send_file(doc['file_path'], as_attachment=True)
    else:
        flash('Document not found', 'danger')
        return redirect(url_for('documents'))

@app.route('/verify/<int:doc_id>')
def verify(doc_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(dictionary=True)
    cur.execute("""
        SELECT * FROM documents 
        WHERE id = %s AND username = %s
    """, (doc_id, session['username']))
    doc = cur.fetchone()
    cur.close()

    if doc:
        current_hash = hash_file(doc['file_path'])
        is_valid = current_hash == doc['file_hash']
        
        if is_valid:
            flash('Document integrity verified successfully', 'success')
        else:
            flash('Document integrity check failed', 'danger')
    else:
        flash('Document not found', 'danger')
    
    return redirect(url_for('documents'))

@app.route('/delete/<int:doc_id>', methods=['POST'])
def delete_document(doc_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(dictionary=True)
    cur.execute("""
        SELECT * FROM documents 
        WHERE id = %s AND username = %s
    """, (doc_id, session['username']))
    doc = cur.fetchone()

    if doc:
        # Delete file from filesystem
        try:
            os.remove(doc['file_path'])
        except OSError:
            pass  # File might not exist

        # Delete from database
        cur.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
        mysql.connection.commit()
        flash('Document deleted successfully', 'success')
    else:
        flash('Document not found', 'danger')

    cur.close()
    return redirect(url_for('documents'))

@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    flash('You have been successfully logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
