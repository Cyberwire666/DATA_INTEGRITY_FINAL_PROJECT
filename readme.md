PACKAGES :
pip install Flask Flask-MySQLdb Flask-Bcrypt Flask-Session python-dotenv pyotp qrcode[pil] flask-dance python-qrcode mysql-connector-python pycryptodome

GITHUB OAUTH:
https://github.com/settings/developers
Data_integrity_final_project-main
Homepage URL: http://localhost:5000/
Authorization callback URL: http://127.0.0.1:5000/login/github/authorized

GOOGLE OAUTH:
https://console.cloud.google.com/auth/clients/
Authorized JavaScript origins: http://localhost:5000
Authorized redirect URIs: http://127.0.0.1:5000/login/google/authorized

TO RUN : python app.py
