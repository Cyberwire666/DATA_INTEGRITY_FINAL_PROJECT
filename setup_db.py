from flask import Flask
from flask_mysqldb import MySQL
import os

app = Flask(__name__)

# MySQL config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'securedocs_db'

mysql = MySQL(app)

def setup_database():
    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            
            # Create documents table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    filename VARCHAR(255) NOT NULL,
                    file_path VARCHAR(255) NOT NULL,
                    file_hash VARCHAR(64) NOT NULL,
                    file_size INT NOT NULL,
                    upload_date DATETIME NOT NULL,
                    is_encrypted BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            """)
            
            # Create logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    action_type VARCHAR(50) NOT NULL,
                    message TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            """)
            
            mysql.connection.commit()
            print("Database tables created successfully!")
            
        except Exception as e:
            print(f"Error setting up database: {str(e)}")
        finally:
            cur.close()

if __name__ == '__main__':
    setup_database() 