# SecureDocs - Secure Document Management System

SecureDocs is a robust and secure document management system built with Flask that provides end-to-end encryption for document storage and sharing. The system ensures data integrity and security while maintaining a user-friendly interface.

## Features

### Security Features
- End-to-end encryption using AES-256
- Secure file hashing for integrity verification
- Session-based authentication with secure cookie handling
- OAuth2 integration with Google and GitHub
- Two-factor authentication support
- Role-based access control (Admin and User roles)
- Secure password hashing using bcrypt
- Protection against common web vulnerabilities

### Document Management
- Secure file upload and download
- File encryption at rest
- Document integrity verification
- File type validation
- Automatic file hash generation
- User-specific document storage
- Document access logging

### User Management
- User registration and authentication
- Profile management
- OAuth2 social login integration
- Session management
- Role-based permissions
- Activity logging

### Admin Features
- User management dashboard
- System activity monitoring
- Access logs review
- Document management
- User role management

## Technical Stack

### Backend
- Python 3.x
- Flask (Web Framework)
- MySQL (Database)
- PyCryptodome (Cryptography)
- Flask-Session (Session Management)
- Flask-Bcrypt (Password Hashing)
- Flask-Dance (OAuth Integration)

### Frontend
- HTML5
- CSS3 (with modern features)
- Bootstrap 5
- Font Awesome
- JavaScript
- Responsive design
- Dark/Light theme support

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-docs.git
cd secure-docs
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory with the following variables:
```
SECRET_KEY=your-secret-key
MYSQL_HOST=localhost
MYSQL_USER=your-mysql-user
MYSQL_PASSWORD=your-mysql-password
MYSQL_DB=securedocs_db
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

5. Initialize the database:
```bash
python setup_db.py
```

6. Run the application:
```bash
python app.py
```

## Security Measures

1. **File Security**
   - Files are encrypted using AES-256 in CBC mode
   - Each file has a unique encryption key
   - File integrity is verified using SHA-256 hashing

2. **Authentication Security**
   - Secure session management
   - Password hashing with bcrypt
   - OAuth2 integration for social login
   - Two-factor authentication support

3. **Application Security**
   - CSRF protection
   - XSS prevention
   - SQL injection prevention
   - Secure headers implementation
   - Rate limiting
   - Input validation

## Usage

1. **User Registration/Login**
   - Register a new account or login with existing credentials
   - Option to use Google or GitHub for authentication
   - Enable two-factor authentication for additional security

2. **Document Management**
   - Upload documents through the secure interface
   - View and manage your documents
   - Download encrypted documents
   - Verify document integrity

3. **Admin Dashboard**
   - Monitor system activity
   - Manage users and roles
   - Review access logs
   - Handle document management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the development team.

## Acknowledgments

- Flask framework and its contributors
- PyCryptodome for cryptographic functions
- Bootstrap for the frontend framework
- All other open-source contributors
