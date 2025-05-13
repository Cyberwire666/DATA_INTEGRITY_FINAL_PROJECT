-- Create documents table if it doesn't exist
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
);

-- Create logs table if it doesn't exist
CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
); 