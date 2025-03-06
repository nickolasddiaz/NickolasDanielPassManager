# [Password Manager](https://github.com/nickolasddiaz/NickolasDanielPassManager)

A secure password manager built with Python Flask, JavaScript and PostgreSQL.
[Website Link](https://nickolasdanielpassmanager.onrender.com/)

![image-1](https://github.com/user-attachments/assets/d5b7599a-1379-4a11-9f1a-289e72782ddf)
![image-2](https://github.com/user-attachments/assets/23c1ebdb-edf5-4387-b31b-b25e497cd776)
![image](https://github.com/user-attachments/assets/7029c775-2a5c-42ed-aa17-b343722f3896)


## Features

### Security
- Secure password hashing using SHA-256
- JWT (JSON Web Token) for authentication
- CSRF protection
- Rate limiting to prevent brute-force attacks
- Secure headers implementation with Flask-Talisman
- AES encryption for stored credentials

### User Management
- User registration with email verification
- Secure login system
- Password change functionality
- Email change with verification
- Account deletion option

### Credential Management
- Add, update, and delete credentials (website, username, password)
- View all stored credentials in a table format
- Show/hide password functionality
- Edit credentials directly in the table
- Search functionality to filter credentials

### User Interface
- Clean and intuitive web interface
- Responsive design for various screen sizes
- Real-time updates without page reloads

### API
- RESTful API endpoints for all functionalities
- Proper error handling and status codes

### Database
- PostgreSQL database with connection pooling for efficient data management
- Indexed tables for optimized query performance

### Additional Security Measures
- Environment variable usage for sensitive information
- Secure cookie handling
- XSS protection

## Technical Stack
- Backend: Python Flask
- Frontend: HTML, CSS, JavaScript
- Database: PostgreSQL
- Authentication: JWT
- Encryption: AES, Fernet


## Setup and Installation

### Prerequisites
- Python version 3.11.2

### Setup
```bash
pip install -r requirements.txt
flask run
```

### Environment Configuration
Create a `.env` file in the root directory with the following content:

```
local_salt = ""
JWT_SECRET_KEY = ""
databasesx = "postgres"
hostsx = "database-website"
usersx = "database-username"
passwordsx = "database-password"
portsx = "database-port"
csrfsecretekey = b'crsfsecretekey'
urlx = 'url'
```

Replace the empty values and placeholders with your actual configuration.

### Database Setup

Execute the following SQL commands to set up your database:

```sql
CREATE TABLE users (
    hashed_email TEXT UNIQUE NOT NULL PRIMARY KEY,
    encrypted_key TEXT NOT NULL,
    salt TEXT NOT NULL,
    verification_code TEXT,
    is_verified BOOLEAN DEFAULT FALSE
);

CREATE TABLE stored_credentials (
    user_email TEXT REFERENCES users (hashed_email),
    hashwebuser TEXT UNIQUE NOT NULL,
    encrwebuserpass TEXT NOT NULL
);

CREATE INDEX idx_stored_credentials_hashwebuser ON stored_credentials (encrwebuserpass);
CREATE INDEX idx_users_hashed_email ON users (hashed_email);
CREATE INDEX idx_stored_credentials_user_email ON stored_credentials (user_email);

ALTER TABLE stored_credentials
DROP CONSTRAINT IF EXISTS stored_credentials_user_email_fkey,
ADD CONSTRAINT stored_credentials_user_email_fkey 
FOREIGN KEY (user_email) REFERENCES users (hashed_email) ON UPDATE CASCADE ON DELETE CASCADE;
```

![image-3](https://github.com/user-attachments/assets/6d1e7575-2235-4e8f-aaf9-1245ef0b08b1)

# Encryption and Data Management in the Password Manager

## Storing User Credentials

1. **User Registration**:
   - When a user signs up, their email is hashed with a local salt: <br />
   `hashed_email = hash_password(email, local_salt)`
   - A unique salt is generated for the user: <br />
   `salt = generate_salt()`
   - The user's password is hashed with their email and salt: <br />
   `password_hash = hash_password(hashed_email + password, salt)`
   - A unique key is generated: <br />
   `key = generate_salt()`
   - This key is encrypted using the password hash:<br /> `encrypted_key = encrypt(local_salt + '.' + key, password_hash)`
   - The hashed email, encrypted key, and salt are stored in the `users` table

2. **Storing Website Credentials**:
   - When a user adds a website credential, a unique identifier is created: <br />
   `hashwebuser = hash_password(website + username, local_salt)`
   - The website, username, and password are encrypted together: <br />
   `encrwebuserpass = encrypt(website + ',' + username + ',' + password, key)`
   - Here, `key` is derived from the user's login process and contains the decryption key
   - The `hashwebuser` and `encrwebuserpass` are stored in the `stored_credentials` table

## Proccess for Changing Password

1. The user provides their current password and new password
2. The system verifies the current password by:
   - Retrieving the user's salt and encrypted key from the database
   - Hashing the provided current password with the stored salt
   - Attempting to decrypt the stored encrypted key
3. If verification succeeds:
   - A new salt is generated
   - The new password is hashed with the user's email and new salt
   - The user's unique key is re-encrypted with the new password hash
   - The database is updated with the new encrypted key and salt

## Proccess for Changing Email

1. The user provides their new email and current password
2. The system verifies the current password (as in password change)
3. If verification succeeds:
   - The new email is hashed with the local salt
   - A new salt is generated
   - The password is hashed with the new email hash and new salt
   - The user's unique key is re-encrypted with the new password hash
   - The database is updated with the new hashed email, encrypted key, and salt
4. The process includes email verification steps to ensure the user owns the new email address

## Security Features

- All sensitive data (emails, passwords, website credentials) are hashed or encrypted before storage
- Each user has a unique salt, enhancing security against rainbow table attacks
- The encryption key for website credentials is itself encrypted, providing an additional layer of security
- Password changes and email changes require re-encryption of the user's key, maintaining the encryption chain
- The system uses a combination of hashing (for emails and passwords) and symmetric encryption (for storing the key and website credentials)



