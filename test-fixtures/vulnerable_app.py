# Deliberately vulnerable test file — used to verify the Precogs scanner works
# DO NOT use in production

import sqlite3

# Secret: hardcoded database URL
DATABASE_URL = "mongodb+srv://admin:password123@cluster0.example.net/production"

# Secret: generic password
API_SECRET = "super_secret_api_key_12345_production"

# PII: SSN
customer_ssn = "123-45-6789"

# Vulnerability: SQL injection
def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchone()

# Secret: JWT token (fake)
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
