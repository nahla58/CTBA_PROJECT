import sqlite3
import hashlib
import binascii

def get_db_connection():
    conn = sqlite3.connect('ctba_platform.db')
    conn.row_factory = sqlite3.Row
    return conn

def _verify_password(stored_salt_hex: str, stored_hash_hex: str, password: str) -> bool:
    salt = binascii.unhexlify(stored_salt_hex.encode())
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(dk).decode() == stored_hash_hex

# Test like the endpoint does
username = 'analyst1'
password = 'password123'

conn = get_db_connection()
cur = conn.cursor()
cur.execute('SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ? LIMIT 1', (username,))
row = cur.fetchone()
conn.close()

if not row:
    print("User not found!")
else:
    print(f"User found: {row['username']}")
    print(f"Password salt type: {type(row['password_salt'])}")
    print(f"Password hash type: {type(row['password_hash'])}")
    print(f"Password salt: {row['password_salt']}")
    print(f"Password hash: {row['password_hash'][:50]}...")
    
    is_valid = _verify_password(row['password_salt'], row['password_hash'], password)
    print(f"Password verification: {is_valid}")
