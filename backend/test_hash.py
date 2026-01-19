import hashlib
import binascii
import os

def _hash_password(password: str) -> tuple:
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

def _verify_password(stored_salt_hex: str, stored_hash_hex: str, password: str) -> bool:
    salt = binascii.unhexlify(stored_salt_hex.encode())
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(dk).decode() == stored_hash_hex

# Test
password = "password123"
salt, hash_pwd = _hash_password(password)
print(f"Password: {password}")
print(f"Salt: {salt}")
print(f"Hash: {hash_pwd}")

# Now verify
is_correct = _verify_password(salt, hash_pwd, password)
print(f"Verify with correct password: {is_correct}")

is_wrong = _verify_password(salt, hash_pwd, "wrongpass")
print(f"Verify with wrong password: {is_wrong}")

# Check what's in database
import sqlite3
conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute('SELECT username, password_salt, password_hash FROM users WHERE username = "analyst1"')
row = cursor.fetchone()
if row:
    print(f"\nDatabase user: {row['username']}")
    print(f"Stored salt: {row['password_salt']}")
    print(f"Stored hash: {row['password_hash'][:50]}...")
    
    # Verify the password from db
    is_valid = _verify_password(row['password_salt'], row['password_hash'], "password123")
    print(f"Verify DB password: {is_valid}")
else:
    print("User not found!")

conn.close()
