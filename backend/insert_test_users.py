import sqlite3
import hashlib
import binascii
import os

def _hash_password(password: str) -> tuple:
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Delete old users and add new ones
cursor.execute('DELETE FROM users')

test_users = [
    ('analyst1', 'password123', 'VOC_L1'),
    ('lead1', 'password123', 'VOC_LEAD'),
    ('admin', 'password123', 'ADMINISTRATOR'),
    ('manager1', 'password123', 'MANAGER')
]

for username, password, role in test_users:
    salt, h = _hash_password(password)
    cursor.execute('INSERT INTO users (username, role, password_hash, password_salt) VALUES (?, ?, ?, ?)', 
                   (username, role, h, salt))
    print(f"✅ Inserted user: {username} ({role})")

conn.commit()
conn.close()

print("\n✅ All 4 test users inserted successfully!")
