#!/usr/bin/env python
import sqlite3
from datetime import datetime
import pytz
import hashlib
import binascii
import os

def _hash_password(password: str) -> tuple:
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

# Initialize database
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Create tables
cursor.execute('''
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        description TEXT,
        severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
        cvss_score REAL,
        cvss_version TEXT DEFAULT 'N/A',
        published_date TEXT,
        status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'DEFERRED')),
        analyst TEXT,
        decision_date TIMESTAMP,
        decision_comments TEXT,
        imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source TEXT DEFAULT 'NVD',
        source_primary TEXT DEFAULT 'NVD',
        sources_secondary JSON DEFAULT '[]'
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS affected_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        confidence REAL DEFAULT 0.0,
        FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
        UNIQUE(cve_id, vendor, product)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS technologies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('OUT_OF_SCOPE', 'PRIORITY', 'NORMAL')),
        added_by TEXT DEFAULT 'system',
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        UNIQUE(vendor, product)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('VOC_L1', 'VOC_LEAD', 'ADMINISTRATOR', 'MANAGER')),
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS cve_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        action TEXT CHECK(action IN ('ACCEPTED', 'REJECTED', 'DEFERRED')),
        analyst TEXT NOT NULL,
        comments TEXT,
        action_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
    )
''')

conn.commit()

# Now insert test data
test_cves = [
    {
        'cve_id': 'CVE-2026-1100',
        'description': 'A critical remote code execution vulnerability has been discovered in the PHP runtime engine. This affects all versions before 8.3.0. Attackers can execute arbitrary code with high privileges.',
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'cvss_version': '3.1',
        'published_date': '2026-01-18T10:00:00Z',
        'status': 'PENDING'
    },
    {
        'cve_id': 'CVE-2026-1101',
        'description': 'A critical vulnerability in Apache HTTP Server allows unauthenticated remote attackers to bypass authentication and execute arbitrary code. This affects versions 2.4.0 through 2.4.56.',
        'severity': 'CRITICAL',
        'cvss_score': 9.1,
        'cvss_version': '3.1',
        'published_date': '2026-01-17T14:30:00Z',
        'status': 'PENDING'
    },
    {
        'cve_id': 'CVE-2026-1102',
        'description': 'A high severity vulnerability in OpenSSL allows attackers to trigger a denial of service attack. The vulnerability exists in the TLS processing module.',
        'severity': 'HIGH',
        'cvss_score': 8.6,
        'cvss_version': '3.1',
        'published_date': '2026-01-18T11:00:00Z',
        'status': 'PENDING'
    },
    {
        'cve_id': 'CVE-2026-1103',
        'description': 'A high severity vulnerability in Nginx HTTP Server allows authenticated users to bypass security restrictions. This vulnerability is present in versions 1.19 and later.',
        'severity': 'HIGH',
        'cvss_score': 7.8,
        'cvss_version': '3.1',
        'published_date': '2026-01-16T09:15:00Z',
        'status': 'PENDING'
    },
    {
        'cve_id': 'CVE-2026-1104',
        'description': 'A medium severity vulnerability in MySQL Server allows local attackers to cause denial of service through specially crafted SQL statements.',
        'severity': 'MEDIUM',
        'cvss_score': 6.5,
        'cvss_version': '3.1',
        'published_date': '2026-01-18T12:00:00Z',
        'status': 'PENDING'
    },
    {
        'cve_id': 'CVE-2026-1105',
        'description': 'A medium severity vulnerability in PostgreSQL allows remote authenticated users to read sensitive data from the database.',
        'severity': 'MEDIUM',
        'cvss_score': 6.2,
        'cvss_version': '3.1',
        'published_date': '2026-01-15T16:45:00Z',
        'status': 'PENDING'
    },
    {
        'cve_id': 'CVE-2026-1106',
        'description': 'A low severity vulnerability in Curl library allows information disclosure through improper error handling.',
        'severity': 'LOW',
        'cvss_score': 4.3,
        'cvss_version': '3.1',
        'published_date': '2026-01-14T08:30:00Z',
        'status': 'PENDING'
    }
]

# Mapping of products per CVE
product_mapping = {
    'CVE-2026-1100': [('PHP', 'PHP'), ('Zend', 'Zend Engine')],
    'CVE-2026-1101': [('Apache', 'Apache HTTP Server'), ('Apache Software Foundation', 'httpd')],
    'CVE-2026-1102': [('OpenSSL', 'OpenSSL'), ('OpenSSL Project', 'OpenSSL Cryptography Library')],
    'CVE-2026-1103': [('Nginx', 'Nginx'), ('Nginx Inc', 'Nginx HTTP Server')],
    'CVE-2026-1104': [('MySQL', 'MySQL'), ('Oracle', 'MySQL Server')],
    'CVE-2026-1105': [('PostgreSQL', 'PostgreSQL'), ('PostgreSQL Global Development Group', 'PostgreSQL Database')],
    'CVE-2026-1106': [('Curl', 'Curl'), ('Daniel Stenberg', 'libcurl')]
}

for cve in test_cves:
    try:
        cursor.execute(
            '''INSERT INTO cves 
            (cve_id, description, severity, cvss_score, cvss_version, published_date, status, imported_at, last_updated, source, source_primary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                cve['cve_id'],
                cve['description'],
                cve['severity'],
                cve['cvss_score'],
                cve['cvss_version'],
                cve['published_date'],
                cve['status'],
                datetime.now(pytz.UTC).isoformat(),
                datetime.now(pytz.UTC).isoformat(),
                'TEST',
                'TEST'
            )
        )
        
        # Add products for this CVE
        for vendor, product in product_mapping.get(cve['cve_id'], []):
            cursor.execute(
                '''INSERT INTO affected_products (cve_id, vendor, product, confidence)
                VALUES (?, ?, ?, ?)''',
                (cve['cve_id'], vendor, product, 0.9)
            )
        
        print(f"✅ Added {cve['cve_id']} ({cve['severity']}) with {len(product_mapping.get(cve['cve_id'], []))} products")
    except Exception as e:
        print(f"❌ Error adding {cve['cve_id']}: {e}")

conn.commit()
conn.close()

print("\n✅ Database initialized and test data inserted successfully!")
print("📊 Total CVEs: 7 (2 CRITICAL, 2 HIGH, 2 MEDIUM, 1 LOW)")

# Now add test users
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

test_users = [
    ('analyst1', 'password123', 'VOC_L1'),
    ('lead1', 'password123', 'VOC_LEAD'),
    ('admin', 'password123', 'ADMINISTRATOR'),
    ('manager1', 'password123', 'MANAGER')
]

for username, password, role in test_users:
    try:
        salt, hash_pwd = _hash_password(password)
        cursor.execute(
            '''INSERT INTO users (username, password_hash, password_salt, role, is_active)
            VALUES (?, ?, ?, ?, 1)''',
            (username, hash_pwd, salt, role)
        )
        print(f"✅ Added user {username} ({role})")
    except Exception as e:
        print(f"❌ Error adding user {username}: {e}")

conn.commit()
conn.close()

print("\n🌐 Check http://localhost:3000 to login")
