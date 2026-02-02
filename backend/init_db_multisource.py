#!/usr/bin/env python3
"""
Initialize database with test CVEs that have intentional overlaps between sources
to properly test multi-source functionality
"""

import sqlite3
import json
from datetime import datetime, timedelta
import pytz

# Create database
db_path = 'ctba_platform.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("Initializing database with test CVEs for multi-source testing...")

# Create tables
cursor.executescript('''
    DROP TABLE IF EXISTS cves;
    DROP TABLE IF EXISTS affected_products;
    DROP TABLE IF EXISTS users;
    
    CREATE TABLE cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        description TEXT,
        severity TEXT DEFAULT 'MEDIUM',
        cvss_score REAL,
        cvss_version TEXT,
        published_date TEXT,
        status TEXT DEFAULT 'PENDING',
        analyst TEXT,
        decision_date TEXT,
        decision_comments TEXT,
        imported_at TEXT,
        last_updated TEXT,
        source TEXT,
        source_primary TEXT DEFAULT 'NVD',
        sources_secondary JSON DEFAULT '[]'
    );
    
    CREATE TABLE affected_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        confidence REAL DEFAULT 0.5,
        UNIQUE(cve_id, vendor, product),
        FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
    );
    
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'analyst'
    );
''')

# Helper function
def add_cve(cve_id, source_primary, description, vendor, product, severity='MEDIUM', cvss=5.0):
    """Add a CVE with affected products"""
    imported_at = datetime.now(pytz.UTC).isoformat()
    cursor.execute('''
        INSERT INTO cves (
            cve_id, description, severity, cvss_score, cvss_version,
            published_date, source_primary, sources_secondary, imported_at,
            last_updated, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        cve_id,
        description,
        severity,
        cvss,
        '3.1',
        (datetime.now() - timedelta(days=7)).isoformat(),
        source_primary,
        json.dumps([]),
        imported_at,
        imported_at,
        'PENDING'
    ))
    
    # Add affected product
    cursor.execute('''
        INSERT INTO affected_products (cve_id, vendor, product, confidence)
        VALUES (?, ?, ?, ?)
    ''', (cve_id, vendor, product, 1.0))

# Add test CVEs that WILL overlap
print("\n1. Adding NVD CVEs (these will be the primary source)...")
nvd_cves = [
    ('CVE-2024-1001', 'NVD', 'SQL injection in Apache server', 'Apache', 'Apache HTTP Server', 'HIGH', 7.5),
    ('CVE-2024-1002', 'NVD', 'Buffer overflow in OpenSSL', 'OpenSSL', 'OpenSSL', 'CRITICAL', 9.8),
    ('CVE-2024-1003', 'NVD', 'RCE in Nginx', 'Nginx', 'Nginx', 'HIGH', 8.0),
    ('CVE-2024-1004', 'NVD', 'XSS in WordPress', 'WordPress', 'WordPress', 'MEDIUM', 6.1),
    ('CVE-2024-1005', 'NVD', 'SSRF in Django', 'Django', 'Django', 'MEDIUM', 5.0),
]

for cve_id, source, desc, vendor, product, severity, cvss in nvd_cves:
    add_cve(cve_id, source, desc, vendor, product, severity, cvss)
    print(f"  ✓ {cve_id} ({vendor}/{product})")

print(f"Added {len(nvd_cves)} NVD CVEs")

# Add cvedetails CVEs (some overlap with NVD)
print("\n2. Adding CVEdetails CVEs (2 will overlap with NVD)...")
cvedetails_cves = [
    ('CVE-2024-1001', 'cvedetails', 'SQL injection in Apache server', 'Apache', 'Apache Tomcat', 'HIGH', 7.5),  # OVERLAP
    ('CVE-2024-1002', 'cvedetails', 'OpenSSL Vulnerability', 'OpenSSL', 'OpenSSL Library', 'CRITICAL', 9.8),  # OVERLAP
    ('CVE-2024-2001', 'cvedetails', 'PHP Code Execution', 'PHP', 'PHP', 'HIGH', 8.5),
    ('CVE-2024-2002', 'cvedetails', 'Java Spring RCE', 'Spring', 'Spring Framework', 'CRITICAL', 9.0),
]

added = 0
for cve_id, source, desc, vendor, product, severity, cvss in cvedetails_cves:
    try:
        add_cve(cve_id, source, desc, vendor, product, severity, cvss)
        print(f"  ✓ {cve_id} ({vendor}/{product})")
        added += 1
    except sqlite3.IntegrityError:
        # This CVE already exists - would be handled by secondary source logic
        print(f"  ⚠ {cve_id} ALREADY EXISTS (would be secondary source)")

print(f"Added {added} CVEdetails CVEs")

# Add TEST CVEs
print("\n3. Adding TEST CVEs...")
test_cves = [
    ('TEST-2024-001', 'test', 'Test CVE 1', 'TestVendor1', 'TestProduct1', 'MEDIUM', 5.0),
    ('TEST-2024-002', 'test', 'Test CVE 2', 'TestVendor2', 'TestProduct2', 'MEDIUM', 5.0),
    ('TEST-2024-003', 'test', 'Test CVE 3', 'TestVendor3', 'TestProduct3', 'MEDIUM', 5.0),
]

for cve_id, source, desc, vendor, product, severity, cvss in test_cves:
    add_cve(cve_id, source, desc, vendor, product, severity, cvss)
    print(f"  ✓ {cve_id} ({vendor}/{product})")

print(f"Added {len(test_cves)} TEST CVEs")

# Add test users
print("\n4. Adding test users...")
users = [
    ('admin', 'admin123', 'admin@test.com', 'admin'),
    ('analyst1', 'analyst123', 'analyst1@test.com', 'analyst'),
    ('analyst2', 'analyst123', 'analyst2@test.com', 'analyst'),
    ('viewer', 'viewer123', 'viewer@test.com', 'viewer'),
]

for username, password, email, role in users:
    try:
        cursor.execute('''
            INSERT INTO users (username, password, email, role)
            VALUES (?, ?, ?, ?)
        ''', (username, password, email, role))
        print(f"  ✓ {username} ({role})")
    except sqlite3.IntegrityError:
        print(f"  ⚠ {username} already exists")

conn.commit()

# Print summary
print("\n" + "="*60)
print("DATABASE INITIALIZATION COMPLETE")
print("="*60)

cursor.execute('SELECT COUNT(*) as count FROM cves')
total = cursor.fetchone()['count']
print(f"\nTotal CVEs: {total}")

cursor.execute('SELECT source_primary, COUNT(*) as count FROM cves GROUP BY source_primary')
print("\nCVEs by source_primary:")
for row in cursor.fetchall():
    print(f"  {row['source_primary']}: {row['count']}")

cursor.execute('SELECT cve_id, source_primary FROM cves ORDER BY cve_id')
print("\nAll CVEs:")
for row in cursor.fetchall():
    print(f"  {row['cve_id']}: {row['source_primary']}")

conn.close()
print("\n✅ Database initialized successfully!")
