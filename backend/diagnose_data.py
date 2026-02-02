#!/usr/bin/env python
"""Diagnostic script to check data quality in ctba_platform.db"""

import sqlite3
from datetime import datetime

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 80)
print("CVE DATA QUALITY DIAGNOSTICS")
print("=" * 80)

# 1. Check dates in database
print("\n1. SAMPLE DATES FROM DATABASE:")
print("-" * 80)
cursor.execute('''
    SELECT cve_id, published_date, last_updated, source_primary 
    FROM cves 
    LIMIT 10
''')
for row in cursor.fetchall():
    print(f"{row['cve_id']} ({row['source_primary']}):")
    print(f"  pub: {row['published_date']}")
    print(f"  upd: {row['last_updated']}")

# 2. Check for date inconsistencies
print("\n\n2. DATE FORMAT ANALYSIS:")
print("-" * 80)
cursor.execute('SELECT DISTINCT substr(published_date, 1, 20) as date_format FROM cves LIMIT 10')
formats = cursor.fetchall()
print(f"Published date formats found:")
for fmt in formats:
    print(f"  - {fmt[0]}")

cursor.execute('SELECT DISTINCT substr(last_updated, 1, 20) as date_format FROM cves LIMIT 10')
formats = cursor.fetchall()
print(f"\nLast updated formats found:")
for fmt in formats:
    print(f"  - {fmt[0]}")

# 3. Check if last_updated is being set to import time
print("\n\n3. CHECK IF LAST_UPDATED IS SYNCHRONIZED:")
print("-" * 80)
cursor.execute('''
    SELECT last_updated, COUNT(*) as count
    FROM cves
    GROUP BY last_updated
    ORDER BY count DESC
    LIMIT 5
''')
rows = cursor.fetchall()
print(f"Most common last_updated values:")
for row in rows:
    print(f"  {row['last_updated']}: {row['count']} CVEs")

# 4. Check affected_products formatting
print("\n\n4. AFFECTED PRODUCTS SAMPLE:")
print("-" * 80)
cursor.execute('''
    SELECT c.cve_id, ap.vendor, ap.product
    FROM cves c
    LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
    LIMIT 15
''')
rows = cursor.fetchall()
current_cve = None
for row in rows:
    if row['cve_id'] != current_cve:
        current_cve = row['cve_id']
        print(f"\n{current_cve}:")
    if row['vendor']:
        print(f"  - {row['vendor']}: {row['product']}")
    else:
        print(f"  (no products)")

# 5. Check if products have URL formatting issues
print("\n\n5. PRODUCTS WITH UNUSUAL FORMATTING:")
print("-" * 80)
cursor.execute('''
    SELECT DISTINCT vendor, COUNT(*) as count
    FROM affected_products
    WHERE vendor LIKE '%://%' OR vendor LIKE '%.%' OR vendor LIKE 'Www%'
    GROUP BY vendor
    LIMIT 10
''')
rows = cursor.fetchall()
if rows:
    print("Products with URL-like or weird formatting:")
    for row in rows:
        print(f"  {row['vendor']}: {row['count']} occurrences")
else:
    print("No URL-like vendors found (good!)")

conn.close()
