#!/usr/bin/env python
"""
Test script to create CVEs with multiple sources
This demonstrates the multi-source functionality
"""

import sqlite3
import json
from datetime import datetime

# Connect to database
conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 60)
print("TEST: Creating CVEs with Multiple Sources")
print("=" * 60)

# Test CVEs that will exist in multiple sources
test_cves = [
    {
        'cve_id': 'CVE-2024-1001',
        'description': 'Critical vulnerability in popular framework',
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'published_date': '2024-01-15T10:30:00Z'
    },
    {
        'cve_id': 'CVE-2024-1002',
        'description': 'High severity authentication bypass',
        'severity': 'HIGH',
        'cvss_score': 8.5,
        'published_date': '2024-02-20T14:45:00Z'
    },
    {
        'cve_id': 'CVE-2024-1003',
        'description': 'Medium severity information disclosure',
        'severity': 'MEDIUM',
        'cvss_score': 5.3,
        'published_date': '2024-03-10T08:20:00Z'
    }
]

imported_at = datetime.utcnow().isoformat()

print("\n📋 Creating base CVEs with NVD as primary source...")
for test_cve in test_cves:
    cursor.execute('''
        INSERT OR IGNORE INTO cves 
        (cve_id, description, severity, cvss_score, published_date, 
         status, imported_at, last_updated, source_primary, sources_secondary)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        test_cve['cve_id'],
        test_cve['description'],
        test_cve['severity'],
        test_cve['cvss_score'],
        test_cve['published_date'],
        'PENDING',
        imported_at,
        imported_at,
        'NVD',  # Primary source is NVD
        json.dumps([])
    ))
    print(f"  ✅ Created {test_cve['cve_id']} with NVD as primary")

conn.commit()

# Now add secondary sources
print("\n📊 Adding secondary sources to existing CVEs...")

# For CVE-2024-1001: add cvedetails and cveorg as secondary
cursor.execute('SELECT sources_secondary FROM cves WHERE cve_id = ?', ('CVE-2024-1001',))
row = cursor.fetchone()
if row:
    secondary = json.loads(row['sources_secondary'])
    secondary.append({
        'name': 'cvedetails',
        'added_at': imported_at,
        'data_enrichment': 'cvss_score,vendor_product'
    })
    secondary.append({
        'name': 'cveorg',
        'added_at': imported_at,
        'data_enrichment': 'vendor,product'
    })
    cursor.execute(
        'UPDATE cves SET sources_secondary = ? WHERE cve_id = ?',
        (json.dumps(secondary), 'CVE-2024-1001')
    )
    print(f"  ✅ CVE-2024-1001: Added cvedetails + cveorg as secondary sources")

# For CVE-2024-1002: add cvedetails as secondary
cursor.execute('SELECT sources_secondary FROM cves WHERE cve_id = ?', ('CVE-2024-1002',))
row = cursor.fetchone()
if row:
    secondary = json.loads(row['sources_secondary'])
    secondary.append({
        'name': 'cvedetails',
        'added_at': imported_at,
        'data_enrichment': 'cvss_score,vendor_product'
    })
    cursor.execute(
        'UPDATE cves SET sources_secondary = ? WHERE cve_id = ?',
        (json.dumps(secondary), 'CVE-2024-1002')
    )
    print(f"  ✅ CVE-2024-1002: Added cvedetails as secondary source")

# For CVE-2024-1003: add cveorg as secondary
cursor.execute('SELECT sources_secondary FROM cves WHERE cve_id = ?', ('CVE-2024-1003',))
row = cursor.fetchone()
if row:
    secondary = json.loads(row['sources_secondary'])
    secondary.append({
        'name': 'cveorg',
        'added_at': imported_at,
        'data_enrichment': 'vendor,product'
    })
    cursor.execute(
        'UPDATE cves SET sources_secondary = ? WHERE cve_id = ?',
        (json.dumps(secondary), 'CVE-2024-1003')
    )
    print(f"  ✅ CVE-2024-1003: Added cveorg as secondary source")

conn.commit()

# Add products from different sources
print("\n🏭 Adding products from multiple sources...")
products = {
    'CVE-2024-1001': [
        ('Apache', 'Log4j', 'NVD'),
        ('Apache', 'Log4j', 'CVEdetails'),
        ('Apache', 'Log4j', 'CVE.org'),
    ],
    'CVE-2024-1002': [
        ('Spring', 'Framework', 'NVD'),
        ('Spring', 'Framework', 'CVEdetails'),
    ],
    'CVE-2024-1003': [
        ('Nginx', 'Web Server', 'NVD'),
        ('Nginx', 'Web Server', 'CVE.org'),
    ]
}

for cve_id, prod_list in products.items():
    for vendor, product, source in prod_list:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO affected_products 
                (cve_id, vendor, product, confidence)
                VALUES (?, ?, ?, ?)
            ''', (cve_id, vendor, product, 1.0))
            print(f"  ✅ {cve_id}: Added {vendor}/{product} (from {source})")
        except Exception as e:
            print(f"  ⚠️ {cve_id}: Error adding product: {str(e)[:50]}")

conn.commit()

# Display results
print("\n" + "=" * 60)
print("📊 RESULTS - CVEs with Multiple Sources")
print("=" * 60)

cursor.execute('''
    SELECT cve_id, source_primary, sources_secondary FROM cves 
    WHERE cve_id LIKE 'CVE-2024-%'
    ORDER BY cve_id
''')

for row in cursor.fetchall():
    cve_id = row['cve_id']
    primary = row['source_primary']
    secondary_json = row['sources_secondary']
    try:
        secondary_list = json.loads(secondary_json)
        secondary_names = [s.get('name') if isinstance(s, dict) else s for s in secondary_list]
    except:
        secondary_names = []
    
    all_sources = [primary] + secondary_names
    print(f"\n{cve_id}:")
    print(f"  Primary: {primary}")
    print(f"  Secondary: {secondary_names if secondary_names else 'None'}")
    print(f"  All Sources: {' → '.join(all_sources)}")

print("\n" + "=" * 60)
print("✅ Test data created successfully!")
print("   The Dashboard should now show CVEs with MULTIPLE sources")
print("   Refresh the browser to see the updates")
print("=" * 60)

conn.close()
for row in cursor.fetchall():
    print(f"  {row[0]:20} : {row[1]}")

# Now manually test the multi-source feature
print("\n" + "=" * 70)
print("Testing multi-source source field:")
print("=" * 70)

# Simulate what the CVE Details importer will do
test_cve_id = 'CVE-2026-23829'  # This CVE exists in NVD
cursor.execute("SELECT id, source FROM cves WHERE cve_id = ?", (test_cve_id,))
result = cursor.fetchone()

if result:
    cve_id_db, current_source = result
    print(f"\nTest CVE: {test_cve_id}")
    print(f"  Current source: {current_source}")
    
    # Build combined source
    sources = set()
    if current_source:
        sources.update(current_source.split(','))
    sources.add('cvedetails')
    combined_source = ','.join(sorted(sources))
    
    print(f"  After adding cvedetails: {combined_source}")
    print(f"  Would display as multiple badges: {', '.join(sorted(sources))}")
else:
    print(f"\n{test_cve_id} not found in database")

conn.close()
