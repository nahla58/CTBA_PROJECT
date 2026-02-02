#!/usr/bin/env python3
"""
Diagnostic script to check CVSS scores and dates in database
"""
import sqlite3
import os

DB_PATH = 'ctba_platform.db'

if not os.path.exists(DB_PATH):
    print(f"Database {DB_PATH} not found")
    exit(1)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check the cves table structure
print("=" * 80)
print("TABLE STRUCTURE")
print("=" * 80)
cursor.execute("PRAGMA table_info(cves)")
for row in cursor.fetchall():
    print(f"  {row['name']:25} {row['type']:15} {'NOT NULL' if row['notnull'] else ''}")

# Get sample CVEs with CVSS scores
print("\n" + "=" * 80)
print("SAMPLE CVEs - ALL SOURCES (First 20)")
print("=" * 80)
cursor.execute("""
    SELECT cve_id, source_primary, severity, cvss_score, cvss_version, published_date, last_updated
    FROM cves 
    WHERE status = 'PENDING'
    ORDER BY last_updated DESC
    LIMIT 20
""")

for cve in cursor.fetchall():
    print(f"\n{cve['cve_id']:15} | Source: {cve['source_primary']:12} | Severity: {cve['severity']:8}")
    print(f"  CVSS Score: {cve['cvss_score']!r:20} (type: {type(cve['cvss_score']).__name__})")
    print(f"  CVSS Version: {cve['cvss_version']!r}")
    print(f"  Published: {cve['published_date']}")
    print(f"  Last Updated: {cve['last_updated']}")

# Count CVEs by source
print("\n" + "=" * 80)
print("CVE COUNT BY SOURCE")
print("=" * 80)
cursor.execute("""
    SELECT source_primary, COUNT(*) as count, 
           AVG(CAST(cvss_score AS FLOAT)) as avg_cvss,
           COUNT(CASE WHEN cvss_score IS NULL OR cvss_score = 0 THEN 1 END) as null_cvss
    FROM cves
    WHERE status = 'PENDING'
    GROUP BY source_primary
    ORDER BY count DESC
""")

for row in cursor.fetchall():
    print(f"{row['source_primary']:15} | Count: {row['count']:3} | Avg CVSS: {row['avg_cvss'] or 'None':6} | NULL/0: {row['null_cvss']}")

# Check CVEs with no CVSS score
print("\n" + "=" * 80)
print("CVEs WITH NO CVSS SCORE (NULL or 0) - First 10")
print("=" * 80)
cursor.execute("""
    SELECT cve_id, source_primary, cvss_score, published_date
    FROM cves
    WHERE (cvss_score IS NULL OR cvss_score = 0)
    AND status = 'PENDING'
    LIMIT 10
""")

for cve in cursor.fetchall():
    print(f"{cve['cve_id']:15} | Source: {cve['source_primary']:12} | CVSS: {cve['cvss_score']!r} | Published: {cve['published_date']}")

# Check date formats
print("\n" + "=" * 80)
print("DATE FORMAT CHECK (Last 5 CVEs)")
print("=" * 80)
cursor.execute("""
    SELECT cve_id, published_date, last_updated
    FROM cves
    WHERE status = 'PENDING'
    ORDER BY last_updated DESC
    LIMIT 5
""")

for cve in cursor.fetchall():
    print(f"\n{cve['cve_id']}")
    print(f"  published_date: {cve['published_date']!r}")
    print(f"  last_updated: {cve['last_updated']!r}")

conn.close()
print("\n" + "=" * 80)
