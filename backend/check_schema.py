"""Check database schema"""
import sqlite3
import os

os.chdir('C:\\essai\\CTBA_PROJECT\\backend')
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Check region_mailing_lists schema
print("📊 region_mailing_lists columns:")
cursor.execute("PRAGMA table_info(region_mailing_lists)")
for row in cursor.fetchall():
    print(f"  - {row[1]} ({row[2]})")

print("\n📊 Data in region_mailing_lists:")
cursor.execute("SELECT * FROM region_mailing_lists LIMIT 2")
for row in cursor.fetchall():
    print(f"  {row}")

conn.close()
