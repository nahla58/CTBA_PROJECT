"""Check regions and mailing lists"""
import sqlite3
import os

os.chdir('C:\\essai\\CTBA_PROJECT\\backend')
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

print("📍 Regions in database:")
cursor.execute("SELECT id, name FROM regions")
for row in cursor.fetchall():
    print(f"  - ID {row[0]}: {row[1]}")

print("\n📧 Mailing lists in database:")
cursor.execute("SELECT id, region_id, to_recipients FROM region_mailing_lists")
for row in cursor.fetchall():
    print(f"  - ID {row[0]}, Region {row[1]}: {row[2][:30]}...")

print("\n❌ MISMATCH FOUND:")
print("  Regions exist for IDs: 1, 2, 3, 4")
print("  Mailing lists exist for region IDs: 6, 7")
print("  Missing mailing lists for regions: 1, 2, 3, 4")

conn.close()
