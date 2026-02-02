import sqlite3
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
db_path = 'ctba_platform.db'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get data from region_mailing_lists
cursor.execute("SELECT COUNT(*) FROM region_mailing_lists")
total_records = cursor.fetchone()[0]
print(f"✅ Total records: {total_records}")

# Show sample
print("\n📧 Mailing Lists by Region:")
cursor.execute("""
    SELECT region_id, 
           COALESCE(to_recipients, '') as to_list,
           COALESCE(cc_recipients, '') as cc_list,
           COALESCE(bcc_recipients, '') as bcc_list
    FROM region_mailing_lists
    ORDER BY region_id
""")

for row in cursor.fetchall():
    region_id = row[0]
    to_count = len([x for x in row[1].split(',') if x.strip()]) if row[1] else 0
    cc_count = len([x for x in row[2].split(',') if x.strip()]) if row[2] else 0
    bcc_count = len([x for x in row[3].split(',') if x.strip()]) if row[3] else 0
    print(f"  Region {region_id}: To={to_count}, Cc={cc_count}, Bcc={bcc_count}")

conn.close()
print("\n✅ Database populated successfully!")

