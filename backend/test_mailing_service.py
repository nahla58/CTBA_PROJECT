"""Test the mailing list endpoints"""
import sys
import os
os.chdir('C:\\essai\\CTBA_PROJECT\\backend')
sys.path.insert(0, '.')

from app.services.region_mailing_service import RegionMailingService
import sqlite3

# Test service directly
service = RegionMailingService()

# Test 1: Get existing mailing list
print("✅ Test 1: Get region 1 mailing list")
try:
    ml = service.get_region_mailing(region_id=1)
    if ml:
        print(f"  Found mailing list object")
        print(f"  To: {ml.to_recipients}")
        print(f"  Cc: {ml.cc_recipients}")
        print(f"  Bcc: {ml.bcc_recipients}")
    else:
        print("  ❌ None returned - this is the problem!")
except Exception as e:
    print(f"  ❌ Error: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("\n✅ Test 2: Check database directly")
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM region_mailing_lists")
count = cursor.fetchone()[0]
print(f"  Total records in region_mailing_lists: {count}")
cursor.execute("SELECT region_id, region_name FROM region_mailing_lists LIMIT 5")
for row in cursor.fetchall():
    print(f"  - Region {row[0]}: {row[1]}")
conn.close()
