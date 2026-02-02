"""
Quick test setup - Uses your Gmail for all regions to test bulletin sending
"""
import sqlite3

# For testing purposes, use your Gmail
TEST_EMAIL = 'messaoudinahla80@gmail.com'

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

print("=" * 80)
print("QUICK TEST SETUP - CONFIGURING ALL REGIONS WITH YOUR GMAIL")
print("=" * 80)

regions = cursor.execute('SELECT id, name FROM regions').fetchall()

for region_id, region_name in regions:
    try:
        # Check if exists
        cursor.execute('SELECT id FROM region_mailing_lists WHERE region_id = ?', (region_id,))
        existing = cursor.fetchone()
        
        if existing:
            # Update
            cursor.execute('''
                UPDATE region_mailing_lists
                SET to_recipients = ?,
                    cc_recipients = NULL,
                    bcc_recipients = NULL,
                    active = 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE region_id = ?
            ''', (TEST_EMAIL, region_id))
            action = 'UPDATED'
        else:
            # Insert
            cursor.execute('''
                INSERT INTO region_mailing_lists (region_id, to_recipients, cc_recipients, bcc_recipients, active)
                VALUES (?, ?, NULL, NULL, 1)
            ''', (region_id, TEST_EMAIL))
            action = 'CREATED'
        
        # Log in audit
        cursor.execute('''
            INSERT INTO mailing_list_audit (region_id, action, new_to_list, changed_by, reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (region_id, action, TEST_EMAIL, 'SYSTEM_TEST', 'Test configuration'))
        
        print(f"✅ {action} {region_name}: To={TEST_EMAIL}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        conn.rollback()
        continue

conn.commit()

# Verify configuration
print("\n" + "=" * 80)
print("VERIFICATION")
print("=" * 80)

cursor.execute('''
    SELECT r.name, rml.to_recipients, rml.cc_recipients, rml.bcc_recipients
    FROM regions r
    LEFT JOIN region_mailing_lists rml ON r.id = rml.region_id
    ORDER BY r.name
''')

for name, to_list, cc_list, bcc_list in cursor.fetchall():
    print(f"\n📍 {name}:")
    print(f"   To: {to_list or 'NOT CONFIGURED'}")
    print(f"   Cc: {cc_list or 'None'}")
    print(f"   Bcc: {bcc_list or 'None'}")

conn.close()

print("\n" + "=" * 80)
print("✅ TEST SETUP COMPLETE")
print("=" * 80)
print(f"\n✉️  All bulletins will be sent to: {TEST_EMAIL}")
print("\nYou can now test bulletin sending to any region!")
print("\n⚠️  For production, update with real regional email addresses using:")
print("   - setup_all_region_mailing_lists.py (edit email addresses first)")
print("   - Or use the API: PUT /api/regions/{region_id}/mailing-list")
