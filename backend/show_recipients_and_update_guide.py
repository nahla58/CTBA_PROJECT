"""
Show current recipients and how to update them
"""
import sqlite3

print("\n" + "="*80)
print("📧 CURRENT EMAIL RECIPIENTS FOR EACH REGION")
print("="*80)

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute('''
    SELECT r.id, r.name, rml.to_recipients, rml.cc_recipients, rml.bcc_recipients, rml.updated_at
    FROM regions r
    JOIN region_mailing_lists rml ON r.id = rml.region_id
    WHERE rml.active = 1
    ORDER BY r.name
''')

regions = cursor.fetchall()

print("\n⚠️  THESE ARE TEST EMAILS - NOT REAL ADDRESSES!\n")

for region in regions:
    print(f"🌍 Region: {region['name']} (ID: {region['id']})")
    print(f"   To:  {region['to_recipients']}")
    if region['cc_recipients']:
        print(f"   Cc:  {region['cc_recipients']}")
    if region['bcc_recipients']:
        print(f"   Bcc: {region['bcc_recipients']}")
    print(f"   Updated: {region['updated_at']}")
    print()

print("="*80)
print("❌ DO NOT PUT EMAILS IN THE CODE!")
print("="*80)
print("""
BAD PRACTICE: Hardcoding emails in source code
✗ Hard to update (requires code changes)
✗ Security risk (emails visible in code repository)
✗ Not flexible (can't change without redeploying)

GOOD PRACTICE: Store emails in database
✓ Easy to update (just change database)
✓ Secure (not in code repository)
✓ Flexible (update anytime without code changes)
✓ Can be managed via API or admin interface
""")

print("="*80)
print("✅ HOW TO UPDATE RECIPIENTS")
print("="*80)

print("""
OPTION 1: Update via SQL (Quick for testing)
────────────────────────────────────────────
Save this script and run it:
""")

print("""
# update_recipients.py
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Update EUROPE region recipients
cursor.execute('''
    UPDATE region_mailing_lists
    SET to_recipients = ?,
        cc_recipients = ?,
        bcc_recipients = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE region_id = (SELECT id FROM regions WHERE name = 'EUROPE')
''', (
    'analyst1@yourcompany.com,analyst2@yourcompany.com',  # To
    'manager@yourcompany.com',                             # Cc
    'audit@yourcompany.com'                                # Bcc
))

# Log the change
cursor.execute('''
    INSERT INTO mailing_list_audit (region_id, action, new_to_list, changed_by, reason)
    VALUES (
        (SELECT id FROM regions WHERE name = 'EUROPE'),
        'UPDATED',
        'analyst1@yourcompany.com,analyst2@yourcompany.com',
        'admin',
        'Updated to production emails'
    )
''')

conn.commit()
conn.close()
print("✅ EUROPE region recipients updated!")
""")

print("\n" + "="*80)
print("OPTION 2: Update via API (Best for production)")
print("="*80)

print("""
Use the REST API endpoint:

PUT /api/regions/{region_id}/mailing-list

Example request:
{
    "to_recipients": [
        "analyst1@yourcompany.com",
        "analyst2@yourcompany.com"
    ],
    "cc_recipients": [
        "manager@yourcompany.com"
    ],
    "bcc_recipients": [
        "audit@yourcompany.com"
    ]
}

This is the BEST way because:
✓ Creates audit log automatically
✓ Validates email addresses
✓ Can be done by admins without touching database
✓ Secure and tracked
""")

print("\n" + "="*80)
print("📋 QUICK UPDATE SCRIPT FOR ALL REGIONS")
print("="*80)

print("""
Want to update all regions at once? Create this file:
""")

# Generate a template script
template = """
# update_all_recipients.py
import sqlite3

# YOUR REAL EMAIL ADDRESSES HERE
RECIPIENTS = {
    'NORAM': {
        'to': ['john@company.com', 'sarah@company.com'],
        'cc': ['manager.noram@company.com'],
        'bcc': []
    },
    'LATAM': {
        'to': ['carlos@company.com', 'maria@company.com'],
        'cc': ['manager.latam@company.com'],
        'bcc': []
    },
    'EUROPE': {
        'to': ['pierre@company.com', 'anna@company.com'],
        'cc': ['manager.europe@company.com'],
        'bcc': []
    },
    'APMEA': {
        'to': ['kumar@company.com', 'yuki@company.com'],
        'cc': ['manager.apmea@company.com'],
        'bcc': []
    }
}

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

for region_name, emails in RECIPIENTS.items():
    to_csv = ','.join(emails['to'])
    cc_csv = ','.join(emails['cc']) if emails['cc'] else None
    bcc_csv = ','.join(emails['bcc']) if emails['bcc'] else None
    
    cursor.execute('''
        UPDATE region_mailing_lists
        SET to_recipients = ?,
            cc_recipients = ?,
            bcc_recipients = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE region_id = (SELECT id FROM regions WHERE name = ?)
    ''', (to_csv, cc_csv, bcc_csv, region_name))
    
    # Log change
    cursor.execute('''
        INSERT INTO mailing_list_audit (region_id, action, new_to_list, changed_by, reason)
        VALUES (
            (SELECT id FROM regions WHERE name = ?),
            'UPDATED',
            ?,
            'admin',
            'Updated to production emails'
        )
    ''', (region_name, to_csv))
    
    print(f"✅ Updated {region_name}: {to_csv}")

conn.commit()
conn.close()
print("\\n✅ ALL REGIONS UPDATED!")
"""

print(template)

print("\n" + "="*80)
print("💡 RECOMMENDATION")
print("="*80)

print("""
FOR NOW (Testing):
- Keep test emails (admin@region.local)
- Configure Gmail SMTP
- Test with messaoudinahla80@gmail.com

FOR PRODUCTION:
1. Get real email addresses from your team
2. Create update_all_recipients.py script above
3. Fill in YOUR real emails
4. Run: python update_all_recipients.py
5. Test with one region first
6. Then update all regions

NEVER put emails directly in source code files!
Always store them in the database.
""")

conn.close()
