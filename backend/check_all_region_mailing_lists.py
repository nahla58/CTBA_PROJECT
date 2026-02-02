import sqlite3

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 80)
print("REGION MAILING LIST STATUS")
print("=" * 80)

# Get all regions
cursor.execute('SELECT id, name FROM regions ORDER BY name')
regions = cursor.fetchall()

print(f"\nTotal regions: {len(regions)}\n")

for region in regions:
    region_id = region['id']
    region_name = region['name']
    
    # Check if mailing list exists
    cursor.execute('''
        SELECT to_recipients, cc_recipients, bcc_recipients, active 
        FROM region_mailing_lists 
        WHERE region_id = ?
    ''', (region_id,))
    
    mailing = cursor.fetchone()
    
    print(f"📍 {region_name} (ID: {region_id})")
    
    if mailing:
        to_list = mailing['to_recipients']
        cc_list = mailing['cc_recipients']
        bcc_list = mailing['bcc_recipients']
        active = mailing['active']
        
        if to_list:
            to_count = len(to_list.split(','))
            print(f"   ✅ To: {to_count} recipient(s) - {to_list}")
        else:
            print(f"   ❌ To: NOT CONFIGURED")
        
        if cc_list:
            cc_count = len(cc_list.split(','))
            print(f"   ✅ Cc: {cc_count} recipient(s) - {cc_list}")
        
        if bcc_list:
            bcc_count = len(bcc_list.split(','))
            print(f"   ✅ Bcc: {bcc_count} recipient(s) - {bcc_list}")
        
        print(f"   Status: {'ACTIVE' if active else 'INACTIVE'}")
    else:
        print(f"   ❌ NO MAILING LIST CONFIGURED")
    
    print()

print("=" * 80)
print("SOLUTION")
print("=" * 80)

# Check which regions need configuration
cursor.execute('''
    SELECT r.id, r.name 
    FROM regions r 
    LEFT JOIN region_mailing_lists rml ON r.id = rml.region_id 
    WHERE rml.id IS NULL OR rml.to_recipients IS NULL OR rml.to_recipients = ''
''')

missing = cursor.fetchall()

if missing:
    print(f"\n⚠️  {len(missing)} region(s) need mailing list configuration:\n")
    for r in missing:
        print(f"   - {r['name']} (ID: {r['id']})")
    
    print("\nTo fix, you need to configure recipients for these regions.")
    print("Option 1: Use the mailing list management API")
    print("Option 2: Run the update script to configure all regions")
else:
    print("\n✅ All regions have mailing lists configured!")

conn.close()

print("\n" + "=" * 80)
print("Would you like me to create a script to configure APMEA region?")
