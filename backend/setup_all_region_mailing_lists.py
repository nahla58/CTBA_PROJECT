"""
Configure mailing lists for all regions
This will set up default email recipients for bulletin delivery
"""
import sqlite3

# Default email recipients for each region
# REPLACE THESE WITH YOUR ACTUAL EMAIL ADDRESSES
RECIPIENTS = {
    'NORAM': {
        'to': ['analyst.noram@company.com', 'security.noram@company.com'],
        'cc': ['manager.noram@company.com'],
        'bcc': []
    },
    'LATAM': {
        'to': ['analyst.latam@company.com', 'security.latam@company.com'],
        'cc': ['manager.latam@company.com'],
        'bcc': []
    },
    'EUROPE': {
        'to': ['analyst.europe@company.com', 'security.europe@company.com'],
        'cc': ['manager.europe@company.com'],
        'bcc': []
    },
    'APMEA': {
        'to': ['analyst.apmea@company.com', 'security.apmea@company.com'],
        'cc': ['manager.apmea@company.com'],
        'bcc': []
    }
}

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

print("=" * 80)
print("CONFIGURING REGION MAILING LISTS")
print("=" * 80)

for region_name, emails in RECIPIENTS.items():
    try:
        # Get region ID
        cursor.execute('SELECT id FROM regions WHERE name = ?', (region_name,))
        result = cursor.fetchone()
        
        if not result:
            print(f"❌ Region {region_name} not found in database")
            continue
        
        region_id = result[0]
        
        # Convert lists to CSV
        to_csv = ','.join(emails['to'])
        cc_csv = ','.join(emails['cc']) if emails['cc'] else None
        bcc_csv = ','.join(emails['bcc']) if emails['bcc'] else None
        
        # Check if mailing list already exists
        cursor.execute('SELECT id FROM region_mailing_lists WHERE region_id = ?', (region_id,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing
            cursor.execute('''
                UPDATE region_mailing_lists
                SET to_recipients = ?,
                    cc_recipients = ?,
                    bcc_recipients = ?,
                    active = 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE region_id = ?
            ''', (to_csv, cc_csv, bcc_csv, region_id))
            
            action = 'UPDATED'
        else:
            # Insert new
            cursor.execute('''
                INSERT INTO region_mailing_lists (region_id, to_recipients, cc_recipients, bcc_recipients, active)
                VALUES (?, ?, ?, ?, 1)
            ''', (region_id, to_csv, cc_csv, bcc_csv))
            
            action = 'CREATED'
        
        # Log in audit
        cursor.execute('''
            INSERT INTO mailing_list_audit (region_id, action, new_to_list, changed_by, reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (region_id, action, to_csv, 'SYSTEM_SETUP', 'Initial configuration'))
        
        print(f"✅ {action} {region_name}:")
        print(f"   To: {to_csv}")
        if cc_csv:
            print(f"   Cc: {cc_csv}")
        if bcc_csv:
            print(f"   Bcc: {bcc_csv}")
        
    except Exception as e:
        print(f"❌ Error configuring {region_name}: {e}")
        conn.rollback()
        continue

conn.commit()
conn.close()

print("\n" + "=" * 80)
print("✅ CONFIGURATION COMPLETE")
print("=" * 80)
print("\n⚠️  IMPORTANT:")
print("The email addresses configured are EXAMPLES.")
print("You should update them with your actual email addresses:")
print()
print("Option 1: Edit this script and replace the email addresses in RECIPIENTS dictionary")
print("Option 2: Use the Mailing List Manager in the frontend UI")
print("Option 3: Use the API: PUT /api/regions/{region_id}/mailing-list")
print()
print("For testing, you can use your Gmail: messaoudinahla80@gmail.com")
