#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Delete affected products for CVEdetails CVEs
cursor.execute('DELETE FROM affected_products WHERE cve_id IN (SELECT cve_id FROM cves WHERE source LIKE ?)', ('%cvedetails%',))

# Delete CVEdetails CVEs
cursor.execute('DELETE FROM cves WHERE source LIKE ?', ('%cvedetails%',))

conn.commit()
print('✅ Deleted CVEdetails entries')
conn.close()
