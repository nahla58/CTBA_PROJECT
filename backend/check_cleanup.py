#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# CVEs from the list
cves_to_check = [
    'CVE-2026-1149', 'CVE-2026-1148', 'CVE-2026-1147', 'CVE-2026-1146',
    'CVE-2026-1145', 'CVE-2025-59355', 'CVE-2025-29847', 'CVE-2026-1144',
    'CVE-2026-1143', 'CVE-2026-1142', 'CVE-2026-1141', 'CVE-2026-1140',
    'CVE-2026-1139', 'CVE-2026-1138', 'CVE-2026-1137', 'CVE-2026-1136',
    'CVE-2026-1135', 'CVE-2026-1134', 'CVE-2026-0943', 'CVE-2026-1133'
]

print("=== Products after cleanup ===\n")
for cve_id in cves_to_check:
    cursor.execute('SELECT vendor, product FROM affected_products WHERE cve_id = ?', (cve_id,))
    products = cursor.fetchall()
    if products:
        products_str = ', '.join([f"{p['vendor']}: {p['product']}" for p in products])
        print(f"{cve_id} -> {products_str}")
    else:
        print(f"{cve_id} -> NO VALID PRODUCTS")

conn.close()
