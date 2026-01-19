#!/usr/bin/env python3
"""Vérifier les produits affectés après intégration CVE.org"""
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# CVEs à vérifier (ceux mentionnés par l'utilisateur)
cves_to_check = [
    'CVE-2026-1149',
    'CVE-2026-1148',
    'CVE-2026-1147',
    'CVE-2026-1146',
    'CVE-2026-1145',
    'CVE-2025-59355',
]

print("=== Produits affectés après intégration CVE.org ===\n")

for cve_id in cves_to_check:
    cursor.execute('''
        SELECT vendor, product, confidence 
        FROM affected_products 
        WHERE cve_id = ?
        ORDER BY confidence DESC
    ''', (cve_id,))
    
    rows = cursor.fetchall()
    
    if rows:
        print(f"✅ {cve_id}:")
        for row in rows:
            confidence = f" (confidence: {row['confidence']:.1f})" if row['confidence'] else ""
            print(f"   - {row['vendor']}: {row['product']}{confidence}")
    else:
        print(f"⚠️ {cve_id}: Pas de produits affectés trouvés")
    print()

conn.close()
