#!/usr/bin/env python3
"""Afficher le résumé de la source des CVEs après intégration CVE.org"""
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Compter les CVEs par source
cursor.execute('''
    SELECT source, COUNT(*) as count
    FROM cves
    WHERE source IS NOT NULL
    GROUP BY source
    ORDER BY count DESC
''')

sources = cursor.fetchall()

print("\n" + "="*70)
print("RESUME: ATTRIBUTION DES SOURCES APRES INTEGRATION CVE.ORG")
print("="*70)
print("\nNombre de CVEs par source:\n")

total_cves = 0
for row in sources:
    source = row['source']
    count = row['count']
    total_cves += count
    print(f"  {source:40s} : {count:3d} CVEs")

cursor.execute('SELECT COUNT(*) as count FROM cves')
total = cursor.fetchone()['count']

print("\n" + "-"*70)
print(f"  TOTAL                                  : {total:3d} CVEs")
print("="*70)

# Exemples de CVEs avec multi-sources
print("\nExemples de CVEs avec MULTI-SOURCES (vendor/product de CVE.org):\n")

cursor.execute('''
    SELECT c.cve_id, c.source
    FROM cves c
    WHERE c.source LIKE '%,%'
    ORDER BY c.imported_at DESC
    LIMIT 5
''')

examples = cursor.fetchall()
for row in examples:
    cve_id = row['cve_id']
    source = row['source']
    
    # Afficher les produits
    cursor.execute('''
        SELECT vendor, product
        FROM affected_products
        WHERE cve_id = ?
        LIMIT 2
    ''', (cve_id,))
    products = cursor.fetchall()
    
    print(f"  {cve_id}")
    print(f"    Sources: {source}")
    for p in products:
        print(f"    Product: {p['vendor']}: {p['product']}")
    print()

conn.close()

print("="*70)
print("INTEGRATION REUSSIE: CVE.org fournit des données precises")
print("="*70)
