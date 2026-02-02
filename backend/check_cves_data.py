#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('ctba.db')
cursor = conn.cursor()

# Vérifier le nombre total de CVEs
cursor.execute('SELECT COUNT(*) FROM cves')
total = cursor.fetchone()[0]
print(f'Total de CVEs: {total}')

# Vérifier les CVEs par statut
cursor.execute('SELECT status, COUNT(*) FROM cves GROUP BY status')
statuts = cursor.fetchall()
print(f'\nCVEs par statut:')
for status, count in statuts:
    print(f'  {status}: {count}')

# Vérifier les CVEs avec CVSS
cursor.execute('SELECT COUNT(*) FROM cves WHERE cvss_score IS NOT NULL AND cvss_score != 0')
with_cvss = cursor.fetchone()[0]
print(f'\nCVEs avec CVSS score > 0: {with_cvss}')

# Vérifier les CVEs sans CVSS
cursor.execute('SELECT COUNT(*) FROM cves WHERE cvss_score IS NULL OR cvss_score = 0')
without_cvss = cursor.fetchone()[0]
print(f'CVEs sans CVSS score: {without_cvss}')

# Voir des exemples
cursor.execute('SELECT cve_id, severity, cvss_score, cvss_version, status FROM cves LIMIT 5')
print(f'\nExemples de CVEs:')
for row in cursor.fetchall():
    print(f'  {row}')

# Vérifier les produits affectés
cursor.execute('SELECT COUNT(DISTINCT cve_id) FROM affected_products')
cves_with_products = cursor.fetchone()[0]
print(f'\nCVEs avec produits affectés: {cves_with_products}')

# Vérifier la distribution par sévérité
cursor.execute('SELECT severity, COUNT(*) FROM cves GROUP BY severity ORDER BY severity')
print(f'\nDistribution par sévérité:')
for severity, count in cursor.fetchall():
    print(f'  {severity}: {count}')

conn.close()
