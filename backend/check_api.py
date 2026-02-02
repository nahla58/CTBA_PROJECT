import requests
import json

r = requests.get('http://localhost:8000/api/cves?limit=200')
data = r.json()
cves = data.get('cves', [])

print(f"Nombre total de CVEs retournés: {len(cves)}")

# Distribution par source
sources = {}
for cve in cves:
    source = cve.get('source_primary', 'unknown')
    sources[source] = sources.get(source, 0) + 1

print(f"\nDistribution par source_primary:")
for source, count in sorted(sources.items()):
    print(f"  {source}: {count}")

# Vérifier si les CVEs de CVE.org sont présents
cveorg_cves = [c for c in cves if c.get('source_primary') == 'cveorg']
print(f"\nCVEs avec source_primary='cveorg': {len(cveorg_cves)}")
if cveorg_cves:
    print("Exemples:")
    for cve in cveorg_cves[:3]:
        print(f"  - {cve.get('cve_id')}: {cve.get('affected_products')}")
