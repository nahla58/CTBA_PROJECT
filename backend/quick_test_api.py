import requests
import json

response = requests.get('http://localhost:8000/api/cves?status=PENDING&limit=3')
data = response.json()

print('=== Sample CVEs from API ===')
for cve in data.get('cves', [])[:3]:
    sources_secondary = cve.get('sources_secondary', [])
    secondary_count = len(sources_secondary) if sources_secondary else 0
    print(f"\nCVE: {cve.get('cve_id')}")
    print(f"  source_primary: {cve.get('source_primary')}")
    print(f"  sources_secondary: {secondary_count}")
