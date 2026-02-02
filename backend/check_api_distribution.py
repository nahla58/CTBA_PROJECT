import requests
import json

response = requests.get('http://localhost:8000/api/cves?status=PENDING&limit=100')
data = response.json()

# Count by source
sources_count = {}
for cve in data.get('cves', []):
    source = cve.get('source_primary', 'unknown')
    sources_count[source] = sources_count.get(source, 0) + 1

print('=== CVE Count by Source (from API) ===')
for source, count in sorted(sources_count.items(), key=lambda x: -x[1]):
    print(f'{source}: {count}')

# Find and show a CVEdetails example
print('\n=== Example CVEs from each source ===')
shown_sources = set()
for cve in data.get('cves', []):
    source = cve.get('source_primary', 'unknown')
    if source not in shown_sources:
        print(f'\n{source}: {cve.get("cve_id")}')
        shown_sources.add(source)
    if len(shown_sources) == 3:
        break
