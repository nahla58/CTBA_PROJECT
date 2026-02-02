import requests

r = requests.get('http://localhost:8000/api/cves?limit=200')
data = r.json()
cves = data.get('cves', [])

print(f"Total CVEs: {len(cves)}")
print(f"Premiers 50 CVEs:")
for i, cve in enumerate(cves[:50]):
    print(f"  {i+1}. {cve.get('cve_id')} - source: {cve.get('source_primary')}")

print(f"\n...après l'index 50:")
for i, cve in enumerate(cves[50:60], 51):
    print(f"  {i}. {cve.get('cve_id')} - source: {cve.get('source_primary')}")
