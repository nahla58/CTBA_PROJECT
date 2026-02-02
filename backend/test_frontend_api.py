import requests

# Test with the exact same parameters as the frontend
response = requests.get('http://localhost:8000/api/cves?status=ACCEPTED&limit=10')
data = response.json()

print("=== Frontend API Call Test ===")
print(f"Total CVEs returned: {len(data.get('cves', []))}")
print()

# Show source distribution
sources = {}
for cve in data.get('cves', []):
    source = cve.get('source_primary', 'unknown')
    if source not in sources:
        sources[source] = []
    sources[source].append(cve.get('cve_id'))

print("=== Sources Found ===")
for source in sorted(sources.keys()):
    cves_list = sources[source]
    print(f"\n{source}: {len(cves_list)} CVEs")
    print(f"  Examples: {', '.join(cves_list[:3])}")

# Show first 5 CVEs with all source fields
print("\n=== First 5 CVEs - All Source Fields ===")
for cve in data.get('cves', [])[:5]:
    print(f"\n{cve.get('cve_id')}:")
    print(f"  source_primary: {cve.get('source_primary')}")
    print(f"  source: {cve.get('source')}")
    print(f"  sources_secondary: {cve.get('sources_secondary')}")
