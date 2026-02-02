import requests
import json

# Test the API endpoint
url = "http://localhost:8000/api/cves?limit=15"

try:
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        cves = data.get('data', [])
        
        print("=" * 100)
        print("API TEST - First 15 CVEs")
        print("=" * 100)
        
        for cve in cves[:15]:
            cvss = cve.get('cvss_score', 'N/A')
            pub = cve.get('published_date', 'N/A')[:10] if cve.get('published_date') else 'N/A'
            print(f"{cve.get('cve_id'):15} | {cve.get('source_primary'):12} | CVSS: {cvss:5} | Severity: {cve.get('severity'):8} | {pub}")
        
        # Show distribution
        print("\n" + "=" * 100)
        sources = {}
        for cve in cves:
            src = cve.get('source_primary', 'unknown')
            sources[src] = sources.get(src, 0) + 1
        
        for src, count in sorted(sources.items(), key=lambda x: -x[1]):
            print(f"{src:15} | {count}")
    else:
        print(f"Error: {response.status_code}")
except Exception as e:
    print(f"Connection error: {e}")
