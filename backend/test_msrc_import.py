from app.ingestion.msrc_importer import MSRCImporter
import json

print("🔍 Testing MSRC Import...")

importer = MSRCImporter()
cves = importer.get_latest_cves()

print(f"\n📊 Total CVEs retrieved: {len(cves)}")

if cves:
    print("\n🔍 First 3 CVE samples:")
    for i, cve in enumerate(cves[:3]):
        print(f"\n--- CVE {i+1} ---")
        print(f"CVE ID: {cve.get('cve_id', 'MISSING')}")
        print(f"Description: {cve.get('description', 'MISSING')[:100]}...")
        print(f"CVSS Score: {cve.get('cvss_score', 'MISSING')}")
        print(f"Severity: {cve.get('severity', 'MISSING')}")
        print(f"Products: {len(cve.get('affected_products', []))} products")
        print(f"References: {len(cve.get('references', []))} refs")
        print(f"Published: {cve.get('published_date', 'MISSING')}")
        
        # Show structure
        print(f"Keys: {list(cve.keys())}")
else:
    print("❌ No CVEs retrieved!")
