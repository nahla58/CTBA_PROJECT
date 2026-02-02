"""Test rapide de l'import multi-sources"""
from services.cve_fetcher_service import CVEFetcherService

print("🧪 Test de récupération multi-sources...")
results = CVEFetcherService.fetch_all_sources(days=2, limit=20)

print(f"\n📊 Résultats:")
print(f"  - NVD: {len(results['nvd'])} CVEs")
print(f"  - CVE.org enrichi: {len(results['cveorg'])} CVEs")
print(f"  - Total unique: {len(results['all'])} CVEs")

if results['all']:
    print(f"\n📋 Exemple de CVE:")
    cve = results['all'][0]
    print(f"  ID: {cve['cve_id']}")
    print(f"  Score: {cve.get('cvss_score', 0)}")
    print(f"  Source: {cve.get('source', 'Unknown')}")
    print(f"  Produits: {len(cve.get('affected_products', []))}")
