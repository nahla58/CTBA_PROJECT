"""Test rapide de l'import MSRC"""
import logging
logging.basicConfig(level=logging.INFO)

from app.ingestion.msrc_importer import MSRCImporter

print("=== Test MSRC Importer ===\n")

msrc = MSRCImporter(timeout=30)

print("1. Test récupération des CVEs récents...")
cves = msrc.get_latest_cves()
print(f"   ✓ {len(cves)} CVEs trouvés\n")

if cves:
    print("2. Premier CVE trouvé:")
    cve = cves[0]
    print(f"   ID: {cve.get('id')}")
    print(f"   CVSS: {cve.get('cvss')}")
    print(f"   Description: {cve.get('description', '')[:100]}...")
    print(f"   Produits: {len(cve.get('affected_products', []))}")
else:
    print("   ⚠️ Aucun CVE trouvé - vérifier l'API MSRC")

print("\n=== Test terminé ===")
