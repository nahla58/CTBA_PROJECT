"""Test MSRC avec données historiques réelles"""
import logging
logging.basicConfig(level=logging.INFO)

from app.ingestion.msrc_importer import MSRCImporter

print("=== Test MSRC avec données 2025 ===\n")

msrc = MSRCImporter(timeout=30)

# Tester avec décembre 2025 et janvier 2026
for year, month in [(2025, 12), (2026, 1), (2025, 11)]:
    print(f"\nTest {year}-{month:02d}:")
    cves = msrc.get_monthly_bulletins(year, month)
    print(f"   ✓ {len(cves)} CVEs trouvés")
    
    if cves:
        cve = cves[0]
        print(f"   Premier CVE: {cve.get('id')} - CVSS: {cve.get('cvss')}")
        break

print("\n=== Test terminé ===")
