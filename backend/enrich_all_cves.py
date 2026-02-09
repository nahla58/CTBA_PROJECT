"""
Script pour enrichir TOUS les CVEs non enrichis avec CVE.org
"""
import sys
import os

# Ajouter le chemin du backend
backend_path = os.path.dirname(os.path.abspath(__file__))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from services.cve_enrichment_service import CVEEnrichmentService
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

print("="*70)
print("🔄 ENRICHISSEMENT COMPLET CVE.org")
print("="*70)

# Enrichir tous les CVEs PENDING sans limite
logger.info("🚀 Démarrage de l'enrichissement complet...")
stats = CVEEnrichmentService.enrich_all_pending_cves(limit=None)  # None = tous

print("\n" + "="*70)
print("✅ ENRICHISSEMENT TERMINÉ")
print("="*70)
print(f"CVEs traités: {stats['total_processed']}")
print(f"Produits ajoutés: {stats['total_products_added']}")
print(f"Dates mises à jour: {stats['total_dates_updated']}")
print(f"Erreurs: {stats['total_errors']}")
print(f"Durée: {stats['duration']:.1f}s")
print("="*70)
