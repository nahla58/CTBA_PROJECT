#!/usr/bin/env python3
"""
Teste le cycle d'importation avec CVE.org intégré
"""
import sys
sys.path.insert(0, '/ctba_project/backend')

from main import import_from_nvd, import_from_cvedetails, import_from_cveorg
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

print("\n" + "="*60)
print("TEST DU CYCLE D'IMPORTATION MULTI-SOURCE")
print("="*60)

print("\n[1/3] 🚀 Exécution NVD importer...")
result_nvd = import_from_nvd()
print(f"✅ Résultat NVD: {result_nvd}\n")

print("[2/3] 🚀 Exécution CVE Details importer...")
result_cvedetails = import_from_cvedetails()
print(f"✅ Résultat CVE Details: {result_cvedetails}\n")

print("[3/3] 🚀 Exécution CVE.org importer (NEW)...")
result_cveorg = import_from_cveorg()
print(f"✅ Résultat CVE.org: {result_cveorg}\n")

print("="*60)
print("✨ Cycle d'importation complet!")
print("="*60)
print(f"NVD: {result_nvd}")
print(f"CVE Details: {result_cvedetails}")
print(f"CVE.org: {result_cveorg}")
print("="*60)
