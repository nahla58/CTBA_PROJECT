#!/usr/bin/env python3
"""Test le cycle d'importation avec CVE.org intégré"""
import sys
sys.path.insert(0, 'c:\\ctba_project\\backend')

from main import import_from_nvd, import_from_cvedetails, import_from_cveorg

print("\n" + "="*60)
print("TEST DU CYCLE D'IMPORTATION MULTI-SOURCE")
print("="*60)

print("\n[1/3] Execution NVD importer...")
result_nvd = import_from_nvd()
print("Resultat NVD: " + str(result_nvd) + "\n")

print("[2/3] Execution CVE Details importer...")
result_cvedetails = import_from_cvedetails()
print("Resultat CVE Details: " + str(result_cvedetails) + "\n")

print("[3/3] Execution CVE.org importer (NEW)...")
result_cveorg = import_from_cveorg()
print("Resultat CVE.org: " + str(result_cveorg) + "\n")

print("="*60)
print("Cycle d'importation complet!")
print("="*60)
print("NVD: " + str(result_nvd))
print("CVE Details: " + str(result_cvedetails))
print("CVE.org: " + str(result_cveorg))
print("="*60)
