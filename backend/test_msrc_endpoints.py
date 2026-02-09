"""Test des endpoints MSRC disponibles"""
import requests
import json

print("=== Test des endpoints MSRC ===\n")

endpoints = [
    "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
    "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    "https://api.security.microsoft.com/api/vulnerabilities",
    "https://api.msrc.microsoft.com/sug/v2.0/updates",
]

for url in endpoints:
    print(f"\nTest: {url}")
    try:
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'CTBA-CVE-Platform/2.0',
            'Accept': 'application/json'
        })
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   ✓ API disponible!")
            print(f"   Contenu: {response.text[:200]}...")
    except Exception as e:
        print(f"   ✗ Erreur: {e}")

print("\n=== Test terminé ===")
