#!/usr/bin/env python3
"""
Test the API endpoint to verify sources are returned correctly
"""
import requests
import json

try:
    response = requests.get("http://localhost:8000/api/cves?limit=5", timeout=5)
    data = response.json()
    
    print("=" * 100)
    print("TEST API - Vérifier sources_list")
    print("=" * 100)
    
    for cve in data.get('data', [])[:5]:
        print(f"\n{cve['cve_id']} | {cve['source_primary']}")
        print(f"  sources_list: {cve.get('sources_list', [])}")
        print(f"  sources_secondary: {cve.get('sources_secondary', [])[:100]}")
        print(f"  last_updated: {cve.get('last_updated')[:30]}")
        print(f"  published_date: {cve.get('published_date')[:30]}")
        
except Exception as e:
    print(f"Error: {e}")
