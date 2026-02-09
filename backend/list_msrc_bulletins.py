"""Voir le format des bulletins MSRC"""
import requests
import json

url = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
response = requests.get(url, timeout=30, headers={
    'User-Agent': 'CTBA-CVE-Platform/2.0',
    'Accept': 'application/json'
})

data = response.json()
updates = data.get('value', [])

print(f"=== MSRC Bulletins disponibles (derniers 20) ===\n")
for update in updates[-20:]:
    print(f"ID: {update.get('ID')}  |  Date: {update.get('InitialReleaseDate')}  |  Titre: {update.get('DocumentTitle', '')[:50]}")

print(f"\nTotal: {len(updates)} bulletins disponibles")
