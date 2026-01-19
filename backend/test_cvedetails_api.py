#!/usr/bin/env python3
"""
Test script to find the correct CVE Details API endpoint
"""
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

api_token = os.environ.get('CVEDETAILS_API_TOKEN')

if not api_token:
    print("❌ CVEDETAILS_API_TOKEN not found in .env")
    exit(1)

print(f"🔑 Using token: {api_token[:30]}...")
print("\n" + "="*70)
print("Testing CVE Details API endpoints...")
print("="*70 + "\n")

# List of endpoints to test
endpoints = [
    # Version 1.0 endpoints
    ("https://www.cvedetails.com/api/v1.0/cveinfo", "GET", {}),
    ("https://www.cvedetails.com/api/v1.0/search", "GET", {"apikey": api_token, "keyword": "apache"}),
    ("https://www.cvedetails.com/api/v1.0/vulnerabilities", "GET", {"apikey": api_token, "limit": 10}),
    
    # Version 1 endpoints
    ("https://www.cvedetails.com/api/v1/cves", "GET", {"apikey": api_token, "limit": 10}),
    ("https://www.cvedetails.com/api/v1/search", "GET", {"apikey": api_token, "keyword": "apache"}),
    
    # Version 2 endpoints
    ("https://www.cvedetails.com/api/v2.0/cves", "GET", {"apikey": api_token, "limit": 10}),
    ("https://www.cvedetails.com/api/v2/cves", "GET", {"apikey": api_token, "limit": 10}),
    
    # Bearer token in header (with and without apikey param)
    ("https://www.cvedetails.com/api/v1/cves", "GET_BEARER", {"limit": 10}),
    
    # Direct endpoints without version
    ("https://www.cvedetails.com/api/cves", "GET", {"apikey": api_token, "limit": 10}),
    ("https://www.cvedetails.com/api/search", "GET", {"apikey": api_token, "keyword": "apache"}),
]

for idx, (url, method, params) in enumerate(endpoints, 1):
    print(f"[{idx}] Testing: {url}")
    print(f"    Method: {method}")
    print(f"    Params: {params}")
    
    try:
        if method == "GET_BEARER":
            headers = {"Authorization": f"Bearer {api_token}"}
            response = requests.get(url, headers=headers, params=params, timeout=5)
        else:
            response = requests.get(url, params=params, timeout=5)
        
        print(f"    Status: {response.status_code}")
        
        if response.status_code == 200:
            print(f"    ✅ SUCCESS! Response preview:")
            try:
                data = response.json()
                # Show first part of response
                if isinstance(data, dict):
                    for key in list(data.keys())[:3]:
                        print(f"       - {key}: {type(data[key])}")
                elif isinstance(data, list):
                    print(f"       List with {len(data)} items")
                    if len(data) > 0:
                        print(f"       First item: {data[0]}")
            except:
                print(f"    Response: {response.text[:200]}")
            print(f"\n    🎯 USE THIS ENDPOINT!\n")
            break
        else:
            print(f"    ❌ Error: {response.status_code}")
            
    except requests.exceptions.Timeout:
        print(f"    ❌ Timeout")
    except Exception as e:
        print(f"    ❌ Error: {str(e)}")
    
    print()

print("="*70)
print("Test complete!")
print("\nIf you found a working endpoint, share the URL with me!")
print("="*70)
