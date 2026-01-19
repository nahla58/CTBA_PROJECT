import os
from dotenv import load_dotenv
import requests
import json

load_dotenv()
token = os.environ.get('CVEDETAILS_API_TOKEN')

print(f"Token present: {bool(token)}")

# Test the exact endpoint your code uses
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
params = {
    'query': '*',
    'page': 1,
    'limit': 20,
    'orderby': 'date',
    'order': 'desc'
}

url = "https://www.cvedetails.com/api/v1/vulnerability/search"

try:
    print(f"\nFetching from: {url}")
    print(f"Params: {params}")
    
    resp = requests.get(url, headers=headers, params=params, timeout=10)
    print(f"Status Code: {resp.status_code}")
    
    data = resp.json()
    print(f"\nResponse Keys: {list(data.keys())}")
    print(f"Response Structure: {json.dumps({k: type(v).__name__ for k, v in data.items()}, indent=2)}")
    
    # Check if results key exists
    if 'results' in data:
        results = data['results']
        print(f"\n✅ Found 'results' key with {len(results)} items")
        
        if results:
            print(f"\n📋 First CVE structure:")
            print(json.dumps(results[0], indent=2, default=str)[:500])
            
            # Check for CVE ID field
            first_cve = results[0]
            cve_id = first_cve.get('id') or first_cve.get('cve_id') or first_cve.get('cve')
            print(f"\n🔍 CVE ID extracted as: {cve_id}")
            
            # List all CVE IDs
            print(f"\n📊 All CVE IDs in response:")
            for i, cve in enumerate(results[:10], 1):
                cve_id_val = cve.get('id') or cve.get('cve_id') or cve.get('cve')
                print(f"  {i}. {cve_id_val}")
    else:
        print(f"\n⚠️ No 'results' key found in response")
        print(f"Available keys: {list(data.keys())}")
        
except Exception as e:
    print(f"\n❌ Error: {str(e)}")
    import traceback
    traceback.print_exc()
