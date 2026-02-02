import requests
import json

print("Testing API endpoint for CVE-2026-25069...")
print("=" * 80)

try:
    # Call API
    response = requests.get('http://localhost:8000/api/cves?decision=PENDING&limit=200')
    
    if response.status_code == 200:
        data = response.json()
        cves = data.get('items', [])
        
        print(f"✅ API Response: {response.status_code}")
        print(f"Total CVEs returned: {len(cves)}")
        
        # Find CVE-2026-25069
        target_cve = None
        for cve in cves:
            if cve['cve_id'] == 'CVE-2026-25069':
                target_cve = cve
                break
        
        if target_cve:
            print(f"\n✅ CVE-2026-25069 IS IN API RESPONSE!")
            print(f"   CVE ID: {target_cve['cve_id']}")
            print(f"   Severity: {target_cve['severity']}")
            print(f"   CVSS Score: {target_cve['cvss_score']}")
            print(f"   Status: {target_cve.get('status', 'N/A')}")
            print(f"   Description: {target_cve['description'][:100]}...")
        else:
            print(f"\n❌ CVE-2026-25069 NOT FOUND in API response")
            print(f"\nFirst 5 CVEs in response:")
            for i, cve in enumerate(cves[:5], 1):
                print(f"   {i}. {cve['cve_id']} - {cve['severity']} (CVSS: {cve['cvss_score']})")
    else:
        print(f"❌ API Error: {response.status_code}")
        print(f"Response: {response.text}")
        
except Exception as e:
    print(f"❌ Error calling API: {e}")
    print("\n⚠️  Make sure backend is running: python main.py")

print("\n" + "=" * 80)
print("TROUBLESHOOTING:")
print("=" * 80)
print("If CVE is in database but NOT in API response:")
print("  1. Check if backend is applying filters that exclude it")
print("  2. Check pagination (API might not return all 168 CVEs)")
print("  3. Try: http://localhost:8000/api/cves?decision=PENDING&search=CVE-2026-25069")
print("\nIf CVE IS in API response but NOT in frontend:")
print("  1. Hard refresh frontend (Ctrl+Shift+R or Ctrl+F5)")
print("  2. Check browser console for JavaScript errors")
print("  3. Check frontend filters (severity filter, search box)")
print("  4. Clear browser cache and cookies")
