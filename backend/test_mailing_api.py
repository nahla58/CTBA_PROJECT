import requests
import json

BASE_URL = "http://localhost:8000"

print("🧪 Testing API Endpoints\n")
print("=" * 60)

# Test 1: Get Regions
print("\n1️⃣  Testing GET /api/regions")
try:
    response = requests.get(f"{BASE_URL}/api/regions")
    if response.status_code == 200:
        regions = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {len(regions)} regions")
        for r in regions[:3]:
            print(f"   - Region {r.get('id')}: {r.get('name')}")
    else:
        print(f"❌ Status: {response.status_code}")
except Exception as e:
    print(f"❌ Connection failed: {e}")

# Test 2: Get Mailing List for Region 6
print("\n2️⃣  Testing GET /api/regions/6/mailing-list")
try:
    response = requests.get(f"{BASE_URL}/api/regions/6/mailing-list")
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📧 Region {data.get('region_id')} ({data.get('region_name')})")
        print(f"   To: {len(data.get('to_recipients', []))} recipients")
        print(f"   Cc: {len(data.get('cc_recipients', []))} recipients")
        print(f"   Bcc: {len(data.get('bcc_recipients', []))} recipients")
    else:
        print(f"❌ Status: {response.status_code}")
        print(f"Response: {response.text[:200]}")
except Exception as e:
    print(f"❌ Connection failed: {e}")

# Test 3: Update Mailing List
print("\n3️⃣  Testing PUT /api/regions/6/mailing-list")
try:
    payload = {
        "to_recipients": ["test1@example.com", "test2@example.com"],
        "cc_recipients": ["cc@example.com"],
        "bcc_recipients": [],
        "updated_by": "api_tester"
    }
    response = requests.put(
        f"{BASE_URL}/api/regions/6/mailing-list",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"✅ Successfully updated mailing list")
        print(f"   New To recipients: {data.get('to_recipients', [])}")
    else:
        print(f"❌ Status: {response.status_code}")
        print(f"Response: {response.text[:300]}")
except Exception as e:
    print(f"❌ Connection failed: {e}")

# Test 4: Get Audit Logs
print("\n4️⃣  Testing GET /api/audit-logs")
try:
    response = requests.get(f"{BASE_URL}/api/audit-logs")
    if response.status_code == 200:
        logs = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📝 Total audit logs: {len(logs) if isinstance(logs, list) else 'N/A'}")
    else:
        print(f"❌ Status: {response.status_code}")
except Exception as e:
    print(f"❌ Connection failed: {e}")

print("\n" + "=" * 60)
print("✅ API Testing Complete!")
