import requests
import json

response = requests.post('http://localhost:8000/api/auth/login', json={
    'username': 'analyst1',
    'password': 'password123'
})

print("Status:", response.status_code)
if response.status_code == 200:
    data = response.json()
    print("✅ Login successful!")
    print(f"   Username: {data['username']}")
    print(f"   Role: {data['role']}")
    print(f"   Token: {data['access_token'][:50]}...")
else:
    print("❌ Login failed!")
    print("Error:", response.json())
