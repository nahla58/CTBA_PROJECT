import requests
from datetime import datetime

year = datetime.utcnow().year
month = datetime.utcnow().month
url = f'https://api.msrc.microsoft.com/cvrf/v2.0/updates/{year}-{month:02d}'

try:
    response = requests.get(url, timeout=10)
    if response.status_code == 200:
        data = response.json()
        bulletins = data.get('value', [])
        print(f'✅ MSRC API is accessible')
        print(f'📊 Found {len(bulletins)} bulletins for {year}-{month:02d}')
    else:
        print(f'⚠️ API returned {response.status_code}')
except Exception as e:
    print(f'ℹ️ MSRC API test: {type(e).__name__}: {e}')
