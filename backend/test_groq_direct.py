"""
Test direct de l'API Groq pour diagnostiquer l'erreur 400
"""

import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv('GROQ_API_KEY')
GROQ_MODEL = os.getenv('GROQ_MODEL', 'mixtral-8x7b-32768')

print(f"🔑 API Key: {GROQ_API_KEY[:20]}..." if GROQ_API_KEY else "❌ Pas de clé API")
print(f"🤖 Model: {GROQ_MODEL}")
print()

# Test 1: Requête minimale
print("=" * 60)
print("TEST 1: Requête minimale")
print("=" * 60)

headers = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

payload = {
    "model": GROQ_MODEL,
    "messages": [
        {
            "role": "user",
            "content": "Hello, say hi!"
        }
    ],
    "max_tokens": 50
}

print(f"📤 Payload: {json.dumps(payload, indent=2)}")
print()

try:
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=30
    )
    
    print(f"📊 Status: {response.status_code}")
    print(f"📋 Response headers: {dict(response.headers)}")
    print()
    
    if response.status_code != 200:
        print("❌ ERREUR DÉTAILLÉE:")
        try:
            error_json = response.json()
            print(json.dumps(error_json, indent=2))
        except:
            print(response.text)
    else:
        result = response.json()
        print("✅ SUCCÈS:")
        print(json.dumps(result, indent=2))
        
except Exception as e:
    print(f"❌ Exception: {e}")

print()
print("=" * 60)
print("TEST 2: Avec system message")
print("=" * 60)

payload2 = {
    "model": GROQ_MODEL,
    "messages": [
        {
            "role": "system",
            "content": "Tu es un assistant."
        },
        {
            "role": "user",
            "content": "Dis bonjour en français."
        }
    ],
    "max_tokens": 100,
    "temperature": 0.7
}

print(f"📤 Payload: {json.dumps(payload2, indent=2)}")
print()

try:
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=payload2,
        timeout=30
    )
    
    print(f"📊 Status: {response.status_code}")
    
    if response.status_code != 200:
        print("❌ ERREUR DÉTAILLÉE:")
        try:
            error_json = response.json()
            print(json.dumps(error_json, indent=2))
        except:
            print(response.text)
    else:
        result = response.json()
        print("✅ SUCCÈS:")
        if 'choices' in result:
            print(result['choices'][0]['message']['content'])
        
except Exception as e:
    print(f"❌ Exception: {e}")

print()
print("=" * 60)
print("TEST 3: Liste des modèles disponibles")
print("=" * 60)

try:
    response = requests.get(
        "https://api.groq.com/openai/v1/models",
        headers=headers,
        timeout=10
    )
    
    print(f"📊 Status: {response.status_code}")
    
    if response.status_code == 200:
        models = response.json()
        print("✅ Modèles disponibles:")
        if 'data' in models:
            for model in models['data']:
                print(f"  - {model.get('id', 'N/A')}")
    else:
        print(f"❌ Erreur: {response.text[:500]}")
        
except Exception as e:
    print(f"❌ Exception: {e}")
