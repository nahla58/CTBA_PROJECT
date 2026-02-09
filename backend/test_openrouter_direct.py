#!/usr/bin/env python3
"""Test direct de l'API OpenRouter"""

import os
import sys
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Importer le service
from ai_remediation_openrouter import get_openrouter_service

def test_openrouter():
    api_key = os.getenv('OPENROUTER_API_KEY')
    
    if not api_key:
        print("❌ OPENROUTER_API_KEY non trouvée dans .env")
        return False
    
    print(f"✅ Clé API trouvée: {api_key[:20]}...")
    
    # Initialiser le service
    service = get_openrouter_service(api_key, "anthropic/claude-3.5-sonnet")
    
    print(f"✅ Service initialisé: {service.get_model_info()}")
    
    # Test simple
    print("\n🧪 Test de génération...")
    try:
        result = service.generate_remediation(
            cve_id="CVE-2026-25582",
            description="iccDEV heap buffer overflow in CIccIO::WriteUInt16Float()",
            severity="HIGH",
            cvss_score=7.8,
            affected_products="Internationalcolorconsortium: Iccdev"
        )
        
        print("\n✅ Remédiation générée!")
        print(f"Actions immédiates: {len(result['immediate_actions'])} chars")
        print(f"Patches: {len(result['patches'])} chars")
        
        # Afficher un aperçu
        print("\n📝 Aperçu des actions immédiates:")
        print(result['immediate_actions'][:300])
        
        return True
        
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_openrouter()
    sys.exit(0 if success else 1)
