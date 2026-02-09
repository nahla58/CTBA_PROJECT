"""
Test rapide du service OpenRouter pour la remédiation IA
"""
import os
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '')
OPENROUTER_MODEL = os.getenv('OPENROUTER_MODEL', 'anthropic/claude-3.5-sonnet')

print("=" * 60)
print("TEST OPENROUTER - Configuration")
print("=" * 60)

if not OPENROUTER_API_KEY:
    print("❌ ERREUR: OPENROUTER_API_KEY non définie dans .env")
    print("\nVeuillez ajouter votre clé dans le fichier .env:")
    print("OPENROUTER_API_KEY=sk-or-v1-...")
    exit(1)

print(f"✓ API Key trouvée: {OPENROUTER_API_KEY[:20]}...{OPENROUTER_API_KEY[-4:]}")
print(f"✓ Modèle: {OPENROUTER_MODEL}")

print("\n" + "=" * 60)
print("TEST 1: Initialisation du service")
print("=" * 60)

try:
    from ai_remediation_openrouter import OpenRouterRemediationService
    
    service = OpenRouterRemediationService(
        api_key=OPENROUTER_API_KEY,
        model=OPENROUTER_MODEL
    )
    
    print("✓ Service initialisé avec succès")
    
    # Afficher les infos du modèle
    info = service.get_model_info()
    print(f"✓ Provider: {info['provider']}")
    print(f"✓ Model: {info['model']}")
    print(f"✓ Status: {'Ready' if info['loaded'] else 'Not Ready'}")
    
except Exception as e:
    print(f"❌ Erreur d'initialisation: {e}")
    exit(1)

print("\n" + "=" * 60)
print("TEST 2: Génération de remédiation (CVE de test)")
print("=" * 60)

try:
    # CVE de test
    test_cve = {
        'cve_id': 'CVE-2024-TEST',
        'description': 'SQL Injection vulnerability in web application login form allowing unauthorized access',
        'severity': 'HIGH',
        'cvss_score': 8.5,
        'affected_products': 'WebApp v2.0'
    }
    
    print(f"\nGénération pour {test_cve['cve_id']}...")
    print(f"Description: {test_cve['description'][:60]}...")
    print(f"Sévérité: {test_cve['severity']} (CVSS: {test_cve['cvss_score']})")
    
    print("\n⏳ Appel de l'API OpenRouter (peut prendre 5-15 secondes)...")
    
    result = service.generate_remediation(
        cve_id=test_cve['cve_id'],
        description=test_cve['description'],
        severity=test_cve['severity'],
        cvss_score=test_cve['cvss_score'],
        affected_products=test_cve['affected_products']
    )
    
    print("\n✅ SUCCÈS! Remédiation générée:")
    print("\n" + "=" * 60)
    print("ACTIONS IMMEDIATES:")
    print("=" * 60)
    print(result['immediate_actions'][:300] + "...")
    
    print("\n" + "=" * 60)
    print("CORRECTIFS ET PATCHES:")
    print("=" * 60)
    print(result['patches'][:300] + "...")
    
    print("\n" + "=" * 60)
    print("✅ Test terminé avec succès!")
    print("=" * 60)
    print("\nVous pouvez maintenant:")
    print("1. Démarrer le backend: python main.py")
    print("2. Tester via l'interface web ou l'API")
    print("3. Le système utilisera automatiquement OpenRouter au lieu d'Ollama")
    
except Exception as e:
    print(f"\n❌ Erreur lors de la génération: {e}")
    print("\nVérifiez:")
    print("- Votre clé API est valide")
    print("- Vous avez des crédits OpenRouter")
    print("- Votre connexion internet fonctionne")
    exit(1)
