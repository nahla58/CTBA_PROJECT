"""
Script de test pour évaluer les améliorations du modèle IA
Compare les résultats avant/après pour CVE-2026-1642 (NGINX MITM)
"""

import sys
import requests
import json
from datetime import datetime

API_URL = "http://localhost:8000"

def test_cve_remediation(cve_id: str):
    """Test génération IA pour un CVE spécifique"""
    
    print(f"\n{'='*80}")
    print(f"🧪 TEST: {cve_id}")
    print(f"{'='*80}\n")
    
    try:
        # Appel API
        print(f"⏳ Génération en cours avec Ollama...")
        start_time = datetime.now()
        
        response = requests.post(
            f"{API_URL}/api/ai/remediation/{cve_id}",
            timeout=180  # 3 minutes max
        )
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if response.status_code != 200:
            print(f"❌ Erreur HTTP {response.status_code}")
            print(response.text)
            return False
        
        result = response.json()
        remediation = result.get('remediation', {})
        
        print(f"✅ Génération terminée en {elapsed:.1f}s\n")
        
        # Afficher résultats
        print(f"📊 CVE: {result.get('cve_id')}")
        print(f"🔴 Sévérité: {result.get('severity')} (Score: {result.get('cvss_score')})")
        print(f"🤖 Modèle: {remediation.get('note', 'N/A')}\n")
        
        # Vérifier complétude
        sections = ['immediate_actions', 'patches', 'workarounds', 'verification']
        section_names = {
            'immediate_actions': '⚠️  IMMEDIATE ACTIONS',
            'patches': '🔧 PATCHES',
            'workarounds': '🛠️  WORKAROUNDS',
            'verification': '✅ VERIFICATION'
        }
        
        scores = {
            'completeness': 0,
            'length': 0,
            'security_check': True
        }
        
        for section in sections:
            content = remediation.get(section, '')
            section_name = section_names[section]
            
            if content and len(content.strip()) > 20:
                scores['completeness'] += 1
                scores['length'] += len(content)
                check_mark = "✅"
            else:
                check_mark = "❌"
            
            print(f"{check_mark} {section_name} ({len(content)} chars)")
            print(f"   {content[:100]}..." if len(content) > 100 else f"   {content}")
            print()
            
            # Vérifier recommandations dangereuses
            dangerous_keywords = ['use http://', 'disable tls', 'disable ssl', 'turn off encryption']
            content_lower = content.lower()
            for keyword in dangerous_keywords:
                if keyword in content_lower:
                    print(f"   ⚠️  ALERTE: Recommandation dangereuse détectée: '{keyword}'")
                    scores['security_check'] = False
        
        # Score final
        print(f"\n{'='*80}")
        print(f"📈 SCORE D'ÉVALUATION:")
        print(f"   Complétude: {scores['completeness']}/4 sections")
        print(f"   Longueur totale: {scores['length']} caractères")
        print(f"   Sécurité: {'✅ PASS' if scores['security_check'] else '❌ FAIL - Recommandations dangereuses'}")
        print(f"   Temps génération: {elapsed:.1f}s")
        
        quality_score = (scores['completeness'] / 4) * 100
        if not scores['security_check']:
            quality_score = 0
        
        print(f"   Score qualité: {quality_score:.0f}%")
        
        if quality_score >= 75:
            print(f"   🌟 EXCELLENT")
        elif quality_score >= 50:
            print(f"   👍 BON")
        elif quality_score >= 25:
            print(f"   ⚠️  MOYEN")
        else:
            print(f"   ❌ MAUVAIS")
        
        print(f"{'='*80}\n")
        
        return quality_score >= 50
        
    except requests.exceptions.Timeout:
        print(f"❌ Timeout après 180 secondes")
        return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def main():
    """Lance les tests sur plusieurs CVEs"""
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  TEST DES AMÉLIORATIONS DU MODÈLE IA                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Ce script teste les améliorations suivantes:
  ✅ Prompt renforcé avec contraintes de sécurité
  ✅ Validation anti-recommandations dangereuses  
  ✅ Vérification complétude (4 sections)
  ✅ Templates de secours intelligents
  ✅ Modèle llama3.1:8b (au lieu de qwen2.5:3b)
  ✅ Paramètres optimisés (temperature=0.5, num_predict=600)

""")
    
    # Vérifier que le backend est lancé
    try:
        response = requests.get(f"{API_URL}/api/ai/status", timeout=5)
        if response.status_code == 200:
            model_info = response.json().get('model_info', {})
            print(f"✅ Backend détecté")
            print(f"   Modèle: {model_info.get('model_name', 'N/A')}")
            print(f"   Framework: {model_info.get('framework', 'N/A')}\n")
        else:
            print(f"⚠️  Backend répond mais status != 200")
    except:
        print(f"❌ ERREUR: Backend non accessible sur {API_URL}")
        print(f"   Lancez d'abord: cd backend && python main.py")
        sys.exit(1)
    
    # CVEs de test
    test_cases = [
        ("CVE-2026-1642", "NGINX MITM - Le test critique (précédemment FAILED)"),
        ("CVE-2026-25579", "Navidrome XSS - CRITICAL 9.2"),
    ]
    
    results = []
    
    for cve_id, description in test_cases:
        print(f"\n📋 Test: {description}")
        success = test_cve_remediation(cve_id)
        results.append((cve_id, success))
    
    # Résumé final
    print(f"\n{'='*80}")
    print(f"📊 RÉSUMÉ DES TESTS")
    print(f"{'='*80}\n")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for cve_id, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status} - {cve_id}")
    
    print(f"\n  Résultat: {passed}/{total} tests réussis")
    
    if passed == total:
        print(f"\n  🎉 SUCCÈS COMPLET - Améliorations validées!")
    elif passed > 0:
        print(f"\n  ⚠️  SUCCÈS PARTIEL - Quelques problèmes persistent")
    else:
        print(f"\n  ❌ ÉCHEC - Améliorations insuffisantes")
    
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
