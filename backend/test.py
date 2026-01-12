# test_real_extraction.py
import requests
import json
import re

def test_real_nvd_extraction():
    """Teste l'extraction RÉELLE depuis l'API NVD"""
    
    cve_id = "CVE-2026-0669"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/{cve_id}"
    
    print(f"🔍 TEST EXTRACTION RÉELLE POUR {cve_id}")
    print("="*70)
    
    try:
        # 1. Récupérer les données depuis NVD
        print("1. 📡 Récupération depuis NVD...")
        response = requests.get(url, timeout=15)
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code != 200:
            print(f"   ❌ Erreur HTTP: {response.status_code}")
            return
        
        data = response.json()
        
        if 'vulnerabilities' not in data or not data['vulnerabilities']:
            print("   ❌ Pas de données CVE dans la réponse")
            return
        
        cve_data = data['vulnerabilities'][0]['cve']
        print(f"   ✅ Données NVD récupérées")
        
        # 2. Afficher la description
        print("\n2. 📝 DESCRIPTION (ce que dit la CVE):")
        description = ""
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                print(f"   {description[:300]}...")
                break
        
        # 3. Chercher les produits DANS TOUTE LA STRUCTURE
        print("\n3. 🔍 RECHERCHE DES PRODUITS DANS LA RÉPONSE:")
        
        # Convertir en string JSON pour recherche
        json_str = json.dumps(cve_data)
        
        # Chercher TOUTES les occurrences de CPE
        cpe_pattern = r'cpe:2\.3:[aoh]:([^:*]+):([^:*]+):'
        all_matches = re.findall(cpe_pattern, json_str)
        
        if all_matches:
            print(f"   ✅ {len(all_matches)} patterns CPE trouvés")
            
            # Afficher les 10 premiers
            print("   Exemples de CPE trouvés:")
            for i, (vendor, product) in enumerate(all_matches[:10]):
                vendor_clean = vendor.replace('_', ' ').title()
                product_clean = product.replace('_', ' ').title()
                print(f"     {i+1}. {vendor_clean}/{product_clean}")
        else:
            print("   ❌ AUCUN pattern CPE trouvé")
            
            # Chercher d'autres indicateurs
            print("\n   🔎 Recherche de noms de produits dans le JSON...")
            
            # Chercher des noms connus
            known_products = ['mediawiki', 'wordpress', 'apache', 'linux', 'windows', 
                            'php', 'python', 'mysql', 'nginx', 'docker']
            
            found = []
            for product in known_products:
                if product in json_str.lower():
                    found.append(product.title())
            
            if found:
                print(f"   ✅ Produits trouvés: {', '.join(found)}")
            else:
                print("   ❌ Aucun produit connu trouvé")
        
        # 4. Vérifier la structure spécifique des configurations
        print("\n4. 📊 STRUCTURE DES CONFIGURATIONS:")
        configurations = cve_data.get('configurations', [])
        
        if configurations:
            print(f"   Nombre de configurations: {len(configurations)}")
            
            # Explorer la première configuration
            config = configurations[0]
            nodes = config.get('nodes', [])
            print(f"   Nombre de nodes: {len(nodes)}")
            
            if nodes:
                node = nodes[0]
                print(f"   Keys dans node: {list(node.keys())}")
                
                # Chercher 'cpeMatch' ou 'cpe_match'
                cpe_matches = node.get('cpeMatch', node.get('cpe_match', []))
                print(f"   Nombre de CPE matches: {len(cpe_matches)}")
                
                if cpe_matches:
                    print("   Exemples de CPE matches:")
                    for i, cpe_match in enumerate(cpe_matches[:5]):
                        print(f"     {i+1}. {cpe_match}")
                else:
                    print("   ❌ Pas de CPE matches dans node")
        else:
            print("   ⚠️  PAS DE CONFIGURATIONS (c'est normal pour certaines CVE)")
        
        # 5. Quelle devrait être l'extraction DYNAMIQUE RÉELLE ?
        print("\n5. 🎯 CE QUE L'EXTRACTION DYNAMIQUE DEVRAIT TROUVER:")
        
        # Analyser la description pour trouver les vrais produits
        if 'mediawiki' in description.lower():
            print("   ✅ Devrait trouver: Wikimedia/MediaWiki")
        
        if 'css extension' in description.lower():
            print("   ✅ Devrait trouver: MediaWiki/CSS Extension")
        
        # Chercher les références
        references = cve_data.get('references', [])
        print(f"   Nombre de références: {len(references)}")
        
        # Chercher dans les URLs des références
        for ref in references[:3]:
            url = ref.get('url', '')
            if 'mediawiki' in url.lower():
                print(f"   ✅ Référence trouvée: {url}")
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()

def test_multiple_cves():
    """Test plusieurs CVE pour voir les patterns"""
    print("\n" + "="*70)
    print("🧪 TEST MULTIPLE CVE POUR COMPRENDRE LE PATTERN")
    print("="*70)
    
    test_cves = [
        "CVE-2026-0669",    # MediaWiki
        "CVE-2026-21856",   # Tarkov Data Manager  
        "CVE-2025-66786",   # OpenAirInterface
        "CVE-2024-99999"    # Votre CVE de test
    ]
    
    for cve_id in test_cves[:2]:  # Tester les 2 premiers
        print(f"\n🔍 {cve_id}:")
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/{cve_id}"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            if 'vulnerabilities' in data and data['vulnerabilities']:
                cve_data = data['vulnerabilities'][0]['cve']
                
                # Description
                desc = ""
                for d in cve_data.get('descriptions', []):
                    if d.get('lang') == 'en':
                        desc = d.get('value', '')[:100]
                        break
                
                # Configurations
                configs = cve_data.get('configurations', [])
                has_configs = len(configs) > 0
                
                print(f"   Description: {desc}...")
                print(f"   Configurations: {'OUI' if has_configs else 'NON'}")
                
                if has_configs:
                    # Compter les CPE
                    cpe_count = 0
                    for config in configs:
                        for node in config.get('nodes', []):
                            cpe_count += len(node.get('cpeMatch', []))
                    print(f"   CPE matches: {cpe_count}")
            else:
                print(f"   ❌ Pas de données")
                
        except Exception as e:
            print(f"   ❌ Erreur: {e}")

if __name__ == "__main__":
    test_real_nvd_extraction()
    test_multiple_cves()
    
    print("\n" + "="*70)
    print("🎯 DIAGNOSTIC FINAL:")
    print("="*70)
    print("1. Si NVD ne retourne PAS de 'configurations', alors:")
    print("   - Votre extraction NE PEUT PAS être dynamique depuis CPE")
    print("   - Il faut extraire depuis la description/references")
    
    print("\n2. Pour une extraction VRAIMENT dynamique:")
    print("   a) Chercher d'abord dans 'configurations' → 'cpeMatch'")
    print("   b) Si pas trouvé, analyser la description")
    print("   c) Si pas trouvé, analyser les URLs des références")
    print("   d) En dernier recours, utiliser des mots-clés génériques")
    
    print("\n3. Votre système actuel:")
    print("   ❌ Utilise une liste STATIQUE de produits")
    print("   ❌ N'extrait pas les vrais produits mentionnés")
    print("   ✅ Mais montre les statuts technologies (OUT_OF_SCOPE)")
    
    print("\n4. Pour corriger:")
    print("   🔧 Fournissez-moi votre fonction extract_affected_products")
    print("   🔧 Je vais la remplacer par une extraction VRAIMENT dynamique")