# 🧪 Instructions de Test - Enrichissement CVE.org

## Pré-requis

1. Le backend doit être démarré : `python main.py`
2. La base de données doit contenir des CVEs (lancez un import si nécessaire)

## Test 1 : Vérifier l'API

### 1.1 Vérifier la santé du service
```bash
curl http://localhost:8000/api/cves/health
```

**Résultat attendu :**
```json
{
  "success": true,
  "service": "CVE Fetcher API",
  "status": "healthy",
  "endpoints": [
    "POST /api/cves/enrich-from-cveorg",
    ...
  ]
}
```

### 1.2 Test d'enrichissement d'un CVE spécifique
```bash
curl -X POST "http://localhost:8000/api/cves/enrich-from-cveorg?cve_ids=CVE-2024-21413"
```

**Résultat attendu :**
```json
{
  "success": true,
  "message": "✅ Enrichissement CVE.org terminé en 1.2s",
  "statistics": {
    "total_processed": 1,
    "products_added": 3,
    "products_skipped": 0,
    "dates_updated": 1,
    "errors": 0,
    "duration_seconds": 1.2
  }
}
```

## Test 2 : Script de test automatisé

### 2.1 Exécuter le script de test
```bash
cd backend
python test_cve_enrichment.py
```

**Résultat attendu :**
```
🧪 TESTS D'ENRICHISSEMENT CVE.ORG
====================================
TEST 1: Récupération d'un CVE depuis CVE.org
✅ CVE CVE-2024-21413 récupéré avec succès
📦 Produits affectés: 3
   - Microsoft: Outlook

TEST 2: Enrichissement de CVEs spécifiques
📊 Statistiques d'enrichissement:
   ✅ CVEs traités: 2
   📦 Produits ajoutés: 6
   ...

✅ PASS - Fetch single CVE
✅ PASS - Enrich specific CVEs
✅ PASS - Database integration
✅ PASS - Rate limiting

🎯 Résultat global: 4/4 tests réussis
✅ Tous les tests sont passés avec succès!
```

## Test 3 : Vérification en base de données

### 3.1 Vérifier les CVEs enrichis
```sql
SELECT cve_id, source, published_date, last_updated
FROM cves
WHERE source LIKE '%cveorg%'
LIMIT 5;
```

**Résultat attendu :**
```
CVE-2024-21413 | NVD,cveorg | 2024-01-15T10:30:00Z | 2024-01-20T14:45:00Z
CVE-2024-21351 | NVD,cveorg | 2024-01-10T08:20:00Z | 2024-01-18T12:30:00Z
...
```

### 3.2 Vérifier les produits affectés
```sql
SELECT cve_id, vendor, product, confidence
FROM affected_products
WHERE cve_id = 'CVE-2024-21413';
```

**Résultat attendu :**
```
CVE-2024-21413 | Microsoft | Outlook | 1.0
CVE-2024-21413 | Microsoft | Office | 1.0
...
```

## Test 4 : Enrichissement automatique

### 4.1 Attendre le scheduler (30 minutes)
Le scheduler enrichit automatiquement les CVEs toutes les 30 minutes.

### 4.2 Vérifier les logs
```bash
# Dans les logs du backend
🔄 Démarrage enrichissement CVE.org automatique...
📊 50 CVEs à enrichir
✅ Enrichissement terminé: 150 produits, 45 dates mises à jour
```

## Test 5 : Test de charge (optionnel)

### 5.1 Enrichir 100 CVEs
```bash
curl -X POST "http://localhost:8000/api/cves/enrich-from-cveorg?limit=100"
```

**Durée attendue :** ~60 secondes

### 5.2 Vérifier la progression dans les logs
```bash
# Les logs doivent montrer:
📦 Traitement du lot 1/2
📦 Traitement du lot 2/2
✅ CVE-2024-XXXX: +3 produits, dates: 1
...
✅ Enrichissement terminé en 58.4s
```

## Test 6 : Test de robustesse

### 6.1 Test avec un CVE inexistant
```bash
curl -X POST "http://localhost:8000/api/cves/enrich-from-cveorg?cve_ids=CVE-9999-99999"
```

**Résultat attendu :**
```json
{
  "success": true,
  "statistics": {
    "total_processed": 1,
    "products_added": 0,
    "errors": 1,
    ...
  }
}
```

### 6.2 Vérifier le log d'erreur
```
CVE CVE-9999-99999 non trouvé sur CVE.org (404)
```

## Checklist de validation

- [ ] ✅ API health check fonctionne
- [ ] ✅ Enrichissement d'un CVE spécifique réussit
- [ ] ✅ Script de test automatisé passe (4/4 tests)
- [ ] ✅ Les CVEs enrichis ont `source` contenant "cveorg"
- [ ] ✅ Les produits ont une confiance de 1.0
- [ ] ✅ Les dates sont au format ISO 8601
- [ ] ✅ Le rate limiting fonctionne (~0.6s par CVE)
- [ ] ✅ Les erreurs sont gérées proprement (pas de crash)
- [ ] ✅ Les logs sont clairs et informatifs

## Problèmes connus

### CVE non trouvé (404)
**Cause :** CVE trop récent, pas encore dans CVE.org  
**Solution :** Normal, le CVE sera enrichi plus tard

### Rate limit (429)
**Cause :** Trop de requêtes à CVE.org  
**Solution :** Le service attend automatiquement 2 secondes

### Timeout
**Cause :** Réseau lent ou CVE.org indisponible  
**Solution :** Le CVE est skippé, réessayez plus tard

## Support

En cas de problème :
1. Vérifier les logs du backend
2. Vérifier que l'API CVE.org est accessible : `curl https://cveawg.mitre.org/api/cve/CVE-2024-21413`
3. Réduire le `limit` pour tester avec moins de CVEs
4. Consulter la documentation complète : [CVE_ORG_ENRICHMENT.md](../CVE_ORG_ENRICHMENT.md)

---

**Note :** Tous les tests doivent passer pour valider l'intégration complète de l'enrichissement CVE.org.
