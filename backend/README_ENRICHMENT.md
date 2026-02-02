# 🔄 Enrichissement CVE.org - Guide Rapide

## Qu'est-ce que l'enrichissement CVE.org ?

L'enrichissement CVE.org améliore automatiquement la qualité des données CVE en intégrant les informations officielles de MITRE :
- ✅ **Produits affectés** précis (vendor + product)
- ✅ **Dates de publication** officielles
- ✅ **Dates de mise à jour** actualisées

## 🚀 Utilisation Rapide

### 1. Enrichissement automatique
L'enrichissement se fait automatiquement toutes les 30 minutes après l'import des CVEs. Aucune action requise !

### 2. Enrichissement manuel via l'interface web

**Enrichir tous les CVEs en attente (max 100) :**
```bash
POST http://localhost:8000/api/cves/enrich-from-cveorg?limit=100
```

**Enrichir des CVEs spécifiques :**
```bash
POST http://localhost:8000/api/cves/enrich-from-cveorg?cve_ids=CVE-2024-1234,CVE-2024-5678
```

### 3. Test de l'enrichissement

Exécutez le script de test :
```bash
cd backend
python test_cve_enrichment.py
```

## 📊 Vérifier les résultats

### Via l'interface web
1. Accédez au tableau de bord : http://localhost:3000
2. Consultez la colonne "PRODUITS AFFECTÉS"
3. Vérifiez les dates de publication et mise à jour

### Via la base de données
```sql
-- Vérifier les CVEs enrichis
SELECT cve_id, source, published_date, last_updated
FROM cves
WHERE source LIKE '%cveorg%'
LIMIT 10;

-- Vérifier les produits enrichis
SELECT cve_id, vendor, product, confidence
FROM affected_products
WHERE confidence = 1.0  -- Confiance maximale = CVE.org
LIMIT 20;
```

## 📈 Performance

- **1 CVE** : ~0.6 seconde
- **50 CVEs** : ~30 secondes
- **100 CVEs** : ~60 secondes

## 🔍 Logs

Les logs d'enrichissement se trouvent dans la console du backend :
```
🚀 Démarrage de l'enrichissement CVE.org...
📊 100 CVEs à enrichir
✅ CVE-2024-1234: +5 produits, dates: 1
✅ Enrichissement terminé en 45.2s
```

## ⚙️ Configuration

Aucune configuration nécessaire ! L'API CVE.org est publique et gratuite.

Les paramètres par défaut :
- Rate limit : 600ms entre chaque requête
- Timeout : 10 secondes par requête
- Batch size : 50 CVEs par lot

## 📚 Documentation complète

Pour plus de détails, consultez [CVE_ORG_ENRICHMENT.md](../CVE_ORG_ENRICHMENT.md)

## 🆘 En cas de problème

1. **CVE non trouvé (404)** : Normal pour les CVEs très récents qui ne sont pas encore dans CVE.org
2. **Rate limit (429)** : Le service attend automatiquement 2 secondes puis réessaie
3. **Timeout** : Le CVE est skippé automatiquement

Les erreurs sont loggées mais n'interrompent pas le processus d'enrichissement global.

---

**Astuce** : Pour un enrichissement plus rapide, limitez le nombre de CVEs avec le paramètre `?limit=50`
