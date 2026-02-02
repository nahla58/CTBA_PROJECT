# 🔄 Enrichissement CVE.org - Documentation

## Vue d'ensemble

Le système d'enrichissement CVE.org intègre les données officielles de MITRE (CVE.org) pour améliorer la qualité et la précision des informations CVE dans la plateforme CTBA.

## 🎯 Objectifs

L'enrichissement CVE.org permet de :

1. **Produits affectés** : Obtenir la liste officielle et précise des produits affectés (vendor + product)
2. **Date de publication** : Récupérer la date de publication officielle depuis la source MITRE
3. **Date de mise à jour** : Obtenir la dernière date de mise à jour du CVE

## 🏗️ Architecture

### Service d'enrichissement
```
backend/services/cve_enrichment_service.py
```

Le service `CVEEnrichmentService` fournit :

- **fetch_cve_from_cveorg()** : Récupère les données d'un CVE depuis l'API CVE.org
- **extract_affected_products()** : Extrait les produits affectés depuis les données JSON
- **extract_dates()** : Extrait les dates de publication et mise à jour
- **enrich_single_cve()** : Enrichit un seul CVE
- **enrich_all_pending_cves()** : Enrichit tous les CVEs en attente (batch)
- **enrich_specific_cves()** : Enrichit une liste spécifique de CVEs

### Fonctionnalités clés

#### 1. Rate Limiting
- Délai de 600ms entre chaque requête
- Gestion automatique du rate limit (429)
- Timeout de 10s par requête

#### 2. Traitement par lots
- Traite les CVEs par lots de 50
- Évite les timeouts et surcharges
- Progression trackée avec logs

#### 3. Priorité des données
- **CVE.org = Source authoritative** : Les données CVE.org remplacent celles des autres sources
- Confiance maximale (1.0) pour les produits officiels
- Mise à jour de la colonne `source` pour indiquer `cveorg`

## 🚀 Utilisation

### 1. Enrichissement automatique

L'enrichissement est déclenché automatiquement toutes les 30 minutes après l'import des CVEs :

```python
# Dans main.py - fonction run_importers()
enrich_stats = CVEEnrichmentService.enrich_all_pending_cves(limit=50)
```

### 2. Enrichissement manuel via API

#### Enrichir tous les CVEs en attente
```bash
POST http://localhost:8000/api/cves/enrich-from-cveorg?limit=100
```

**Paramètres :**
- `limit` (optionnel, défaut=100) : Nombre maximum de CVEs à enrichir

**Réponse :**
```json
{
  "success": true,
  "message": "✅ Enrichissement CVE.org terminé en 45.2s",
  "statistics": {
    "total_processed": 100,
    "products_added": 450,
    "products_skipped": 12,
    "dates_updated": 95,
    "errors": 5,
    "duration_seconds": 45.2
  }
}
```

#### Enrichir des CVEs spécifiques
```bash
POST http://localhost:8000/api/cves/enrich-from-cveorg?cve_ids=CVE-2024-1234,CVE-2024-5678
```

**Paramètres :**
- `cve_ids` : Liste de CVE IDs séparés par virgule

### 3. Enrichissement programmatique

```python
from services.cve_enrichment_service import CVEEnrichmentService

# Enrichir tous les CVEs PENDING
stats = CVEEnrichmentService.enrich_all_pending_cves(limit=100)

# Enrichir des CVEs spécifiques
cve_list = ['CVE-2024-1234', 'CVE-2024-5678']
stats = CVEEnrichmentService.enrich_specific_cves(cve_list)

# Enrichir un seul CVE
import sqlite3
conn = sqlite3.connect('ctba_platform.db')
stats = CVEEnrichmentService.enrich_single_cve('CVE-2024-1234', conn)
conn.close()
```

## 📊 Statistiques d'enrichissement

Chaque opération d'enrichissement retourne des statistiques détaillées :

```python
{
    'total_processed': 100,        # Nombre de CVEs traités
    'total_products_added': 450,   # Produits ajoutés
    'total_products_skipped': 12,  # Produits déjà existants
    'total_dates_updated': 95,     # CVEs dont les dates ont été mises à jour
    'total_errors': 5,             # Nombre d'erreurs
    'duration': 45.2               # Durée en secondes
}
```

## 🗄️ Structure des données

### Table `cves`
Colonnes mises à jour par l'enrichissement :
- `published_date` : Date de publication officielle (ISO 8601)
- `last_updated` : Date de dernière mise à jour (ISO 8601)
- `source` : Source(s) des données (ex: "NVD,cveorg")

### Table `affected_products`
Colonnes :
- `cve_id` : Identifiant du CVE
- `vendor` : Nom du vendor (ex: "Microsoft")
- `product` : Nom du produit (ex: "Windows 10")
- `confidence` : Niveau de confiance (1.0 pour CVE.org)

### Format JSON CVE.org

L'API CVE.org retourne des données au format :
```json
{
  "cveMetadata": {
    "datePublished": "2024-01-15T10:30:00.000Z",
    "dateUpdated": "2024-01-20T14:45:00.000Z"
  },
  "containers": {
    "cna": {
      "affected": [
        {
          "vendor": "Microsoft",
          "product": "Windows 10"
        }
      ]
    }
  }
}
```

## ⚙️ Configuration

### Variables d'environnement
Aucune configuration spéciale requise. L'API CVE.org est publique.

### Paramètres de performance
```python
# Dans cve_enrichment_service.py
CVE_ORG_API_BASE = "https://cveawg.mitre.org/api/cve"
RATE_LIMIT_DELAY = 0.6      # 600ms entre requêtes
REQUEST_TIMEOUT = 10         # Timeout par requête
BATCH_SIZE = 50              # Taille des lots
```

## 🔍 Logs et monitoring

### Niveaux de log

**INFO** : Progression normale
```
🚀 Démarrage de l'enrichissement CVE.org...
📊 100 CVEs à enrichir
✅ CVE-2024-1234: +5 produits, dates: 1
```

**WARNING** : Problèmes mineurs
```
⚠️ Rate limit atteint pour CVE.org, attente 2s...
CVE CVE-2024-5678 non trouvé sur CVE.org (404)
```

**ERROR** : Erreurs importantes
```
⚠️ Erreur enrichissement global: Connection timeout
Erreur enrichissement CVE-2024-9999: Invalid JSON response
```

### Surveillance

Surveiller ces métriques :
- **Taux d'erreurs** : Ne devrait pas dépasser 5%
- **Durée d'enrichissement** : ~0.6s par CVE en moyenne
- **Produits ajoutés** : Vérifier que les produits sont bien extraits

## 🚨 Gestion des erreurs

Le service gère automatiquement :

1. **Timeouts** : Skip et passage au CVE suivant
2. **404 Not Found** : CVE pas encore dans CVE.org (normal pour CVEs récents)
3. **429 Rate Limit** : Attente automatique de 2s
4. **Erreurs réseau** : Retry automatique avec backoff
5. **JSON invalide** : Skip et log d'erreur

## 📈 Performance

### Temps d'exécution typiques

- **1 CVE** : ~0.6s
- **50 CVEs** : ~30s
- **100 CVEs** : ~60s
- **500 CVEs** : ~5 minutes

### Optimisations

✅ **Implémenté :**
- Rate limiting intelligent
- Traitement par lots
- Gestion des erreurs robuste
- Logs détaillés

🔜 **Futures améliorations :**
- Cache local pour éviter les requêtes répétées
- Parallélisation avec pool de workers
- Base de données locale CVE.org synchronisée

## 🧪 Tests

### Test manuel d'un CVE
```bash
curl -X POST "http://localhost:8000/api/cves/enrich-from-cveorg?cve_ids=CVE-2024-21413"
```

### Vérification en base de données
```sql
-- Vérifier les produits enrichis
SELECT cve_id, vendor, product, confidence 
FROM affected_products 
WHERE cve_id = 'CVE-2024-21413';

-- Vérifier les dates
SELECT cve_id, published_date, last_updated, source 
FROM cves 
WHERE cve_id = 'CVE-2024-21413';
```

## 🔗 Références

- **API CVE.org** : https://cveawg.mitre.org/api/
- **Documentation officielle** : https://www.cve.org/ResourcesSupport/AllResources/CNARules
- **Format JSON** : https://github.com/CVEProject/cvelistV5

## 📝 Changelog

### Version 1.0 (2026-02-01)
- ✅ Service d'enrichissement créé
- ✅ Endpoint API `/enrich-from-cveorg`
- ✅ Intégration dans le scheduler automatique
- ✅ Support des produits affectés
- ✅ Support des dates de publication/mise à jour
- ✅ Rate limiting et gestion d'erreurs
- ✅ Traitement par lots

## 👥 Support

Pour toute question ou problème :
1. Consulter les logs : `backend/logs/`
2. Vérifier la santé du service : `GET /api/cves/health`
3. Contacter l'équipe de développement

---

**Note** : L'enrichissement CVE.org est essentiel pour garantir des données de haute qualité dans la plateforme CTBA. Il doit être exécuté régulièrement pour maintenir les informations à jour.
