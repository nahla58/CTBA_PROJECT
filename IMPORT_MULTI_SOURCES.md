# 📡 Import Multi-Sources - Guide d'Utilisation

## Vue d'ensemble

Le système d'import multi-sources permet d'importer et d'afficher les nouveaux CVEs depuis **toutes les sources disponibles** :
- **NVD** (National Vulnerability Database) - Source principale
- **CVEdetails** - Source complémentaire
- **CVE.org** - Enrichissement officiel MITRE

## 🚀 Endpoints disponibles

### 1. Import complet depuis toutes les sources

```bash
POST http://localhost:8000/api/import/all-sources?days=7&enrich=true
```

**Paramètres :**
- `days` (optionnel, défaut=7) : Nombre de jours précédents à importer (1-30)
- `enrich` (optionnel, défaut=true) : Enrichir automatiquement avec CVE.org

**Réponse :**
```json
{
  "success": true,
  "message": "✅ Import multi-sources terminé : 145 nouveaux CVEs importés",
  "statistics": {
    "nvd": {
      "imported": 100,
      "updated": 10,
      "errors": 0
    },
    "cvedetails": {
      "imported": 45,
      "updated": 5,
      "errors": 0
    },
    "cveorg_enrichment": {
      "products_added": 320,
      "dates_updated": 142,
      "processed": 145,
      "errors": 3
    },
    "total_imported": 145,
    "total_updated": 15,
    "duration": 78.5
  },
  "recent_cves": [
    {
      "cve_id": "CVE-2024-21413",
      "description": "Microsoft Outlook Remote Code Execution...",
      "severity": "HIGH",
      "cvss_score": 8.5,
      "source": "NVD,cveorg",
      "published_date": "2024-02-01T10:30:00Z",
      "imported_at": "2024-02-01T12:15:00Z"
    }
  ],
  "total_cves": 145,
  "duration_seconds": 78.5
}
```

### 2. Statistiques d'import

```bash
GET http://localhost:8000/api/import/stats
```

**Réponse :**
```json
{
  "success": true,
  "statistics": {
    "total_cves": 1250,
    "enriched_with_cveorg": 890,
    "recent_7_days": 145,
    "by_source": {
      "NVD": 800,
      "NVD,cveorg": 350,
      "CVEdetails": 100
    },
    "by_status": {
      "PENDING": 145,
      "ACCEPTED": 980,
      "REJECTED": 125
    },
    "by_severity": {
      "CRITICAL": 50,
      "HIGH": 450,
      "MEDIUM": 600,
      "LOW": 150
    }
  }
}
```

### 3. Refresh automatique lors de l'affichage

```bash
GET http://localhost:8000/api/cves?force_refresh=true&limit=100
```

**Effet :**
- Importe les derniers CVEs depuis NVD, CVEdetails
- Enrichit avec CVE.org (limite 50 CVEs)
- Retourne immédiatement les CVEs pour affichage

## 📊 Flux de travail complet

### Scénario 1 : Import manuel complet

```bash
# 1. Lancer l'import multi-sources (7 derniers jours)
curl -X POST "http://localhost:8000/api/import/all-sources?days=7&enrich=true"

# 2. Afficher les CVEs importés
curl "http://localhost:8000/api/cves?status=PENDING&limit=100"

# 3. Vérifier les statistiques
curl "http://localhost:8000/api/import/stats"
```

### Scénario 2 : Refresh rapide depuis le dashboard

```bash
# Refresh + affichage en une seule requête
curl "http://localhost:8000/api/cves?force_refresh=true&status=PENDING&limit=100"
```

### Scénario 3 : Import programmé (scheduler)

Le scheduler s'exécute automatiquement toutes les 30 minutes :
1. Import depuis NVD (24 dernières heures)
2. Import depuis CVEdetails
3. Enrichissement CVE.org (50 CVEs)

## 🎯 Fonctionnalités clés

### ✅ Import NVD
- Source principale et la plus complète
- CVEs avec scores CVSS et descriptions
- Mis à jour quotidiennement

### ✅ Import CVEdetails
- Source complémentaire
- CVEs supplémentaires non présents dans NVD
- Utile pour la couverture complète

### ✅ Enrichissement CVE.org
- **Produits affectés** : Données officielles MITRE (vendor + product)
- **Dates** : Dates de publication et mise à jour authoritative
- **Confiance** : Niveau de confiance 1.0 (source officielle)

### ✅ Enrichissement à la volée
- Enrichit automatiquement lors de l'affichage
- Détecte les produits suspects (`www.`, `advisories`, etc.)
- Remplace immédiatement par les données CVE.org

## 📈 Performance

### Temps d'exécution typiques

| Opération | Durée | CVEs traités |
|-----------|-------|--------------|
| Import NVD seul | ~10-15s | 50-100 CVEs |
| Import CVEdetails | ~5-10s | 20-50 CVEs |
| Enrichissement CVE.org | ~30-60s | 50-100 CVEs |
| **Import complet** | **~60-90s** | **100-200 CVEs** |

### Optimisations

✅ **Implémenté :**
- Import parallèle des sources
- Rate limiting respecté
- Gestion d'erreurs robuste
- Cache des CVEs déjà enrichis

## 🧪 Tests

### Test 1 : Import complet

```bash
# Lancer l'import
curl -X POST "http://localhost:8000/api/import/all-sources?days=1&enrich=true" | jq

# Vérifier les logs backend
# Devrait afficher :
# 📡 Import depuis NVD...
# ✅ NVD: 50 importés, 5 mis à jour
# 📡 Import depuis CVEdetails...
# ✅ CVEdetails: 20 importés
# 🔄 Enrichissement avec CVE.org...
# ✅ CVE.org: 150 produits enrichis
# ✅ Import multi-sources terminé en 45.2s - 70 nouveaux CVEs
```

### Test 2 : Vérifier les statistiques

```bash
curl "http://localhost:8000/api/import/stats" | jq
```

**Vérifier :**
- `total_cves` > 0
- `enriched_with_cveorg` > 0
- `by_source` contient "NVD,cveorg"

### Test 3 : Force refresh

```bash
curl "http://localhost:8000/api/cves?force_refresh=true&limit=50" | jq
```

**Observer dans les logs :**
```
🔄 Force refresh requested - importing from all sources...
✅ Force refresh terminé: 70 CVEs importés/enrichis
```

## 🔍 Monitoring

### Logs à surveiller

**Import réussi :**
```
✅ NVD: 50 importés, 5 mis à jour
✅ CVEdetails: 20 importés
✅ CVE.org: 150 produits enrichis
✅ Import multi-sources terminé en 45.2s - 70 nouveaux CVEs
```

**Enrichissement à la volée :**
```
✅ Enrichi à la volée: CVE-2024-21413 (3 produits)
```

**Erreurs (normales) :**
```
⚠️ CVE CVE-2024-XXXX non trouvé sur CVE.org (404)
⚠️ Timeout fetching CVE-2024-YYYY from CVE.org
```

### Métriques importantes

- **Taux d'enrichissement** : `enriched_with_cveorg / total_cves`
- **Taux de succès** : `(total_imported - errors) / total_imported`
- **Couverture multi-sources** : Nombre de CVEs avec `source` contenant `,`

## 📋 Checklist d'intégration

- [ ] ✅ Endpoint `/api/import/all-sources` fonctionne
- [ ] ✅ Endpoint `/api/import/stats` retourne des données
- [ ] ✅ `force_refresh=true` importe les nouveaux CVEs
- [ ] ✅ Enrichissement CVE.org activé par défaut
- [ ] ✅ Enrichissement à la volée détecte les produits suspects
- [ ] ✅ Les sources sont correctement fusionnées (ex: "NVD,cveorg")
- [ ] ✅ Les logs sont clairs et informatifs
- [ ] ✅ Les erreurs n'empêchent pas l'import global

## 🔗 Intégration Frontend

### Bouton "Importer nouveaux CVEs"

```javascript
const importNewCVEs = async () => {
  const response = await fetch('http://localhost:8000/api/import/all-sources?days=7&enrich=true', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const result = await response.json();
  
  if (result.success) {
    console.log(`✅ ${result.total_cves} nouveaux CVEs importés`);
    console.log('Statistiques:', result.statistics);
    
    // Recharger la liste des CVEs
    loadCVEs();
  }
};
```

### Affichage des statistiques

```javascript
const loadStats = async () => {
  const response = await fetch('http://localhost:8000/api/import/stats');
  const result = await response.json();
  
  if (result.success) {
    const stats = result.statistics;
    console.log(`Total CVEs: ${stats.total_cves}`);
    console.log(`Enrichis avec CVE.org: ${stats.enriched_with_cveorg}`);
    console.log(`Récents (7j): ${stats.recent_7_days}`);
  }
};
```

## 🆘 Troubleshooting

### Problème : Import trop lent

**Solution :**
- Réduire le paramètre `days` (ex: `days=1`)
- Désactiver l'enrichissement : `enrich=false`
- Utiliser `force_refresh` pour un import plus rapide

### Problème : Erreurs CVE.org (404)

**Cause :** CVEs trop récents, pas encore dans CVE.org

**Solution :** Normal, les CVEs seront enrichis plus tard

### Problème : Timeout

**Cause :** Trop de CVEs à traiter

**Solution :**
- Augmenter le timeout FastAPI
- Réduire le nombre de CVEs avec `days=1`
- Enrichir en plusieurs fois

## 📝 Notes importantes

1. **Import complet = NVD + CVEdetails + CVE.org** : Tous les sources en une seule requête
2. **Enrichissement automatique** : CVE.org est appelé automatiquement si `enrich=true`
3. **À la volée** : Les CVEs sont aussi enrichis lors de leur affichage si nécessaire
4. **Scheduler** : Continue de fonctionner en arrière-plan toutes les 30 minutes

---

**Astuce** : Pour une mise à jour quotidienne complète, utilisez `POST /api/import/all-sources?days=1&enrich=true`
