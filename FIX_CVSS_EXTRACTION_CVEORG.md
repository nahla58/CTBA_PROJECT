# 🔧 Correction: Extraction Scores CVSS depuis CVE.org

## 📋 Problème Résolu

Les CVEs importés avaient un score CVSS de 0 alors que **CVE.org contient déjà les scores** publiés par les CNA (CVE Numbering Authorities).

Notre code n'extrayait pas ces scores depuis la section `containers.cna.metrics` de l'API CVE.org.

## ✅ Correction Appliquée

### Fichier: `backend/services/cve_fetcher_service.py`

**Fonction modifiée:** `fetch_cve_from_cveorg()`

Ajouté l'extraction des scores CVSS depuis CVE.org:

```python
# 🆕 Extraire les scores CVSS depuis CVE.org (publiés par les CNA)
metrics = cna.get("metrics", [])
if metrics and len(metrics) > 0:
    metric = metrics[0]
    
    # CVSS v3.1
    if "cvssV3_1" in metric:
        cvss_data = metric["cvssV3_1"]
        cvss_score = float(cvss_data.get("baseScore", 0))
        cvss_vector = cvss_data.get("vectorString", "N/A")
        cvss_version = "3.1"
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
    
    # CVSS v3.0
    elif "cvssV3_0" in metric:
        # ... extraction v3.0
    
    # CVSS v2.0
    elif "cvssV2_0" in metric:
        # ... extraction v2.0
```

**Retour modifié:**
```python
return {
    "cve_id": cve_id,
    "description": description,
    "cvss_score": round(cvss_score, 1),  # ✅ NOUVEAU
    "cvss_vector": cvss_vector,           # ✅ NOUVEAU
    "cvss_version": cvss_version,         # ✅ NOUVEAU
    "severity": severity,                 # ✅ NOUVEAU
    "affected_products": affected_products,
    "published_date": published,
    "last_updated": updated or published,
    "source": "CVE.org"
}
```

## 🔄 Corriger les CVEs Existants

Pour les CVEs déjà importés avec score = 0, utilisez le script de correction:

### Option 1: Script Python

```bash
cd backend
python fix_cvss_scores_from_cveorg.py
```

**Ce script:**
1. Trouve tous les CVEs avec score CVSS = 0
2. Interroge CVE.org pour chaque CVE
3. Extrait les scores CVSS depuis `containers.cna.metrics`
4. Met à jour la base de données

**Sortie attendue:**
```
🚀 Démarrage de la correction des scores CVSS depuis CVE.org...
📊 23 CVEs sans score CVSS trouvés
🔄 Vérification des scores sur CVE.org...
[1/23] Vérification CVE-2026-25584...
   ✅ CVE-2026-25584: Score mis à jour → 5.3 (MEDIUM)
[2/23] Vérification CVE-2026-25583...
   ✅ CVE-2026-25583: Score mis à jour → 6.1 (MEDIUM)
...
✅ Correction terminée:
   - Total vérifié: 23
   - Scores corrigés: 18
   - Pas encore publié: 5
```

### Option 2: API Endpoint

L'endpoint existant peut aussi être utilisé:

```bash
curl -X POST "http://localhost:8000/api/cves/enrich-cvss-scores-from-nvd?limit=50"
```

Mais maintenant il interrogera d'abord CVE.org (plus rapide) avant de tenter la NVD.

## 🎯 Impact

### Avant
- CVE.org interrogé mais scores CVSS ignorés ❌
- Tous les CVEs importés avec score = 0
- Fallback sur NVD (délai 2-7 jours)

### Après
- CVE.org interrogé ET scores CVSS extraits ✅
- CVEs importés avec scores IMMÉDIATS (si CNA a publié)
- Fallback sur NVD uniquement si pas de score CVE.org

## 📊 Exemple de Données CVE.org

**API CVE.org retourne:**
```json
{
  "containers": {
    "cna": {
      "metrics": [
        {
          "cvssV3_1": {
            "baseScore": 5.3,
            "baseSeverity": "MEDIUM",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        }
      ],
      "affected": [...],
      "descriptions": [...]
    }
  }
}
```

**Maintenant extrait:**
- ✅ `cvss_score`: 5.3
- ✅ `severity`: "MEDIUM"
- ✅ `cvss_version`: "3.1"
- ✅ `cvss_vector`: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

## 🚀 Prochaines Étapes

### 1. Corriger les CVEs existants
```bash
cd backend
python fix_cvss_scores_from_cveorg.py
```

### 2. Redémarrer le backend
```bash
python start_backend.py
```

### 3. Vérifier le dashboard
- Les nouveaux CVEs importés auront leurs scores dès l'import
- Les CVEs corrigés afficheront les bons scores

## 📝 Notes

### Hiérarchie des Sources CVSS

1. **CVE.org (CNA)** - Immédiat, publié par l'autorité qui a assigné le CVE
2. **NVD** - Délai 2-7 jours, scores officiels calculés par NIST
3. **CVE Details** - Agrégateur, peut avoir des scores approximatifs

### CNA (CVE Numbering Authorities)

Les CNA sont des organisations autorisées à publier des CVEs:
- Vendeurs (Microsoft, Apple, Google, etc.)
- Organismes de sécurité (CERT, etc.)
- Chercheurs en sécurité

Ils peuvent publier le score CVSS directement sur CVE.org lors de la publication du CVE.

### Cas où score = 0 reste valide

- CVE très récent (< 24h)
- CNA n'a pas calculé de score
- NVD pas encore analysé
- CVE en état "RESERVED" ou "REJECTED"

---

**Date:** 5 février 2026  
**Fichiers modifiés:** `backend/services/cve_fetcher_service.py`  
**Script créé:** `backend/fix_cvss_scores_from_cveorg.py`  
**Impact:** HIGH - Scores CVSS corrects dès l'import
