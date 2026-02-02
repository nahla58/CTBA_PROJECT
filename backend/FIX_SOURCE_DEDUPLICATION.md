# 🔧 FIX: Problème de Sources Multiples (NVD + CVE.org)

## Problème Identifié

**Symptôme:** Certaines CVEs apparaissent avec `source='NVD'` alors qu'elles existent déjà dans CVE Org, et vice versa.

**Cause Racine:** Les importers n'ont pas de logique cohérente de réconciliation des sources multiples.

### Comportement Actuel (Bugué)

```
1. NVD importe CVE-2024-1234 → source='NVD'
2. CVE Org importe CVE-2024-1234 
   → Cherche si CVE existe
   → Oui! Mais ajoute juste CVE Org comme source dans la colonne source
   → Result: source='NVD,cveorg' ❌ (mélange de deux sources)

3. Frontend affiche la PREMIÈRE source listée (NVD)
   → Confusion: l'utilisateur pense que NVD est la source primaire!
```

### Pourquoi C'est Un Problème

1. **Ordre aléatoire des sources** - Dépend de l'ordre d'import
2. **Pas de source "primaire"** - Impossible de savoir qui est responsable du CVE
3. **Créé de la confusion** - Les analyts voient "NVD" mais les données viennent de CVE Org
4. **Pas de logique métier claire** - Quand dois-je privilégier NVD vs CVE Org?

---

## Solution: Architecture de Source Primaire + Secondaires

### Concept

Chaque CVE a:
- **source_primary** (TEXT): La source initiale qui a créé le CVE (NVD, cvedetails, cveorg, msrc, hackuity, manual)
- **sources_secondary** (JSON): Autres sources qui ont amélioré le CVE [{"name": "cveorg", "added_at": "2024-01-26T10:30:00Z", "data_type": "products"}]

### Schéma Amélioré

```sql
-- Remplacer la colonne 'source' TEXT
-- Par deux colonnes:
ALTER TABLE cves ADD COLUMN source_primary TEXT DEFAULT 'NVD';
ALTER TABLE cves ADD COLUMN sources_secondary JSON DEFAULT '[]';

-- La colonne 'source' devient une vue
CREATE VIEW v_cves_sources AS
SELECT 
  cve_id,
  source_primary as source,
  sources_secondary
FROM cves;
```

### Logique de Reconciliation

```
Quand un CVE est importé:

1. LOOKUP: SELECT source_primary FROM cves WHERE cve_id = ?
2. IF NOT EXISTS:
   → INSERT with source_primary = 'new_source'
   → sources_secondary = '[]'
   
3. IF EXISTS:
   → Check source_primary
   → If different source:
      → ADD to sources_secondary (ne pas remplacer!)
      → Merger les produits affectés (NVD + CVE.org)
   → Keep source_primary unchanged!
```

---

## Implémentation

### Fichier: backend/migrations/fix_multi_source.sql

```sql
-- Étape 1: Créer les colonnes
ALTER TABLE cves ADD COLUMN source_primary TEXT DEFAULT 'NVD';
ALTER TABLE cves ADD COLUMN sources_secondary JSON DEFAULT '[]';

-- Étape 2: Migrer les données existantes
UPDATE cves 
SET source_primary = CASE 
  WHEN source LIKE 'nvd%' THEN 'NVD'
  WHEN source LIKE 'cvedetails%' THEN 'cvedetails'
  WHEN source LIKE 'cveorg%' THEN 'cveorg'
  WHEN source LIKE 'msrc%' THEN 'msrc'
  WHEN source LIKE 'hackuity%' THEN 'hackuity'
  WHEN source LIKE 'manual%' THEN 'manual'
  ELSE 'unknown'
END;

-- Étape 3: Créer une vue de compatibilité (pour l'ancien code)
CREATE VIEW v_cves_sources AS
SELECT 
  cve_id,
  source_primary as source,
  sources_secondary
FROM cves;

-- Étape 4: Créer un index
CREATE INDEX idx_cves_source_primary ON cves(source_primary);
```

---

## Code: Nouvelle Logique d'Import

### A. Importer depuis NVD

```python
def import_from_nvd():
    """Importer depuis NVD avec source_primary"""
    
    for cve in nvd_cves:
        cve_id = cve.get('id')
        
        # Vérifier si CVE existe
        cursor.execute(
            "SELECT source_primary FROM cves WHERE cve_id = ?", 
            (cve_id,)
        )
        existing = cursor.fetchone()
        
        if existing:
            # CVE existe déjà
            primary_source = existing['source_primary']
            
            if primary_source == 'NVD':
                # Même source: mise à jour simple
                cursor.execute("""
                    UPDATE cves 
                    SET description = ?, severity = ?, cvss_score = ?, last_updated = ?
                    WHERE cve_id = ?
                """, (description, severity, cvss_score, now, cve_id))
                
            else:
                # Source différente: ajouter NVD aux sources secondaires
                cursor.execute("SELECT sources_secondary FROM cves WHERE cve_id = ?", (cve_id,))
                row = cursor.fetchone()
                
                secondary_sources = json.loads(row['sources_secondary'] or '[]')
                
                # Vérifier que NVD n'est pas déjà listée
                if not any(s['name'] == 'nvd' for s in secondary_sources):
                    secondary_sources.append({
                        'name': 'nvd',
                        'added_at': datetime.now(pytz.UTC).isoformat(),
                        'data_enrichment': 'severity,cvss_score'
                    })
                
                cursor.execute("""
                    UPDATE cves 
                    SET sources_secondary = ?, last_updated = ?
                    WHERE cve_id = ?
                """, (json.dumps(secondary_sources), now, cve_id))
                
                logger.info(f"✅ Added NVD as secondary source for {cve_id}")
        else:
            # CVE n'existe pas: créer avec NVD comme source primaire
            cursor.execute("""
                INSERT INTO cves 
                (cve_id, description, severity, cvss_score, source_primary, 
                 sources_secondary, imported_at, last_updated)
                VALUES (?, ?, ?, ?, 'NVD', '[]', ?, ?)
            """, (cve_id, description, severity, cvss_score, now, now))
            
            logger.info(f"✅ Added {cve_id} from NVD")
```

### B. Importer depuis CVE.org

```python
def import_from_cveorg():
    """Enrichir avec CVE.org en tant que source secondaire"""
    
    for cve_id in cve_ids_to_enhance:
        # Récupérer les données CVE.org
        cveorg_data = fetch_from_cveorg_api(cve_id)
        
        # Vérifier si CVE existe
        cursor.execute(
            "SELECT source_primary FROM cves WHERE cve_id = ?",
            (cve_id,)
        )
        existing = cursor.fetchone()
        
        if existing:
            # CVE existe: ajouter CVE.org comme source secondaire
            primary_source = existing['source_primary']
            
            if primary_source != 'cveorg':
                # Ajouter CVE.org aux sources secondaires
                cursor.execute(
                    "SELECT sources_secondary FROM cves WHERE cve_id = ?",
                    (cve_id,)
                )
                row = cursor.fetchone()
                
                secondary_sources = json.loads(row['sources_secondary'] or '[]')
                
                if not any(s['name'] == 'cveorg' for s in secondary_sources):
                    secondary_sources.append({
                        'name': 'cveorg',
                        'added_at': datetime.now(pytz.UTC).isoformat(),
                        'data_enrichment': 'vendor,product'
                    })
                
                cursor.execute("""
                    UPDATE cves 
                    SET sources_secondary = ?, last_updated = ?
                    WHERE cve_id = ?
                """, (json.dumps(secondary_sources), now, cve_id))
            
            # Insérer/mettre à jour les produits de CVE.org
            for affected in cveorg_data.get('affected', []):
                vendor = affected.get('vendor', '').strip()
                product = affected.get('product', '').strip()
                
                if vendor and product:
                    cursor.execute("""
                        INSERT OR IGNORE INTO affected_products 
                        (cve_id, vendor, product, confidence, source)
                        VALUES (?, ?, ?, 1.0, 'cveorg')
                    """, (cve_id, vendor, product))
            
            logger.info(f"✅ Enhanced {cve_id} with CVE.org data")
        else:
            # CVE n'existe pas: créer avec CVE.org comme source primaire
            cursor.execute("""
                INSERT INTO cves 
                (cve_id, description, severity, source_primary, 
                 sources_secondary, imported_at, last_updated)
                VALUES (?, ?, ?, 'cveorg', '[]', ?, ?)
            """, (cve_id, description, severity, now, now))
```

---

## Frontend: Afficher les Sources

### React Component

```jsx
function SourcesBadge({ cve }) {
  const primary = cve.source_primary || 'Unknown';
  const secondary = JSON.parse(cve.sources_secondary || '[]');
  
  return (
    <div className="sources-container">
      <span className="source-primary">
        <strong>{primary}</strong> (primaire)
      </span>
      
      {secondary.length > 0 && (
        <span className="source-secondary">
          Enrichi par: {secondary.map(s => s.name).join(', ')}
        </span>
      )}
    </div>
  );
}
```

### CSS

```css
.source-primary {
  background: #3b82f6;
  color: white;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: bold;
}

.source-secondary {
  background: #10b981;
  color: white;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.8rem;
  margin-left: 4px;
}
```

---

## API Response (Avant/Après)

### AVANT (Bugué)
```json
{
  "cve_id": "CVE-2024-1234",
  "source": "NVD,cveorg",  // ❌ Mélangé, pas clair
  "affected_products": [...]
}
```

### APRÈS (Fixé)
```json
{
  "cve_id": "CVE-2024-1234",
  "source_primary": "NVD",
  "sources_secondary": [
    {
      "name": "cveorg",
      "added_at": "2024-01-26T10:30:00Z",
      "data_enrichment": "vendor,product"
    }
  ],
  "affected_products": [...]
}
```

---

## Checklist d'Implémentation

- [ ] Créer la migration SQL (fix_multi_source.sql)
- [ ] Exécuter la migration `psql -U ctba_user -d ctba_db -f fix_multi_source.sql`
- [ ] Mettre à jour `import_from_nvd()` avec la nouvelle logique
- [ ] Mettre à jour `import_from_cvedetails()` avec la nouvelle logique
- [ ] Mettre à jour `import_from_cveorg()` avec la nouvelle logique
- [ ] Mettre à jour `import_from_msrc()` avec la nouvelle logique
- [ ] Mettre à jour la route `/api/cves` pour retourner `source_primary` + `sources_secondary`
- [ ] Mettre à jour le frontend AcceptedCVEs.js pour afficher les sources correctement
- [ ] Tester l'import NVD → CVE.org → affichage
- [ ] Nettoyer les données existantes (supprimer les "NVD,cveorg" mélangées)

---

## FAQ

**Q: Que se passe-t-il si NVD et CVE.org ont des produits différents pour le même CVE?**
A: Les deux sont conservés dans `affected_products`. Chaque produit garde sa trace de source.

**Q: Comment éviter les doublons de produits?**
A: Ajouter une contrainte UNIQUE(cve_id, vendor, product) avec ON CONFLICT DO UPDATE.

**Q: Backward compatibility?**
A: La vue `v_cves_sources` permet au legacy code de continuer à utiliser `source` comme avant.

**Q: Qu'en est-il des autres importers (MSRC, Hackuity)?**
A: Suivre le même pattern: chacun peut être primaire ou secondaire selon l'ordre d'import.

---

## Bénéfices

✅ **Clarté**: Toujours sait qui a créé le CVE  
✅ **Tracabilité**: Historique complet des sources qui l'ont enrichi  
✅ **Pas de perte de données**: Tous les produits des deux sources sont gardés  
✅ **Flexibilité**: Peut privilégier une source ou l'autre dans l'affichage  
✅ **Évolutif**: Ajout facile de nouvelles sources sans conflit  
