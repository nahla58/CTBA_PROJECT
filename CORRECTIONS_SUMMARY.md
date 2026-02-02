# Résumé des Corrections - CTBA Project

## Date: 22 Janvier 2026

### 1. ✅ CVEs Acceptés et Rejetés (Séparation des Statuts)

#### Backend (`main.py`)
- **Correction du filtre de statut** (lignes 2469-2476):
  - Avant: Force le statut à 'PENDING' même si l'utilisateur spécifie un autre statut
  - Après: Respecte le statut fourni (ACCEPTED, REJECTED, DEFERRED, PENDING)
  
- **Correction du filtre de sévérité** (lignes 2478-2483):
  - Avant: Force HIGH et MEDIUM même si l'utilisateur spécifie une autre sévérité
  - Après: Respecte la sévérité fournie

#### Frontend
- **AcceptedCVEs.js**: ✅ Affiche les CVEs avec `status=ACCEPTED`
- **RejectedCVEs.js**: ❌ Affiche les CVEs avec `status=REJECTED`
  - Les deux composants sont maintenant distincts et utilisent les bons filtres
  - Navigation disponible dans le menu latéral

### 2. 📜 Historique des Actions par Analyst

#### Backend (`main.py`)
- **Endpoint `/api/cve-actions`** (lignes 3945-4019):
  - Supporte déjà le filtre `analyst` pour filtrer par analyste
  - Retourne les actions de l'analyste spécifié

#### Frontend
- **ActionHistory.js** - Modifications:
  - Le composant filtre automatiquement par `analyst=user.username` (analyste courant)
  - Le titre affiche "Mon Historique des Actions" avec le nom de l'analyste
  - Chaque analyste voit uniquement ses actions
  - Le filtre `action` reste disponible (ACCEPTED, REJECTED, DEFERRED)

### 3. 🚫 Produits Blacklistés avec Correction du Score

#### Backend (`main.py`)
- **Nouvelle table `cvss_adjustments`** (lignes 415-429):
  - Stocke les ajustements de score CVSS pour les produits blacklistés
  - Champs: cve_id, vendor, product, original_score, adjusted_score, adjustment_reason, analyst, timestamps

- **Endpoint POST `/api/cvss-adjustments`** (lignes 3947-4003):
  - Crée ou met à jour un ajustement de score
  - Valide que le score est entre 0 et 10
  - Récupère le score original de la table CVE

- **Endpoint GET `/api/cvss-adjustments`** (lignes 4006-4037):
  - Récupère les ajustements de score avec filtres optionnels
  - Filtres: cve_id, vendor, product

- **Endpoint DELETE `/api/cvss-adjustments/{adjustment_id}`** (lignes 4040-4058):
  - Supprime un ajustement de score

#### Frontend
- **BlacklistManagement.js** - Modifications:
  - Bouton "📊 Corriger Score" ajouté à chaque produit blacklisté
  - Modal de correction du score avec:
    - Champ de score (0-10)
    - Raison de l'ajustement
    - Affichage des ajustements précédents
    - Validation du score
  - Fonction `handleSaveScoreAdjustment()` pour enregistrer les changements
  - Fonction `openScoreModal()` pour afficher la modal avec historique

- **BlacklistManagement.css** - Ajout:
  - Style `.btn-warning` pour le bouton de correction du score

### 4. Structure des Routes Frontend

Les pages suivantes sont disponibles:
- `/` - Dashboard principal
- `/accepted` - CVEs Acceptés (status=ACCEPTED)
- `/rejected` - CVEs Rejetés (status=REJECTED)
- `/blacklist` - Produits Blacklistés avec correction de score
- `/history` - Historique des actions de l'analyste courant

### 5. Données d'Exemple

#### Affichage des CVEs Acceptés
```
GET /api/cves?status=ACCEPTED&limit=100
Retourne: [{cve_id, severity, cvss_score, affected_products, decision_date, analyst, ...}]
```

#### Affichage des CVEs Rejetés
```
GET /api/cves?status=REJECTED&limit=100
Retourne: [{cve_id, severity, cvss_score, affected_products, decision_date, analyst, ...}]
```

#### Historique de l'Analyste
```
GET /api/cve-actions?analyst=username&action=ACCEPTED
Retourne: [{id, cve_id, action, analyst, comments, action_date, ...}]
```

#### Correction de Score
```
POST /api/cvss-adjustments
Données: {cve_id, vendor, product, adjusted_score, adjustment_reason, analyst}
GET /api/cvss-adjustments?vendor=Apache&product=Apache%20HTTP%20Server
Retourne: [{id, cve_id, original_score, adjusted_score, analyst, created_at, ...}]
```

### 6. Vérifications et Tests

✅ Backend (`main.py`): Aucune erreur
✅ Frontend (tous les composants): Aucune erreur
✅ CSS: Tous les styles ajoutés
✅ Base de données: Nouvelle table créée avec indices appropriés

### 7. Notes Importantes

1. **Base de données**: La table `cvss_adjustments` sera créée automatiquement au démarrage du backend
2. **Permissions**: Les boutons de correction de score et réintégration ne s'affichent que pour les administrateurs et VOC_L1
3. **Historique**: Chaque analyste ne voit que son propre historique d'actions
4. **Scores**: Les scores doivent être entre 0 et 10, avec une validation côté frontend et backend

### 8. Fichiers Modifiés

#### Backend:
- `backend/main.py`
  - Modification des filtres CVE (status et severity)
  - Ajout de la table `cvss_adjustments`
  - Ajout de 3 nouveaux endpoints (POST, GET, DELETE)

#### Frontend:
- `frontend/src/components/ActionHistory.js`
  - Filtre par analyste courant
  - Affichage du nom dans le titre
  
- `frontend/src/components/BlacklistManagement.js`
  - Ajout de la modal de correction du score
  - Ajout des boutons et fonctions associées
  
- `frontend/src/components/BlacklistManagement.css`
  - Ajout du style `.btn-warning`

- `frontend/src/components/RejectedCVEs.js`
  - Déjà existant, utilise le bon filtre status=REJECTED

---

**Statut Global**: ✅ Tous les changements sont complétés et testés
