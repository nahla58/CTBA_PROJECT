# CHANGELOG - CTBA Platform v7.0.1

**Date**: 22 Janvier 2026

## 🎯 Objectifs Réalisés

### 1. ✅ CVEs Acceptés et Rejetés - Séparation des Statuts
**Statut**: ✅ COMPLÉTÉ

**Changements Backend:**
- Modification du filtre de statut dans `/api/cves` pour respecter les valeurs fournies (ACCEPTED, REJECTED, PENDING, DEFERRED)
- Modification du filtre de sévérité pour respecter les valeurs fournies
- Les deux paramètres ne forcent plus les valeurs par défaut si un filtre est spécifié

**Changements Frontend:**
- `AcceptedCVEs.js`: Utilise `status=ACCEPTED` pour afficher les CVEs acceptés
- `RejectedCVEs.js`: Utilise `status=REJECTED` pour afficher les CVEs rejetés
- Menu de navigation: Routes vers `/accepted` et `/rejected` séparées

**Fichiers Modifiés:**
- `backend/main.py` (lignes 2469-2483)
- `frontend/src/components/AcceptedCVEs.js`
- `frontend/src/components/RejectedCVEs.js`

---

### 2. 📜 Historique des Actions par Analyste
**Statut**: ✅ COMPLÉTÉ

**Changements Backend:**
- Endpoint `/api/cve-actions` supporte déjà le filtre `analyst` (pas de changement nécessaire)

**Changements Frontend:**
- `ActionHistory.js`:
  - Filtre automatique par `analyst=user.username` (analyste connecté)
  - Titre mis à jour: "Mon Historique des Actions - Analyste: {username}"
  - Chaque analyste ne voit que ses propres actions
  - Dépendance `user` ajoutée à `useEffect`

**Fichiers Modifiés:**
- `frontend/src/components/ActionHistory.js`

**Données Retournées:**
```javascript
{
  actions: [
    {
      id: 1,
      cve_id: "CVE-2024-1234",
      action: "ACCEPTED",
      analyst: "jean.dupont",
      comments: "Produit critique",
      action_date: "2024-01-22T10:30:00Z"
    }
  ],
  count: 5,
  total: 5
}
```

---

### 3. 🚫 Produits Blacklistés avec Correction du Score CVSS
**Statut**: ✅ COMPLÉTÉ

**Changements Backend:**

#### Nouvelle Table: `cvss_adjustments`
```sql
CREATE TABLE cvss_adjustments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    original_score REAL,
    adjusted_score REAL NOT NULL,
    adjustment_reason TEXT,
    analyst TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
)
```

#### Nouveaux Endpoints:

**POST `/api/cvss-adjustments`**
- Crée ou met à jour un ajustement de score CVSS
- Paramètres: `cve_id`, `vendor`, `product`, `adjusted_score`, `adjustment_reason`, `analyst`
- Validation: Score entre 0 et 10
- Retourne: `{success: true, message: "...", cve_id: "...", original_score: ..., adjusted_score: ...}`

**GET `/api/cvss-adjustments`**
- Récupère les ajustements de score avec filtres optionnels
- Paramètres: `cve_id`, `vendor`, `product`, `limit`, `offset`
- Retourne: `{success: true, adjustments: [...], count: n}`

**DELETE `/api/cvss-adjustments/{adjustment_id}`**
- Supprime un ajustement de score
- Retourne: `{success: true, message: "Adjustment deleted"}`

**Changements Frontend:**

- `BlacklistManagement.js`:
  - États supplémentaires: `showScoreModal`, `selectedProduct`, `scoreAdjustments`, `adjustmentScore`, `adjustmentReason`
  - Nouvelle fonction: `openScoreModal(item)` - Affiche la modal de correction du score
  - Nouvelle fonction: `handleSaveScoreAdjustment(e)` - Enregistre l'ajustement
  - Bouton "📊 Corriger Score" ajouté à chaque ligne du tableau
  - Modal de correction avec:
    - Affichage du nom du produit
    - Champ Score CVSS (0-10)
    - Champ Raison
    - Affichage de l'historique des ajustements précédents
    - Validation du score

- `BlacklistManagement.css`:
  - Style `.btn-warning` pour le bouton de correction du score

**Fichiers Modifiés:**
- `backend/main.py` (lignes 415-429, 3947-4058)
- `frontend/src/components/BlacklistManagement.js`
- `frontend/src/components/BlacklistManagement.css`

---

## 📊 Récapitulatif des Changements

| Catégorie | Élément | Avant | Après | Statut |
|-----------|---------|-------|-------|--------|
| **CVEs** | Filtre Acceptés | Non fonctionnel | ✅ Fonctionnel | ✅ |
| **CVEs** | Filtre Rejetés | Non fonctionnel | ✅ Fonctionnel | ✅ |
| **Historique** | Filtrage Analyste | Non implémenté | ✅ Par analyste courant | ✅ |
| **Blacklist** | Correction Score | Non implémenté | ✅ Modal avec historique | ✅ |
| **BD** | Table Ajustements | N'existe pas | ✅ Créée | ✅ |
| **API** | Endpoints Scores | N'existent pas | ✅ 3 nouveaux endpoints | ✅ |

---

## 🔧 Détails Techniques

### Validations Ajoutées
1. Score CVSS: Entre 0 et 10 (frontend et backend)
2. CVE existence: Vérification avant création d'ajustement
3. Permissions: Seuls les administrateurs et VOC_L1 peuvent corriger les scores

### Performances
- Index créé sur `cvss_adjustments` pour les requêtes rapides
- Limite de pagination: 100-500 résultats par requête

### Sécurité
- Validation du score côté backend
- Filtrage par analyste pour l'historique
- Permissions basées sur les rôles utilisateur

---

## ✅ Tests Effectués

- ✅ Affichage des CVEs acceptés
- ✅ Affichage des CVEs rejetés
- ✅ Historique des actions par analyste
- ✅ Ajout de produits à la blacklist
- ✅ Correction du score CVSS
- ✅ Affichage de l'historique des ajustements
- ✅ Validation des scores (0-10)
- ✅ Affichage des dates au format français
- ✅ Permissions utilisateur

---

## 📝 Notes Importantes

1. **Base de Données**: La table `cvss_adjustments` sera créée automatiquement au démarrage du backend
2. **Migration**: Pas de données historiques pour les ajustements existants
3. **Backward Compatibility**: Tous les changements sont compatibles avec les versions précédentes
4. **Performance**: Aucun impact sur la performance observé

---

## 🚀 Prochaines Étapes (Optionnel)

1. Ajouter un export des ajustements de score en CSV/PDF
2. Ajouter des graphiques pour visualiser les tendances des scores
3. Ajouter des notifications par email lors des corrections de score
4. Ajouter un système d'approbation pour les corrections de score

---

## 📞 Support

Pour toute question ou problème, consultez le guide de test: [TESTING_GUIDE.md](TESTING_GUIDE.md)
