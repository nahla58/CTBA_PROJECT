# Guide de Test - Corrections CTBA Platform

## 1. Démarrage de l'Application

```bash
# Terminal 1 - Backend
cd backend
python main.py

# Terminal 2 - Frontend
cd frontend
npm start
```

## 2. Test des CVEs Acceptés et Rejetés

### Afficher les CVEs Acceptés
1. Allez à `/accepted` dans le menu de navigation
2. Cliquez sur "✅ CVEs Acceptés"
3. Vérifiez que seuls les CVEs avec `status=ACCEPTED` sont affichés
4. Cliquez sur "👁️ Détails" pour voir les informations complètes

### Afficher les CVEs Rejetés
1. Allez à `/rejected` dans le menu de navigation
2. Cliquez sur "❌ CVEs Rejetés"
3. Vérifiez que seuls les CVEs avec `status=REJECTED` sont affichés
4. Cliquez sur "👁️ Détails" pour voir les informations complètes

**Vérification dans la Base de Données:**
```sql
-- Vérifier les CVEs acceptés
SELECT COUNT(*) as accepted_count FROM cves WHERE status = 'ACCEPTED';

-- Vérifier les CVEs rejetés
SELECT COUNT(*) as rejected_count FROM cves WHERE status = 'REJECTED';

-- Vérifier les CVEs en attente
SELECT COUNT(*) as pending_count FROM cves WHERE status = 'PENDING';
```

## 3. Test de l'Historique des Actions par Analyste

### Afficher l'Historique Personnel
1. Allez à `/history` dans le menu de navigation
2. Cliquez sur "📜 Historique des Actions"
3. Le titre doit afficher: "Mon Historique des Actions" avec votre nom d'utilisateur
4. Vous devez voir uniquement vos actions (celles effectuées par vous-même)

### Filtrer par Type d'Action
1. Utilisez le menu déroulant "Filtrer par action"
2. Sélectionnez "✅ Acceptées", "❌ Rejetées", ou "⏸️ Déférées"
3. Vérifiez que le filtre fonctionne correctement

**Vérification dans la Base de Données:**
```sql
-- Vérifier les actions d'un analyste spécifique
SELECT * FROM cve_actions WHERE analyst = 'nom_utilisateur' ORDER BY action_date DESC;

-- Vérifier les actions acceptées d'un analyste
SELECT COUNT(*) as count FROM cve_actions 
WHERE analyst = 'nom_utilisateur' AND action = 'ACCEPTED';
```

## 4. Test des Produits Blacklistés avec Correction du Score

### Ajouter un Produit à la Blacklist
1. Allez à `/blacklist` dans le menu de navigation
2. Remplissez le formulaire "Ajouter à la blacklist":
   - **Vendor**: Apache
   - **Product**: Apache HTTP Server
   - **Reason**: Produit non critique pour notre organisation
3. Cliquez sur "🚫 Add to Blacklist"
4. Vérifiez le message de succès

### Corriger le Score CVSS
1. Dans la table des produits blacklistés, trouvez le produit ajouté
2. Cliquez sur le bouton "📊 Corriger Score"
3. Une modal doit s'afficher avec:
   - Nom du produit
   - Champ "Score CVSS Ajusté" (entre 0 et 10)
   - Champ "Raison de l'ajustement"
   - Historique des ajustements précédents (s'il y en a)
4. Entrez un score (par exemple: 3.5)
5. Entrez une raison (par exemple: "Non critique pour notre infrastructure")
6. Cliquez sur "✅ Enregistrer"
7. Vérifiez le message de succès

### Vérifier les Ajustements de Score
1. Cliquez à nouveau sur "📊 Corriger Score" pour le même produit
2. L'historique des ajustements précédents doit s'afficher
3. Vous pouvez ajouter de nouveaux ajustements qui mettront à jour le score

**Vérification dans la Base de Données:**
```sql
-- Vérifier les produits blacklistés
SELECT * FROM technologies WHERE status = 'OUT_OF_SCOPE';

-- Vérifier les ajustements de score
SELECT * FROM cvss_adjustments ORDER BY updated_at DESC;

-- Vérifier les ajustements pour un produit spécifique
SELECT * FROM cvss_adjustments 
WHERE vendor = 'Apache' AND product = 'Apache HTTP Server'
ORDER BY updated_at DESC;
```

## 5. Test des Permissions

### Administrateur
- Peut ajouter/supprimer des produits de la blacklist
- Peut corriger les scores CVSS

### VOC_L1
- Peut ajouter/supprimer des produits de la blacklist
- Peut corriger les scores CVSS

### Autres Rôles
- Ne voient pas les boutons "📊 Corriger Score" et "♻️ Réintégrer"
- Peuvent toujours consulter les produits blacklistés

## 6. Test des Appels API Directes

### CVEs Acceptés
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/cves?status=ACCEPTED&limit=10"
```

### CVEs Rejetés
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/cves?status=REJECTED&limit=10"
```

### Historique de l'Analyste
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/cve-actions?analyst=votre_username&limit=10"
```

### Ajouter un Ajustement de Score
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "cve_id=CVE-2024-1234&vendor=Apache&product=Apache HTTP Server&adjusted_score=3.5&adjustment_reason=Non critique&analyst=votre_username" \
  "http://localhost:8000/api/cvss-adjustments"
```

### Récupérer les Ajustements
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/cvss-adjustments?vendor=Apache&product=Apache%20HTTP%20Server"
```

## 7. Dépannage

### Les CVEs acceptés/rejetés ne s'affichent pas
1. Vérifiez que des CVEs avec le statut approprié existent dans la base de données
2. Vérifiez les logs du backend pour les erreurs
3. Vérifiez que le token d'authentification est valide

### L'historique des actions est vide
1. Vérifiez que des actions existent pour cet analyste dans la base de données
2. Vérifiez que le nom d'utilisateur du token correspond à celui du filtre

### Le formulaire de correction de score ne fonctionne pas
1. Vérifiez que vous êtes administrateur ou VOC_L1
2. Vérifiez la console du navigateur (F12) pour les erreurs
3. Vérifiez que le serveur backend répond correctement

## 8. Fonctionnalités Clés à Vérifier

✅ Les CVEs acceptés sont séparés des CVEs rejetés
✅ Chaque analyste voit uniquement son historique d'actions
✅ Les produits blacklistés s'affichent avec added_by et created_at
✅ Les scores CVSS peuvent être corrigés pour les produits blacklistés
✅ L'historique des ajustements de score s'affiche dans la modal
✅ Les permissions sont respectées (seuls admin et VOC_L1 peuvent éditer)
✅ Les messages de succès et d'erreur s'affichent correctement
✅ Les timestamps sont affichés au format français (JJ/MM/AAAA)

---

**Note**: Assurez-vous que le serveur backend est en cours d'exécution avant de tester les fonctionnalités!
