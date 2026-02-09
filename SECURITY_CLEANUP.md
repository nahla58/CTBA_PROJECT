# 🔐 SÉCURITÉ: Suppression des Secrets de Git

## ⚠️ Problème
Des secrets (API keys) ont été committés par erreur dans `backend/.env`.

## ✅ Solution: Nettoyer l'historique Git

### Étape 1: Supprimer le fichier du cache Git
```powershell
git rm --cached backend/.env
```

### Étape 2: Vérifier que .gitignore est correct
```powershell
# Le fichier .gitignore contient maintenant:
# backend/.env
# .env
# *.env
```

### Étape 3: Commit la suppression
```powershell
git add .gitignore backend/.env.example
git commit -m "chore: Remove secrets from Git and add .env.example"
```

### Étape 4: Nettoyer TOUT l'historique (BFG Repo Cleaner - RECOMMANDÉ)

#### Option A: Avec BFG (le plus simple)
```powershell
# 1. Télécharger BFG: https://rtyley.github.io/bfg-repo-cleaner/
# 2. Exécuter:
java -jar bfg.jar --delete-files backend/.env
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

#### Option B: Avec git filter-branch (alternative)
```powershell
git filter-branch --force --index-filter `
  "git rm --cached --ignore-unmatch backend/.env" `
  --prune-empty --tag-name-filter cat -- --all
```

### Étape 5: Force push (⚠️ ATTENTION: réécrit l'historique)
```powershell
git push origin main --force
```

---

## 🔑 Configuration Locale

### 1. Copier le template
```powershell
Copy-Item backend\.env.example backend\.env
```

### 2. Éditer avec vos vraies clés
```powershell
notepad backend\.env
```

Remplissez:
- `GROQ_API_KEY`: Obtenez-la sur https://console.groq.com (gratuit)
- `CVEDETAILS_API_TOKEN`: Obtenez-le sur https://www.cvedetails.com/api/
- `SMTP_PASSWORD`: App password Gmail

### 3. Vérifier que .env est ignoré
```powershell
git status
# backend/.env ne doit PAS apparaître
```

---

## 📝 Bonnes Pratiques

✅ **TOUJOURS**:
- Utiliser `.env.example` pour les templates
- Ajouter `.env` au `.gitignore`
- Rotation des clés après une fuite

❌ **JAMAIS**:
- Committer des fichiers `.env`
- Hardcoder des secrets dans le code
- Partager des clés API publiquement

---

## 🚨 En Cas de Fuite

Si des secrets ont été poussés sur GitHub:

1. **Révoquer immédiatement** les clés exposées:
   - Groq: https://console.groq.com/keys
   - Hugging Face: https://huggingface.co/settings/tokens
   - Gmail: Générer nouveau app password

2. **Nettoyer l'historique** (voir ci-dessus)

3. **Générer de nouvelles clés**

4. **Activer GitHub Secret Scanning** (déjà fait automatiquement)

---

## 📚 Ressources

- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [BFG Repo Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [Git Filter Branch](https://git-scm.com/docs/git-filter-branch)
