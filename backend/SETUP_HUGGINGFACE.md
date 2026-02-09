# 🤗 Configuration Hugging Face pour CTBA Platform

## ✅ Étapes Rapides (5 minutes)

### 1. Créer un compte Hugging Face (GRATUIT)
- Allez sur: https://huggingface.co/join
- Créez votre compte (email + mot de passe)

### 2. Générer une clé API (GRATUIT)
- Connectez-vous sur: https://huggingface.co/settings/tokens
- Cliquez sur **"New token"**
- Nom du token: `CTBA Platform`
- Type: **Read** (suffisant pour l'Inference API)
- Cliquez sur **"Generate a token"**
- **COPIEZ la clé** (commence par `hf_...`)

### 3. Configurer CTBA Platform

#### Option A: Fichier `.env` (Recommandé)
```bash
cd backend
cp .env.example .env
```

Éditez `.env` et ajoutez:
```env
AI_PROVIDER=huggingface
HUGGINGFACE_API_KEY=hf_VotreCléIci...
HUGGINGFACE_MODEL=mistral-7b
```

#### Option B: Variable d'environnement PowerShell
```powershell
$env:AI_PROVIDER="huggingface"
$env:HUGGINGFACE_API_KEY="hf_VotreCléIci..."
$env:HUGGINGFACE_MODEL="mistral-7b"
```

### 4. Redémarrer le backend
```powershell
cd backend
python main.py
```

---

## 🎯 Modèles Disponibles (tous GRATUITS)

| Modèle | Description | Cas d'usage |
|--------|-------------|-------------|
| **mistral-7b** ⭐ | Mistral 7B Instruct v0.2 | **Recommandé** - Excellent français, rapide |
| **mixtral-8x7b** 🚀 | Mixtral 8x7B Instruct | Très puissant, plus lent |
| **zephyr-7b** ⚡ | Zephyr 7B Beta | Rapide et efficace |
| **llama2-7b** 🦙 | Meta Llama 2 7B Chat | Classique et fiable |
| **openchat** 💬 | OpenChat 3.5 | Conversationnel |

Pour changer de modèle:
```env
HUGGINGFACE_MODEL=mixtral-8x7b
```

---

## 💰 Limites Gratuites

### Inference API (Gratuit)
- ✅ **Aucun coût**
- ✅ Rate limit raisonnable (suffisant pour usage normal)
- ⏱️ Première requête peut prendre 20-30s (chargement du modèle)
- ⚡ Requêtes suivantes: ~2-5s

### Si vous dépassez les limites
Options:
1. **Attendre quelques minutes** (les quotas se réinitialisent)
2. **Passer à Hugging Face Pro** ($9/mois, limites plus élevées)
3. **Utiliser fallback temporaire** (Simple AI templates)

---

## 🔧 Dépannage

### ❌ Erreur: "Invalid API key"
- Vérifiez que la clé commence par `hf_`
- Régénérez une nouvelle clé sur https://huggingface.co/settings/tokens

### ❌ Erreur 503: "Model is loading"
- C'est normal pour la première requête
- Le système attend automatiquement (20-30s)
- Réessayez si timeout

### ❌ Erreur 429: "Rate limit exceeded"
- Attendez 5-10 minutes
- Les quotas se réinitialisent automatiquement
- OU configurez temporairement: `AI_PROVIDER=simple`

### ❌ Réponse vide ou incomplète
- Changez de modèle: `HUGGINGFACE_MODEL=zephyr-7b`
- Le système utilise automatiquement un fallback de qualité

---

## 📊 Comparaison avec OpenRouter

| Critère | Hugging Face | OpenRouter |
|---------|--------------|------------|
| **Coût** | ✅ GRATUIT | ❌ Payant ($) |
| **Quotas** | ✅ Généreux | ⚠️ Par token |
| **Latence** | ⏱️ 2-5s | ⚡ 1-2s |
| **Qualité** | ✅ Excellente | ✅ Excellente |
| **Setup** | 🟢 Simple | 🟢 Simple |

**Verdict**: Hugging Face est **parfait pour CTBA** (gratuit, qualité équivalente)

---

## ✨ Test Rapide

```powershell
# Vérifier la configuration
cd backend
python -c "import os; from dotenv import load_dotenv; load_dotenv('.env'); print('API Key:', os.getenv('HUGGINGFACE_API_KEY')[:10] + '...' if os.getenv('HUGGINGFACE_API_KEY') else 'NOT SET')"

# Tester une remédiation
curl -X POST "http://localhost:8000/api/ai/remediation/CVE-2024-1234"

# Vérifier le statut IA
curl "http://localhost:8000/api/ai/status"
```

**Résultat attendu**:
```json
{
  "status": "ready",
  "provider": "Hugging Face",
  "model": "mistral-7b",
  "cost": "FREE"
}
```

---

## 🎓 Ressources

- Documentation Hugging Face: https://huggingface.co/docs/api-inference/
- Modèles disponibles: https://huggingface.co/models?pipeline_tag=text-generation
- Dashboard API: https://huggingface.co/settings/tokens

---

**💡 Besoin d'aide ?**
Vérifiez les logs du backend pour les messages d'erreur détaillés.
