# Configuration du Système de Mailing CTBA

## ✅ État Actuel

### Implémentation Code
- ✅ EmailService complet avec support SMTP
- ✅ RegionMailingService pour gestion mailing lists
- ✅ BulletinService pour création/envoi bulletins
- ✅ BulletinReminderService pour rappels automatiques
- ✅ Tous les endpoints API (/api/bulletins, /api/regions, etc.)
- ✅ Tables base de données créées

### ⚠️ Configuration Manquante

Pour que le mailing fonctionne, vous devez :

## 1️⃣ Configurer SMTP

### Option A: Variables d'environnement (PRODUCTION)

Créez un fichier `.env` dans `backend/` :

```env
# Configuration SMTP
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_FROM_EMAIL=votre-email@gmail.com
SMTP_PASSWORD=votre-mot-de-passe-app

# Pour Gmail, utilisez un "App Password" :
# https://myaccount.google.com/apppasswords
```

Puis chargez-le avant de démarrer :

**PowerShell:**
```powershell
cd C:\essai\CTBA_PROJECT\backend

# Charger les variables
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}

# Démarrer le backend
python main.py
```

**Bash/Linux:**
```bash
cd backend
export $(cat .env | xargs)
python main.py
```

### Option B: Mode Test (DÉVELOPPEMENT)

Le système peut fonctionner en **mode simulation** sans SMTP :
- Les emails seront loggés dans la console au lieu d'être envoyés
- Utile pour tester la logique sans vraie configuration email

```python
# Dans EmailService
test_mode=True  # Les emails seront loggés uniquement
```

## 2️⃣ Configurer les Régions

### Via API (Recommandé)

```bash
# Se connecter d'abord
curl -X POST "http://localhost:8000/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password123"}'

# Récupérer le token de la réponse, puis :

# Créer région NORAM
curl -X POST "http://localhost:8000/api/regions" \
  -H "Authorization: Bearer <votre-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "NORAM",
    "description": "North America",
    "recipients": "security-noram@example.com,ops-noram@example.com"
  }'

# Créer région Europe
curl -X POST "http://localhost:8000/api/regions" \
  -H "Authorization: Bearer <votre-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Europe",
    "description": "Europe",
    "recipients": "security-eu@example.com,ops-eu@example.com"
  }'

# Créer région LATAM
curl -X POST "http://localhost:8000/api/regions" \
  -H "Authorization: Bearer <votre-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "LATAM",
    "description": "Latin America",
    "recipients": "security-latam@example.com"
  }'

# Créer région APMEA
curl -X POST "http://localhost:8000/api/regions" \
  -H "Authorization: Bearer <votre-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "APMEA",
    "description": "Asia Pacific & Middle East",
    "recipients": "security-apmea@example.com"
  }'
```

### Via Script Python

Créez et exécutez `init_regions.py` :

```python
import sqlite3

conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

regions = [
    ('NORAM', 'North America', 'security-noram@example.com,ops-noram@example.com'),
    ('Europe', 'Europe', 'security-eu@example.com,ops-eu@example.com'),
    ('LATAM', 'Latin America', 'security-latam@example.com'),
    ('APMEA', 'Asia Pacific & Middle East', 'security-apmea@example.com')
]

for name, description, recipients in regions:
    cursor.execute('''
        INSERT INTO regions (name, description, recipients, created_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ''', (name, description, recipients))
    print(f"✅ Région '{name}' créée")

conn.commit()
conn.close()
print("\n✅ Toutes les régions ont été créées")
```

Puis :
```bash
cd backend
python init_regions.py
```

## 3️⃣ Les Mailing Lists Sont Auto-Configurées

Une fois les régions créées, les mailing lists seront **automatiquement initialisées** au démarrage du backend :

```
🚀 Starting CTBA Platform...
✅ Database initialized
📧 Initializing region mailing lists from regions...
✅ Enhanced bulletin delivery engine started
```

## 🧪 Tester le Système

### Test 1: Créer un bulletin

```bash
curl -X POST "http://localhost:8000/api/bulletins" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Bulletin - CVE Critical Alert",
    "body": "<html><body><h1>Security Alert</h1><p>This is a test bulletin.</p></body></html>",
    "regions": ["NORAM", "Europe"]
  }'
```

### Test 2: Envoyer le bulletin

```bash
curl -X POST "http://localhost:8000/api/bulletins/1/send" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Test 3: Vérifier l'historique

```bash
curl "http://localhost:8000/api/bulletins/1/delivery-history" \
  -H "Authorization: Bearer <token>"
```

## 📊 Mode Test (Sans SMTP)

Si vous voulez tester **sans configurer SMTP**, le système fonctionnera en mode simulation :

**Logs attendus :**
```
⚠️ SMTP not configured; email will be logged instead of sent
📧 Would send email to: security-noram@example.com, ops-noram@example.com
   Subject: Test Bulletin - CVE Critical Alert
   Body length: 123 characters
✅ Email logged (test mode)
```

## 🔧 Configuration SMTP Recommandée par Fournisseur

### Gmail
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_FROM_EMAIL=votre-email@gmail.com
SMTP_PASSWORD=app-password-16-caracteres
```

### Outlook/Office365
```env
SMTP_SERVER=smtp.office365.com
SMTP_PORT=587
SMTP_FROM_EMAIL=votre-email@outlook.com
SMTP_PASSWORD=votre-mot-de-passe
```

### SendGrid
```env
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_FROM_EMAIL=noreply@votre-domaine.com
SMTP_PASSWORD=votre-api-key
```

### Serveur SMTP Local (Test)
```env
SMTP_SERVER=localhost
SMTP_PORT=1025
SMTP_FROM_EMAIL=noreply@localhost
SMTP_PASSWORD=
```

Avec [MailHog](https://github.com/mailhog/MailHog) ou [smtp4dev](https://github.com/rnwood/smtp4dev) pour capturer les emails en local.

## 📝 Résumé

**Le système de mailing est 100% implémenté**, mais nécessite :

1. ✅ Configuration SMTP (ou mode test)
2. ✅ Création des régions
3. ✅ Redémarrage du backend

Une fois configuré, vous pourrez :
- ✅ Créer des bulletins
- ✅ Les envoyer à plusieurs régions
- ✅ Recevoir des rappels automatiques (7j, 14j, 30j)
- ✅ Consulter l'historique de delivery
- ✅ Voir les analytics en temps réel

**Statut:** 🟡 Prêt mais non configuré
