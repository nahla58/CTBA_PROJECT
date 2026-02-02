# 📚 EXEMPLES PRATIQUES - Système de Bulletins

## 🎯 Cas d'Utilisation 1: Créer un Bulletin avec Groupement Automatique

### Scénario
Un analyste de sécurité découvre 5 CVE critiques affectant l'infrastructure de l'entreprise et doit créer un bulletin urgence à envoyer à tous les administrateurs.

### Via l'Interface Web

```
1. Cliquer sur onglet "Créer un Bulletin"
2. Remplir:
   - Titre: "URGENT: Bulletin Sécurité - Vulnérabilités Critiques"
   - Contenu: "Plusieurs CVE critiques découvertes..."
   - CVE: CVE-2024-1234, CVE-2024-5678, CVE-2024-9012, 
           CVE-2024-3456, CVE-2024-7890
   - Régions: ☑ NORAM, ☑ EUROPE, ☑ APMEA

3. Cliquer "Créer le Bulletin"

4. Résultat: Bulletin créé avec groupement automatique
   ✅ DRAFT status
   ✅ 3 groupes créés automatiquement:
      - Apache / Log4j (2 CVE)
      - Microsoft / Windows (2 CVE)
      - Cisco / IOS (1 CVE)
```

### Via l'API

```bash
curl -X POST http://localhost:8000/api/bulletins/create-with-grouping \
  -F "title=URGENT: Bulletin Sécurité - Vulnérabilités Critiques" \
  -F "body=Plusieurs CVE critiques découvertes lors de notre audit..." \
  -F "regions=[\"NORAM\",\"EUROPE\",\"APMEA\"]" \
  -F "cve_ids=CVE-2024-1234,CVE-2024-5678,CVE-2024-9012,CVE-2024-3456,CVE-2024-7890" \
  -F "created_by=security_analyst"
```

### Réponse API

```json
{
  "success": true,
  "bulletin_id": 42,
  "message": "Bulletin créé avec automatic grouping de 3 technology groups",
  "bulletin": {
    "id": 42,
    "title": "URGENT: Bulletin Sécurité - Vulnérabilités Critiques",
    "status": "DRAFT",
    "created_by": "security_analyst",
    "created_at": "2024-01-26T14:30:00",
    "cve_count": 5,
    "regions": ["NORAM", "EUROPE", "APMEA"],
    "groupings": [
      {
        "vendor": "Apache",
        "product": "Log4j",
        "cve_count": 2,
        "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
        "remediation_guidance": "Mettre à jour vers Log4j 2.18 ou supérieur"
      },
      {
        "vendor": "Microsoft",
        "product": "Windows Server 2019",
        "cve_count": 2,
        "cve_ids": ["CVE-2024-9012", "CVE-2024-3456"],
        "remediation_guidance": "Appliquer KB5034127"
      },
      {
        "vendor": "Cisco",
        "product": "IOS XE",
        "cve_count": 1,
        "cve_ids": ["CVE-2024-7890"],
        "remediation_guidance": "Mettre à jour le firmware vers 17.9.x"
      }
    ]
  }
}
```

---

## 📎 Cas d'Utilisation 2: Ajouter des Pièces Jointes

### Scénario
Après créer le bulletin, l'analyste veut ajouter:
- Le patch Log4j à télécharger
- Le guide d'installation Microsoft
- Un fichier de configuration Cisco

### Interface Web

```
1. Cliquer "👁️ Détails" sur le bulletin
2. Section "Pièces Jointes" → "Ajouter une pièce jointe"
3. Pour chaque fichier:
   - Sélectionner le fichier
   - Choisir le type (PATCH, GUIDE, CONFIG, etc.)
   - Écrire une description
   - Cliquer "Uploader"

Exemple 1 - Log4j Patch:
   Fichier: log4j-2.18.0-all.zip
   Type: PATCH
   Description: "Log4j 2.18.0 with security fixes"
   ✅ Uploadé (45 MB)

Exemple 2 - Microsoft Guide:
   Fichier: KB5034127_Installation_Guide.pdf
   Type: GUIDE
   Description: "Step-by-step guide pour KB5034127"
   ✅ Uploadé (2 MB)

Exemple 3 - Cisco Config:
   Fichier: cisco_ios_config.conf
   Type: CONFIG
   Description: "Configuration recommandée pour IOS XE"
   ✅ Uploadé (50 KB)
```

### Via l'API

```bash
# Ajouter le patch Log4j
curl -X POST http://localhost:8000/api/bulletins/bulletins/42/attachments \
  -F "file=@log4j-2.18.0-all.zip" \
  -F "attachment_type=PATCH" \
  -F "description=Log4j 2.18.0 with security fixes" \
  -F "uploaded_by=security_analyst"

# Ajouter le guide Microsoft
curl -X POST http://localhost:8000/api/bulletins/bulletins/42/attachments \
  -F "file=@KB5034127_Installation_Guide.pdf" \
  -F "attachment_type=GUIDE" \
  -F "description=Step-by-step guide pour KB5034127" \
  -F "uploaded_by=security_analyst"

# Ajouter la config Cisco
curl -X POST http://localhost:8000/api/bulletins/bulletins/42/attachments \
  -F "file=@cisco_ios_config.conf" \
  -F "attachment_type=CONFIG" \
  -F "description=Configuration recommandée pour IOS XE" \
  -F "uploaded_by=security_analyst"
```

### Affichage dans le Bulletin

```
📎 PIÈCES JOINTES

┌─ log4j-2.18.0-all.zip (PATCH, 45 MB)
│  Description: Log4j 2.18.0 with security fixes
│  Téléchargements: 23
│  [⬇️ Télécharger]

┌─ KB5034127_Installation_Guide.pdf (GUIDE, 2 MB)
│  Description: Step-by-step guide pour KB5034127
│  Téléchargements: 45
│  [⬇️ Télécharger]

└─ cisco_ios_config.conf (CONFIG, 50 KB)
   Description: Configuration recommandée pour IOS XE
   Téléchargements: 12
   [⬇️ Télécharger]
```

---

## 🌍 Cas d'Utilisation 3: Envoyer aux Régions Spécifiques

### Scénario
Le manager approuve le bulletin et décide d'envoyer:
- NORAM: Tous les équipes US/Canada
- EUROPE: Centres de données EU
- APMEA: Bureau Singapour
- PAS LATAM: Sera envoyé séparément après traduction

### Interface Web

```
1. Cliquer [✉️ Envoyer] sur le bulletin
2. Sélectionner les régions:
   ☑ NORAM   (50 destinataires)
   ☑ EUROPE  (35 destinataires)
   ☑ APMEA   (15 destinataires)
   ☐ LATAM   (sera fait après)
3. Cliquer "Envoyer"

Résultat:
✅ Bulletin envoyé à 100 destinataires
✅ Statut changé en "SENT"
✅ Logs de livraison créés
```

### Via l'API

```bash
curl -X POST http://localhost:8000/api/bulletins/bulletins/42/send \
  -F "regions=[\"NORAM\",\"EUROPE\",\"APMEA\"]" \
  -F "delivery_method=EMAIL" \
  -F "sent_by=manager_security"
```

### Réponse

```json
{
  "success": true,
  "message": "Bulletin envoyé à 3 régions",
  "regions_sent": ["NORAM", "EUROPE", "APMEA"],
  "bulletin": {
    "id": 42,
    "status": "SENT",
    "sent_at": "2024-01-26T14:45:00",
    "sent_by": "manager_security",
    "delivery_status": {
      "total": 100,
      "sent": 100,
      "failed": 0
    }
  }
}
```

### Destinataires par Région

```
NORAM (50 destinataires):
├─ alert@company-us.com (SENT)
├─ security@it-north.com (SENT)
├─ ciso-office@headquarters.com (SENT)
└─ ... 47 autres

EUROPE (35 destinataires):
├─ securite@paris.company.fr (SENT)
├─ sicherheit@berlin.company.de (SENT)
├─ security@london.company.uk (SENT)
└─ ... 32 autres

APMEA (15 destinataires):
├─ security@singapore.company.com (SENT)
├─ ciso@australia.company.com.au (SENT)
├─ security@tokyo.company.jp (SENT)
└─ ... 12 autres
```

---

## 📊 Cas d'Utilisation 4: Voir l'Historique de Livraison

### Requête SQL

```sql
-- Voir le suivi de livraison par région
SELECT 
  r.name as region,
  COUNT(*) as total_recipients,
  SUM(CASE WHEN bdl.delivery_status = 'SENT' THEN 1 ELSE 0 END) as sent,
  SUM(CASE WHEN bdl.delivery_status = 'FAILED' THEN 1 ELSE 0 END) as failed,
  SUM(CASE WHEN bdl.delivery_status = 'BOUNCED' THEN 1 ELSE 0 END) as bounced,
  COUNT(DISTINCT bdl.recipient_email) as unique_recipients
FROM bulletin_delivery_log bdl
JOIN bulletin_regions r ON bdl.region_id = r.id
WHERE bdl.bulletin_id = 42
GROUP BY r.name
ORDER BY r.name;
```

### Résultat

```
region  | total | sent | failed | bounced | unique
--------|-------|------|--------|---------|----------
APMEA   |   15  |  15  |   0    |    0    |   15
EUROPE  |   35  |  34  |   1    |    0    |   35
NORAM   |   50  |  50  |   0    |    0    |   50
```

### Détails des Erreurs

```sql
SELECT 
  recipient_email,
  delivery_status,
  error_message,
  sent_time
FROM bulletin_delivery_log
WHERE bulletin_id = 42 AND delivery_status = 'FAILED'
ORDER BY sent_time DESC;
```

### Résultat

```
recipient_email              | status | error                    | time
-----------------------------|--------|--------------------------|------------------
sicherheit@berlin.invalid    | FAILED | Invalid email address    | 2024-01-26 14:45:12
```

---

## 🔄 Cas d'Utilisation 5: Archiver une Région

### Scénario
L'entreprise ferme son bureau LATAM et doit archiver la région sans perdre l'historique.

### Via l'API

```bash
curl -X PUT http://localhost:8000/api/bulletins/regions/3/archive \
  -F "archived_by=admin"
```

### Réponse

```json
{
  "success": true,
  "message": "Region 3 archived successfully"
}
```

### Vérification en BD

```sql
-- Vérifier l'archivage
SELECT id, name, is_active, archived_at 
FROM bulletin_regions 
WHERE id = 3;

-- Résultat:
id  | name  | is_active | archived_at
----|-------|-----------|---------------------
3   | LATAM | f         | 2024-01-26 14:50:00

-- Les données historiques restent intactes
SELECT COUNT(*) FROM bulletins 
WHERE regions @> '["LATAM"]';

-- Résultat: 15 bulletins historiques toujours accessible
```

### Ajouter une Nouvelle Région

```bash
curl -X POST http://localhost:8000/api/bulletins/regions \
  -F "name=OCEANIA" \
  -F "description=New Oceania region" \
  -F "recipients=security@australia.com,security@newzealand.com"
```

**Résultat:**
- ✅ Nouvelle région OCEANIA créée
- ✅ Tous les 15 bulletins LATAM restent accessibles
- ✅ Futures requêtes peuvent utiliser OCEANIA

---

## 📈 Cas d'Utilisation 6: Créer un Rapport de Bulletins

### Requête SQL - Bulletins par Mois

```sql
SELECT 
  DATE_TRUNC('month', created_at) as month,
  COUNT(*) as bulletins_created,
  SUM(cve_count) as total_cves,
  COUNT(DISTINCT created_by) as analysts
FROM bulletins
WHERE created_at >= '2024-01-01'
GROUP BY DATE_TRUNC('month', created_at)
ORDER BY month DESC;
```

### Résultat

```
month     | bulletins | cves | analysts
-----------|-----------|------|----------
2024-01    |    8      | 42   |   3
2023-12    |   15      | 87   |   5
2023-11    |   12      | 64   |   4
```

### Requête SQL - Efficacité de Livraison

```sql
SELECT 
  b.id,
  b.title,
  COUNT(DISTINCT bdl.recipient_email) as recipients,
  SUM(CASE WHEN bdl.delivery_status = 'SENT' THEN 1 ELSE 0 END) as sent,
  SUM(CASE WHEN bdl.delivery_status = 'FAILED' THEN 1 ELSE 0 END) as failed,
  ROUND(100.0 * SUM(CASE WHEN bdl.delivery_status = 'SENT' THEN 1 ELSE 0 END) / 
        COUNT(DISTINCT bdl.recipient_email), 2) as delivery_rate
FROM bulletins b
LEFT JOIN bulletin_delivery_log bdl ON b.id = bdl.bulletin_id
WHERE b.status = 'SENT'
GROUP BY b.id, b.title
ORDER BY b.created_at DESC
LIMIT 10;
```

### Résultat

```
id | title                                    | recipients | sent | failed | rate
----|------------------------------------------|------------|------|--------|-------
42 | URGENT: Bulletin Sécurité - Critiques   | 100        | 99   | 1      | 99.00%
41 | Bulletin Janvier - Remédiation Apache   | 85         | 85   | 0      | 100.00%
40 | Patch Microsoft - KB5034127             | 120        | 120  | 0      | 100.00%
```

---

## 🔍 Cas d'Utilisation 7: Récupérer l'Historique Complet

### Requête SQL

```sql
SELECT 
  version_number,
  change_type,
  changed_by,
  changed_at,
  change_reason,
  previous_state::jsonb ->> 'status' as prev_status,
  new_state::jsonb ->> 'status' as new_status
FROM bulletin_version_history
WHERE bulletin_id = 42
ORDER BY version_number DESC;
```

### Résultat (Timeline)

```
v# | type            | changed_by         | when                | prev  | new
---|-----------------|-------------------|---------------------|-------|----------
4  | STATUS_CHANGED  | manager_security   | 2024-01-26 14:45:00 | DRAFT | SENT
3  | CONTENT_UPDATED | security_analyst   | 2024-01-26 14:35:00 | DRAFT | DRAFT
2  | ATTACHMENT_ADD  | security_analyst   | 2024-01-26 14:32:00 | DRAFT | DRAFT
1  | CREATED         | security_analyst   | 2024-01-26 14:30:00 | null  | DRAFT
```

---

## 📱 Cas d'Utilisation 8: Affichage Mobile

L'interface répond aux tablettes et mobiles:

```
┌─────────────────────┐
│ 📧 Bulletins       │
├─────────────────────┤
│ [📋] [✏️] [🌍]      │
│                     │
│ ╔════════════════╗  │
│ ║ Bulletin Jan   ║  │
│ ║ [DRAFT]        ║  │
│ ║ 5 CVE, NORAM   ║  │
│ ║ [👁️] [✉️] [⏸️]  ║  │
│ ╚════════════════╝  │
│                     │
│ ╔════════════════╗  │
│ ║ Bulletin Dec   ║  │
│ ║ [SENT]         ║  │
│ ║ 3 CVE, ALL     ║  │
│ ║ [👁️] [📦]      ║  │
│ ╚════════════════╝  │
└─────────────────────┘
```

---

## ✅ Points Clés à Retenir

1. **Groupement Automatique** - CVE groupés SANS action manuelle
2. **Régions Flexibles** - Ajouter/archiver sans impacter l'historique
3. **Pièces Jointes Sécurisées** - Checksum + téléchargement trackés
4. **Multiples Statuts** - DRAFT → SENT → ARCHIVED (flux clair)
5. **Audit Complet** - Chaque changement enregistré
6. **API Complete** - Tous les cas d'utilisation couverts

---

**Prêt à utiliser en production!** 🚀
