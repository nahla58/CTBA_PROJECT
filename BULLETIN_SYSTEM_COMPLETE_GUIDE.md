# 📧 Système de Bulletins CTBA - Guide Complet

## Vue d'Ensemble

Le système de bulletins CTBA implémente les exigences 2.3 à 2.6 des spécifications :

✅ **2.3 - Génération de Bulletins**
- Groupement automatique des CVEs par technologie/produit
- Sélection de régions multiples (NORAM, LATAM, Europe, APMEA)
- Support de pièces jointes
- Statuts multiples (DRAFT, SENT, NOT_PROCESSED)

✅ **2.4 - Moteur de Delivery**
- Envoi via template HTML email standardisé
- Résolution automatique des listes To/Cc/Bcc par région
- Logging complet des actions d'envoi

✅ **2.5 - Rappels & Escalation**
- Rappel automatique à 7 jours
- Rappel automatique à 14 jours
- Escalation automatique à 30 jours
- Fermeture manuelle des bulletins

✅ **2.6 - KPIs & Analytics**
- Dashboard performance analyste
- Dashboard opérationnel
- Timelines des bulletins
- Monitoring charge de travail
- Dashboard temps réel

---

## 📋 API Endpoints - Bulletins

### Créer un Bulletin

```bash
POST /api/bulletins
Content-Type: application/json
Authorization: Bearer <token>

{
  "title": "Security Bulletin - Apache Log4j Critical Vulnerability",
  "body": "<html><body><h1>Critical Security Update</h1>...</body></html>",
  "regions": ["NORAM", "Europe", "APMEA"],
  "cve_ids": ["CVE-2024-12345", "CVE-2024-12346"]
}
```

**Réponse:**
```json
{
  "id": 1,
  "title": "Security Bulletin - Apache Log4j Critical Vulnerability",
  "regions": ["NORAM", "Europe", "APMEA"],
  "status": "DRAFT",
  "created_by": "analyst1"
}
```

### Lister les Bulletins

```bash
GET /api/bulletins?status=DRAFT&limit=50&offset=0
Authorization: Bearer <token>
```

**Filtres disponibles:**
- `status`: DRAFT, SENT, NOT_PROCESSED
- `region`: Filter par région
- `limit`: Nombre max de résultats (max: 500)
- `offset`: Pagination

**Réponse:**
```json
{
  "bulletins": [
    {
      "id": 1,
      "title": "Security Bulletin...",
      "regions": ["NORAM", "Europe"],
      "status": "DRAFT",
      "created_at": "2026-02-01T15:30:00",
      "cve_count": 3
    }
  ],
  "total": 15,
  "limit": 50,
  "offset": 0
}
```

### Obtenir Détail d'un Bulletin

```bash
GET /api/bulletins/1
Authorization: Bearer <token>
```

**Réponse:**
```json
{
  "id": 1,
  "title": "Security Bulletin...",
  "body": "<html>...</html>",
  "regions": ["NORAM", "Europe"],
  "status": "DRAFT",
  "created_by": "analyst1",
  "created_at": "2026-02-01T15:30:00",
  "cves": [
    {
      "cve_id": "CVE-2024-12345",
      "severity": "CRITICAL",
      "score": 9.8
    }
  ],
  "grouped_cves": [
    {
      "technology": "Apache: Log4j",
      "cves": [...],
      "count": 3
    }
  ],
  "attachments": [],
  "attachment_count": 0
}
```

### Mettre à Jour un Bulletin

```bash
PUT /api/bulletins/1
Content-Type: application/json
Authorization: Bearer <token>

{
  "title": "Updated Title",
  "body": "<html>Updated content</html>",
  "status": "DRAFT"
}
```

### Ajouter une Pièce Jointe

```bash
POST /api/bulletins/1/attachments
Content-Type: multipart/form-data
Authorization: Bearer <token>

file: <binary file data>
```

**Réponse:**
```json
{
  "id": 1,
  "bulletin_id": 1,
  "filename": "remediation_guide.pdf",
  "path": "attachments/bulletin_1_remediation_guide.pdf"
}
```

---

## 📤 Envoi de Bulletins

### Envoyer un Bulletin

```bash
POST /api/bulletins/1/send
Content-Type: application/json
Authorization: Bearer <token>

{
  "regions_override": ["NORAM", "Europe"]
}
```

**Fonctionnalités:**
- ✅ Résout automatiquement les listes To/Cc/Bcc pour chaque région
- ✅ Envoie l'email avec template HTML
- ✅ Log toutes les actions d'envoi
- ✅ Met à jour le statut à "SENT"
- ✅ Initialise le timestamp `sent_at` pour les rappels

**Réponse:**
```json
{
  "bulletin_id": 1,
  "results": [
    {
      "region": "NORAM",
      "status": "success",
      "recipients_count": 12
    },
    {
      "region": "Europe",
      "status": "success",
      "recipients_count": 8
    }
  ],
  "total_regions": 2,
  "successful": 2
}
```

### Historique de Delivery

```bash
GET /api/bulletins/1/delivery-history
Authorization: Bearer <token>
```

**Réponse:**
```json
{
  "bulletin_id": 1,
  "history": [
    {
      "id": 1,
      "action": "SENT",
      "region": "NORAM",
      "recipients": "security@example.com, ops@example.com",
      "message": "Bulletin sent successfully to 12 recipients",
      "created_at": "2026-02-01T16:00:00"
    },
    {
      "id": 2,
      "action": "REMINDER_1",
      "region": "NORAM",
      "recipients": "security@example.com, ops@example.com",
      "message": "Reminder sent after 7 days",
      "created_at": "2026-02-08T16:00:00"
    }
  ],
  "count": 2
}
```

---

## ⏰ Rappels Automatiques

Le système envoie automatiquement des rappels selon ce calendrier:

| Jour | Action | Type | Description |
|------|--------|------|-------------|
| 7 | REMINDER_1 | Rappel 1 | Premier rappel automatique |
| 14 | REMINDER_2 | Rappel 2 | Deuxième rappel automatique |
| 30 | ESCALATION | Escalation | Escalation automatique |

### Vérification des Rappels

Le service vérifie les bulletins **toutes les heures** et envoie les rappels automatiquement.

### Fermer Manuellement un Bulletin

```bash
POST /api/bulletins/1/close
Authorization: Bearer <token>
```

**Effet:**
- Change le statut à "NOT_PROCESSED"
- Arrête tous les rappels futurs
- Log l'action de fermeture

**Réponse:**
```json
{
  "message": "Bulletin 1 closed",
  "success": true
}
```

### Statistiques des Rappels

```bash
GET /api/bulletins/reminders/statistics
Authorization: Bearer <token>
```

**Réponse:**
```json
{
  "status_counts": {
    "DRAFT": 5,
    "SENT": 12,
    "NOT_PROCESSED": 3
  },
  "awaiting_reminder_1": 2,
  "awaiting_reminder_2": 1,
  "awaiting_escalation": 0,
  "total_sent": 12
}
```

---

## 🌍 Gestion des Régions

### Lister les Régions

```bash
GET /api/regions
Authorization: Bearer <token>
```

**Réponse:**
```json
{
  "regions": [
    {
      "id": 1,
      "name": "NORAM",
      "description": "North America",
      "recipients": ["security-noram@example.com", "ops-noram@example.com"],
      "created_at": "2026-01-15T10:00:00"
    },
    {
      "id": 2,
      "name": "Europe",
      "description": "Europe",
      "recipients": ["security-eu@example.com"],
      "created_at": "2026-01-15T10:00:00"
    }
  ],
  "count": 4
}
```

### Créer une Région

```bash
POST /api/regions
Content-Type: application/json
Authorization: Bearer <token>
# Requires: ADMINISTRATOR or VOC_LEAD role

{
  "name": "LATAM",
  "description": "Latin America",
  "recipients": "security-latam@example.com, ops-latam@example.com"
}
```

### Mettre à Jour une Région

```bash
PUT /api/regions/1
Content-Type: application/json
Authorization: Bearer <token>
# Requires: ADMINISTRATOR or VOC_LEAD role

{
  "description": "North America (Updated)",
  "recipients": "security-noram@example.com, new-contact@example.com"
}
```

**Note:** Pour archiver une région, mettez à jour la description avec "[ARCHIVED]".

---

## 📊 Analytics & KPIs

### Performance des Analystes

```bash
GET /api/analytics/analyst-performance?analyst_username=analyst1&days=30
Authorization: Bearer <token>
```

**Paramètres:**
- `analyst_username` (optionnel): Filter par analyste spécifique
- `days` (défaut: 30, max: 365): Période d'analyse

**Réponse:**
```json
{
  "period_days": 30,
  "analysts": [
    {
      "analyst": "analyst1",
      "accepted": 45,
      "rejected": 12,
      "pending": 3,
      "total": 60,
      "throughput_per_day": 2.0,
      "actions": {
        "ACCEPT": 45,
        "REJECT": 12,
        "UPDATE": 8
      }
    }
  ]
}
```

### Dashboard Opérationnel

```bash
GET /api/analytics/operational-dashboard
Authorization: Bearer <token>
```

**Réponse:**
```json
{
  "cve_by_source": {
    "NVD": 85,
    "CVEdetails": 42,
    "CVE.org enrichment": 19
  },
  "cve_by_severity": {
    "CRITICAL": 12,
    "HIGH": 45,
    "MEDIUM": 67,
    "LOW": 22
  },
  "cve_by_decision": {
    "ACCEPTED": 78,
    "REJECTED": 34,
    "PENDING": 34
  },
  "bulletin_by_status": {
    "DRAFT": 5,
    "SENT": 12,
    "NOT_PROCESSED": 3
  },
  "ingestion_trend_7days": [
    {"date": "2026-02-01", "count": 23},
    {"date": "2026-01-31", "count": 18}
  ],
  "total_cves": 146,
  "total_bulletins": 20
}
```

### Timelines des Bulletins

```bash
GET /api/analytics/bulletin-timelines
Authorization: Bearer <token>
```

**Réponse:**
```json
{
  "total_bulletins": 20,
  "draft": 5,
  "sent": 12,
  "closed": 3,
  "avg_creation_to_send_hours": 4.5,
  "bulletins_awaiting_reminder": 2,
  "bulletins_in_escalation": 0
}
```

### Charge de Travail des Reviewers

```bash
GET /api/analytics/reviewer-workload
Authorization: Bearer <token>
```

**Réponse:**
```json
{
  "total_pending": 34,
  "pending_by_severity": {
    "CRITICAL": 3,
    "HIGH": 12,
    "MEDIUM": 15,
    "LOW": 4
  },
  "workload_by_analyst": {
    "analyst1": 15,
    "lead1": 10,
    "analyst2": 9
  },
  "avg_processing_hours_by_analyst": {
    "analyst1": 2.3,
    "lead1": 1.8,
    "analyst2": 3.1
  }
}
```

### Dashboard Temps Réel

```bash
GET /api/analytics/real-time-dashboard
Authorization: Bearer <token>
```

**Idéal pour dashboards en direct - rafraîchir toutes les 30-60 secondes**

**Réponse:**
```json
{
  "timestamp": "2026-02-01T16:45:23.123456",
  "pending_cves": 34,
  "today_ingestion": 23,
  "active_bulletins": 17,
  "recent_actions": [
    {
      "action": "ACCEPT",
      "analyst": "analyst1",
      "cve_id": "CVE-2024-12345",
      "timestamp": "2026-02-01T16:40:15"
    }
  ],
  "hourly_velocity": 8
}
```

---

## 🔄 Workflow Complet - Exemple

### Étape 1: Créer un Bulletin

```bash
curl -X POST "http://localhost:8000/api/bulletins" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Critical Apache Log4j Vulnerability",
    "body": "<html><body><h1>Security Alert</h1><p>Critical vulnerability discovered...</p></body></html>",
    "regions": ["NORAM", "Europe", "APMEA"],
    "cve_ids": ["CVE-2024-12345"]
  }'
```

### Étape 2: Ajouter une Pièce Jointe (optionnel)

```bash
curl -X POST "http://localhost:8000/api/bulletins/1/attachments" \
  -H "Authorization: Bearer <token>" \
  -F "file=@remediation_guide.pdf"
```

### Étape 3: Envoyer le Bulletin

```bash
curl -X POST "http://localhost:8000/api/bulletins/1/send" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Étape 4: Rappels Automatiques

Le système enverra automatiquement:
- **Jour 7**: Rappel 1 à toutes les régions
- **Jour 14**: Rappel 2 à toutes les régions
- **Jour 30**: Escalation à toutes les régions

### Étape 5: Fermer le Bulletin (quand résolu)

```bash
curl -X POST "http://localhost:8000/api/bulletins/1/close" \
  -H "Authorization: Bearer <token>"
```

---

## 🎯 Points Clés

### Groupement Automatique des CVEs

Lorsque vous obtenez le détail d'un bulletin (`GET /api/bulletins/{id}`), les CVEs sont automatiquement groupés par technologie/produit:

```json
{
  "grouped_cves": [
    {
      "technology": "Apache: Log4j",
      "cves": [
        {"cve_id": "CVE-2024-12345", "severity": "CRITICAL"},
        {"cve_id": "CVE-2024-12346", "severity": "HIGH"}
      ],
      "count": 2
    },
    {
      "technology": "Microsoft: Windows",
      "cves": [
        {"cve_id": "CVE-2024-12347", "severity": "MEDIUM"}
      ],
      "count": 1
    }
  ]
}
```

### Support des Régions

- ✅ Ajout dynamique de nouvelles régions sans impact sur l'historique
- ✅ Archivage de régions (mettre "[ARCHIVED]" dans la description)
- ✅ Historique complet des envois par région préservé

### Logging et Audit Trail

Toutes les actions sont loggées dans `bulletin_logs`:
- Envoi initial (SENT)
- Rappel 1 (REMINDER_1)
- Rappel 2 (REMINDER_2)
- Escalation (ESCALATION)
- Fermeture manuelle (MANUALLY_CLOSED)

### Service de Rappels en Arrière-Plan

Le service `BulletinReminderService` tourne automatiquement:
- Vérifie toutes les heures
- Envoie les rappels selon le calendrier
- Met à jour `last_reminder` pour éviter les doublons
- Thread daemon (ne bloque pas l'arrêt de l'application)

---

## 🚀 Démarrage

Le système démarre automatiquement avec le backend:

```bash
cd backend
python main.py
```

**Logs de démarrage:**
```
🚀 Starting CTBA Platform...
✅ Database initialized
✅ Enhanced bulletin delivery engine started
✅ Bulletin reminder service started (checks every hour)
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

## 📝 Notes Importantes

1. **Rappels automatiques** nécessitent que le backend reste actif
2. **Mailing lists** doivent être configurées pour chaque région via `/api/regions`
3. **Email service** doit être configuré (SMTP settings)
4. **Statuts de bulletins**:
   - `DRAFT`: En cours de création
   - `SENT`: Envoyé, rappels actifs
   - `NOT_PROCESSED`: Fermé, rappels désactivés

5. **Permissions**:
   - Création/envoi bulletins: `VOC_L1`, `VOC_LEAD`, `ADMINISTRATOR`
   - Gestion régions: `VOC_LEAD`, `ADMINISTRATOR`
   - Suppression bulletins: `ADMINISTRATOR` uniquement

---

## 🔍 Dépannage

### Les rappels ne sont pas envoyés

```bash
# Vérifier les statistiques
curl "http://localhost:8000/api/bulletins/reminders/statistics" \
  -H "Authorization: Bearer <token>"

# Vérifier les logs backend
# Rechercher: "🔍 Checking bulletins for reminders..."
```

### Email non envoyé

```bash
# Vérifier l'historique de delivery
curl "http://localhost:8000/api/bulletins/1/delivery-history" \
  -H "Authorization: Bearer <token>"

# Vérifier les mailing lists de la région
curl "http://localhost:8000/api/regions" \
  -H "Authorization: Bearer <token>"
```

### Dashboard analytics vide

```bash
# Vérifier les données CVE
curl "http://localhost:8000/api/cves?limit=10" \
  -H "Authorization: Bearer <token>"

# Vérifier les bulletins
curl "http://localhost:8000/api/bulletins?limit=10" \
  -H "Authorization: Bearer <token>"
```

---

**✅ Système de Bulletins CTBA - Opérationnel**

Toutes les fonctionnalités des exigences 2.3 à 2.6 sont implémentées et testables via les endpoints API ci-dessus.
