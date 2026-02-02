# 📬 Bulletin System - Quick Start Guide

## Getting Started (5 minutes)

### Step 1: Access Dashboard
```
http://localhost:3000/dashboard
→ Look for "Bulletin Management" widget
```

### Step 2: Create a Bulletin
```
Click "Create Bulletin" button

Fill in:
  Title:        "Critical SVG Parser Vulnerability"
  Body:         Copy-paste threat description
  Add CVEs:     CVE-2026-2481, CVE-2026-2482
  Regions:      ☐ NORAM ☐ LATAM ☐ Europe ☐ APMEA
```

### Step 3: Preview
```
Click "Preview" button
→ See HTML rendering
→ Verify formatting, links, attachments
```

### Step 4: Send
```
Click "Send Bulletin"
→ System auto-groups CVEs by product/remediation
→ Generates email per region with recipient list
→ Logs every send action
→ Status updates to "SENT"
```

### Step 5: Track Follow-ups
```
System automatically:
  Day 7:  Sends reminder email
  Day 14: Sends second reminder  
  Day 30: Escalates to manager

View timeline: Click "View Logs" tab
```

---

## Common Tasks

### 🔍 View All Bulletins
```
GET http://localhost:5000/api/bulletins

Response:
[
  {
    "id": 1,
    "title": "Critical SVG Parser Vulnerability",
    "status": "SENT",
    "regions": ["NORAM", "Europe"],
    "created_at": "2026-01-27T10:30:00",
    "sent_at": "2026-01-27T10:35:00",
    "last_reminder": null
  }
]
```

### 📝 Update Bulletin (before sending)
```
PUT http://localhost:5000/api/bulletins/{id}

Body:
{
  "title": "Updated Title",
  "body": "Updated content"
}

Status MUST be "DRAFT" to edit
```

### 📎 Add Attachment
```
POST http://localhost:5000/api/bulletins/{id}/attachments

Form Data:
  file: <binary file>

Returns:
{
  "id": 123,
  "filename": "remediation_guide.pdf",
  "path": "/uploads/bulletin_attachments/..."
}
```

### 📤 Send Bulletin
```
POST http://localhost:5000/api/bulletins/{id}/send

Body:
{
  "regions": ["NORAM", "Europe"]
}

Response:
{
  "status": "success",
  "message": "Bulletin queued for delivery",
  "bulletin_id": 1,
  "regions_sent": ["NORAM", "Europe"]
}
```

### ⏰ Manual Reminder
```
POST http://localhost:5000/api/bulletins/{id}/remind

Response:
{
  "status": "success",
  "message": "Reminder sent to 45 recipients",
  "timestamp": "2026-01-27T14:15:00"
}
```

### 🔐 Close Bulletin
```
PUT http://localhost:5000/api/bulletins/{1}

Body:
{
  "status": "CLOSED"
}

Changes bulletin to CLOSED status
Preserves sent_at and delivery history
Can be reopened if needed
```

### 📋 View Delivery Logs
```
GET http://localhost:5000/api/bulletins/{id}/logs

Response:
[
  {
    "id": 1,
    "action": "SENT",
    "region": "NORAM",
    "recipients": 25,
    "message": "Delivered successfully",
    "created_at": "2026-01-27T10:35:00"
  },
  {
    "id": 2,
    "action": "REMINDER_7D",
    "region": "NORAM",
    "recipients": 25,
    "message": "First reminder sent",
    "created_at": "2026-02-03T10:35:00"
  }
]
```

---

## Region Management

### 🌍 View Regions
```
GET http://localhost:5000/api/regions

Response:
[
  {
    "id": 1,
    "name": "NORAM",
    "description": "North America",
    "recipients": "ciso@us.company.com,security-ops@us.company.com",
    "archived_at": null
  },
  {
    "id": 2,
    "name": "Europe",
    "description": "European Operations",
    "recipients": "ciso@eu.company.com,security-ops@eu.company.com",
    "archived_at": null
  }
]
```

### ➕ Add New Region
```
POST http://localhost:5000/api/regions

Body:
{
  "name": "APAC",
  "description": "Asia-Pacific Operations",
  "recipients": "ciso@ap.company.com,security-ops@ap.company.com"
}

Status: 201 Created
```

### ✏️ Update Region
```
PUT http://localhost:5000/api/regions/{id}

Body:
{
  "recipients": "new-ciso@eu.company.com,sec@eu.company.com"
}
```

### 🗂️ Archive Region (soft delete)
```
PUT http://localhost:5000/api/regions/{id}

Body:
{
  "archived_at": "2026-01-27T10:30:00"
}

Keeps historical data intact
Bulletins sent before archiving preserved
```

### 🗑️ Delete Region (only if no bulletins)
```
DELETE http://localhost:5000/api/regions/{id}

Only works if region has no sent bulletins
Use archive for data preservation
```

---

## CVE Grouping Algorithm

### How It Works
```
Input: Array of CVEs
  [CVE-2026-2481, CVE-2026-2482, CVE-2026-2483]

Step 1: Extract products
  CVE-2026-2481 → ["SVG Parser", "ImageLib v3.2"]
  CVE-2026-2482 → ["SVG Parser", "WebKit"]
  CVE-2026-2483 → ["PDF Handler"]

Step 2: Group by product
  GROUP "SVG Parser": [CVE-2026-2481, CVE-2026-2482]
  GROUP "ImageLib":   [CVE-2026-2481]
  GROUP "PDF Handler": [CVE-2026-2483]

Step 3: Extract remediation
  FROM descriptions → upgrade library, apply patch, etc.

Step 4: Create groups
  [
    {
      "product": "SVG Parser",
      "cves": [CVE-2026-2481, CVE-2026-2482],
      "remediation": "Upgrade to 4.2+"
    },
    {
      "product": "PDF Handler",
      "cves": [CVE-2026-2483],
      "remediation": "Apply patch 6.1.5"
    }
  ]

Output: Bulletin with grouped sections
```

### Example Grouped Bulletin
```
=== TITLE ===
CRITICAL VULNERABILITIES - ACTION REQUIRED

=== INTRODUCTION ===
The following CVEs require immediate attention...

=== CRITICAL PRODUCTS (3 CVEs) ===

  📌 SVG Parser Library
    ├─ CVE-2026-2481 (CVSS 9.8)
    ├─ CVE-2026-2482 (CVSS 8.1)
    └─ REMEDIATION: Upgrade to version 4.2+
       
  📌 PDF Handler
    ├─ CVE-2026-2483 (CVSS 7.5)
    └─ REMEDIATION: Apply patch 6.1.5

=== MEDIUM SEVERITY (1 CVE) ===
  ...

=== ACTION ITEMS ===
[ ] Inventory affected systems
[ ] Test patches in dev environment
[ ] Schedule maintenance window
[ ] Deploy to production
[ ] Verify remediation
```

---

## Database Queries

### Get all bulletins by status
```sql
SELECT * FROM bulletins 
WHERE status = 'SENT'
ORDER BY sent_at DESC;
```

### Get bulletins needing reminders
```sql
SELECT * FROM bulletins
WHERE status = 'SENT'
  AND (last_reminder IS NULL OR last_reminder < datetime('now', '-7 days'))
ORDER BY sent_at ASC;
```

### Get delivery statistics
```sql
SELECT 
  status,
  COUNT(*) as count,
  SUM(CASE WHEN status = 'SENT' THEN 1 ELSE 0 END) as successful
FROM bulletin_logs
WHERE created_at > datetime('now', '-30 days')
GROUP BY status;
```

### Get region statistics
```sql
SELECT 
  region,
  COUNT(DISTINCT bulletin_id) as bulletin_count,
  SUM(recipients) as total_recipients
FROM bulletin_logs
WHERE created_at > datetime('now', '-30 days')
GROUP BY region;
```

---

## Troubleshooting

### ❌ Email not sending?
```
1. Check SMTP configuration in app/services/email_service.py
   - SMTP_SERVER = "localhost" (default)
   - SMTP_PORT = 587
   - SMTP_TLS = True

2. Check delivery logs:
   GET /api/bulletins/{id}/logs
   → Look for error messages in "message" field

3. Check email service logs:
   tail -f logs/email_service.log

4. Test SMTP connection:
   python -m smtplib localhost 587
```

### ❌ Grouping not working?
```
1. Verify CVEs have products in database:
   SELECT * FROM CVEs WHERE id IN (...)
   → Check "affected_products" column populated

2. Check grouping algorithm:
   app/services/enhanced_bulletin_grouping.py
   → Verify product extraction regex patterns

3. Run diagnostic:
   python backend/test_bulletin_grouping.py
```

### ❌ Regions not appearing?
```
1. Check regions table:
   SELECT * FROM regions WHERE archived_at IS NULL;
   
2. Verify not archived:
   - If archived_at is set, region won't appear
   - Run: UPDATE regions SET archived_at = NULL

3. Check permission:
   - User may not have create_bulletin permission
```

### ⚠️ Reminders not triggering?
```
1. Check background thread is running:
   ps aux | grep "delivery_engine"
   
2. Verify bulletin status = 'SENT':
   SELECT * FROM bulletins WHERE id = ?
   
3. Check last_reminder timestamp:
   - Should be NULL for first reminder
   - Should be > 7 days ago for next reminder
   
4. Check logs:
   SELECT * FROM bulletin_logs 
   WHERE action LIKE '%REMINDER%'
```

---

## Email Template Customization

### Location
```
app/services/email_service.py → class EmailTemplate
```

### Customization Points
```python
# Brand colors
CTBA_COLOR = "#1e40af"  # Blue
HEADER_BG = "#1e3a8a"   # Dark blue
ACCENT = "#06b6d4"      # Cyan

# Logo/footer
COMPANY_NAME = "CTBA Security"
COMPANY_LOGO_URL = "https://..."

# Fonts
HEADER_FONT = "Arial, sans-serif"
BODY_FONT = "Arial, sans-serif"
```

### Render Method
```python
EmailTemplate.render_bulletin(
    bulletin_title="Critical Vulnerabilities",
    groups=[
        {
            "product": "SVG Parser",
            "cves": [CVE objects],
            "remediation": "Upgrade to 4.2+"
        }
    ],
    region="NORAM",
    color_scheme="dark"  # or "light"
)
```

---

## Performance Tips

### For Large Bulletins (50+ CVEs)
```
1. Enable batch delivery:
   - Increases performance
   - Groups recipients by region
   - Staggered sends (avoid overwhelming SMTP)

2. Use pagination in UI:
   GET /api/bulletins?limit=20&offset=0
   
3. Archive old bulletins monthly:
   - Improves query performance
   - Data remains queryable in archive

4. Index frequently searched fields:
   CREATE INDEX idx_bulletins_status ON bulletins(status);
   CREATE INDEX idx_bulletins_sent_at ON bulletins(sent_at);
```

### For Many Regions
```
1. Use regional mailing lists:
   - Store as CSV in database
   - Cache in memory for 1 hour
   
2. Parallel send per region:
   - delivery_engine.py uses threading
   - Adjust thread pool size if needed

3. Monitor SMTP queue:
   - Logs all delivery attempts
   - Retry failed sends automatically
```

---

## API Reference Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/bulletins` | GET | List all bulletins |
| `/bulletins` | POST | Create new bulletin |
| `/bulletins/{id}` | GET | Get bulletin details |
| `/bulletins/{id}` | PUT | Update bulletin |
| `/bulletins/{id}` | DELETE | Delete bulletin |
| `/bulletins/{id}/send` | POST | Send/queue bulletin |
| `/bulletins/{id}/preview` | POST | Preview HTML |
| `/bulletins/{id}/remind` | POST | Send reminder |
| `/bulletins/{id}/escalate` | POST | Send escalation |
| `/bulletins/{id}/logs` | GET | View delivery logs |
| `/bulletins/{id}/attachments` | POST | Add attachment |
| `/bulletins/{id}/attachments/{aid}` | DELETE | Remove attachment |
| `/regions` | GET | List regions |
| `/regions` | POST | Create region |
| `/regions/{id}` | PUT | Update region |
| `/regions/{id}` | DELETE | Delete region |

---

**Last Updated:** January 27, 2026  
**Version:** 1.0 Production  
**Status:** ✅ Ready for Use
