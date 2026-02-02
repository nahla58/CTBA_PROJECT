# 📊 Bulletin System - Visual Diagrams & Flows

## 1. Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CTBA PLATFORM - BULLETIN SYSTEM                 │
└─────────────────────────────────────────────────────────────────────┘

┌────────────────────────────┐
│      FRONTEND (React)       │
│  ┌──────────────────────┐   │
│  │ BulletinManagement   │   │  User creates bulletins
│  │ - Create form        │   │  - Title, body, regions
│  │ - Preview button     │   │  - Select CVEs
│  │ - Send button        │   │
│  └──────────────────────┘   │
│  ┌──────────────────────┐   │
│  │ BulletinHistory      │   │  User sends & tracks
│  │ - List bulletins     │   │  - View status
│  │ - Send              │   │  - Check logs
│  │ - Remind            │   │
│  └──────────────────────┘   │
└────────────────────────────┘
           │
           │ REST API (JSON over HTTP)
           │
┌────────────────────────────────────────────────────────────────┐
│                    BACKEND (Python/Flask)                       │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  API Routes (bulletin_routes.py)         │   │
│  │  POST   /bulletins                → create              │   │
│  │  GET    /bulletins                → list                │   │
│  │  GET    /bulletins/{id}           → detail              │   │
│  │  PUT    /bulletins/{id}           → update              │   │
│  │  DELETE /bulletins/{id}           → delete              │   │
│  │  POST   /bulletins/{id}/send      → queue               │   │
│  │  POST   /bulletins/{id}/preview   → preview HTML        │   │
│  │  POST   /bulletins/{id}/remind    → send reminder       │   │
│  │  GET    /bulletins/{id}/logs      → audit trail         │   │
│  │  POST   /regions                  → manage regions      │   │
│  └─────────────────────────────────────────────────────────┘   │
│           │                                                      │
│           ▼                                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Services Layer                              │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────┐                     │   │
│  │  │  BulletinService               │                     │   │
│  │  │  - CRUD operations             │                     │   │
│  │  │  - CVE grouping algorithm      │                     │   │
│  │  │  - Logging                     │                     │   │
│  │  └────────────────────────────────┘                     │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────┐                     │   │
│  │  │  BulletinDeliveryEngine        │                     │   │
│  │  │  - Queue management            │                     │   │
│  │  │  - Background processing       │                     │   │
│  │  │  - Retry logic                 │                     │   │
│  │  │  - Reminder scheduling         │                     │   │
│  │  └────────────────────────────────┘                     │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────┐                     │   │
│  │  │  EmailService                  │                     │   │
│  │  │  - SMTP configuration          │                     │   │
│  │  │  - Email sending               │                     │   │
│  │  │  - Attachment handling         │                     │   │
│  │  └────────────────────────────────┘                     │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────┐                     │   │
│  │  │  EmailTemplate                 │                     │   │
│  │  │  - HTML rendering (Jinja2)     │                     │   │
│  │  │  - CSS styling                 │                     │   │
│  │  │  - Variable substitution       │                     │   │
│  │  └────────────────────────────────┘                     │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────┐                     │   │
│  │  │  RegionService                 │                     │   │
│  │  │  - Region CRUD                 │                     │   │
│  │  │  - Recipient management        │                     │   │
│  │  └────────────────────────────────┘                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│           │                                                      │
│           ▼                                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            Database (SQLite)                             │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐   │   │
│  │  │  bulletins  │  │ bulletin_logs │  │  regions    │   │   │
│  │  ├─────────────┤  ├──────────────┤  ├─────────────┤   │   │
│  │  │ id (PK)     │  │ id (PK)      │  │ id (PK)     │   │   │
│  │  │ title       │  │ bulletin_id  │  │ name        │   │   │
│  │  │ body        │  │ action       │  │ recipients  │   │   │
│  │  │ regions     │  │ region       │  │ archived_at │   │   │
│  │  │ status      │  │ recipients   │  └─────────────┘   │   │
│  │  │ created_by  │  │ message      │                     │   │
│  │  │ created_at  │  │ created_at   │                     │   │
│  │  │ sent_at     │  └──────────────┘                     │   │
│  │  │ last_reminder                                       │   │
│  │  └─────────────┘                                       │   │
│  └─────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
           │
           │ SMTP Protocol
           │
┌────────────────────────────┐
│     SMTP Server            │
│  ┌──────────────────────┐  │
│  │  localhost:587 (TLS) │  │ Or: gmail.com, mailtrap.io, etc
│  │  (or configured)     │  │
│  └──────────────────────┘  │
└────────────────────────────┘
           │
           │ Email
           │
┌────────────────────────────┐
│   Recipient Inboxes        │
│  ┌──────────────────────┐  │
│  │ HTML-formatted       │  │
│  │ security bulletin    │  │
│  │ with styling         │  │
│  └──────────────────────┘  │
└────────────────────────────┘
```

---

## 2. Bulletin Creation & Delivery Flow

```
START
  │
  ├─ CREATE BULLETIN ──────────────────────┐
  │  POST /api/bulletins                   │
  │  ├─ title: "Critical Vulnerability"    │
  │  ├─ body: "Description..."             │
  │  ├─ regions: ["NORAM", "Europe"]       │
  │  └─ cve_ids: ["CVE-2026-2481", ...]    │
  │                                        │
  │  ✅ Status: DRAFT                      │
  │  ✅ ID: 1                              │
  │                                        │
  ├─ EDIT BULLETIN (Optional) ─────────────┤
  │  PUT /api/bulletins/1                  │
  │  └─ Update title/body/CVEs              │
  │                                        │
  ├─ PREVIEW BULLETIN ─────────────────────┤
  │  POST /api/bulletins/1/preview         │
  │  └─ Renders HTML template              │
  │     Returns: Full HTML email body      │
  │     User views in browser              │
  │                                        │
  ├─ SEND BULLETIN ────────────────────────┤
  │  POST /api/bulletins/1/send            │
  │  ├─ regions: ["NORAM", "Europe"]       │
  │  └─ test_mode: false                   │
  │                                        │
  │  ✅ Added to delivery_queue            │
  │  ✅ Status: SENT                       │
  │  ✅ sent_at: timestamp                 │
  │  └─ Returns immediately                │
  │                                        │
  ├─ PROCESS QUEUE (Background) ───────────┤
  │  BulletinDeliveryEngine.process_queue()│
  │  Runs continuously or on-demand        │
  │                                        │
  │  FOR EACH job in queue:                │
  │    FOR EACH region:                    │
  │      ├─ Get region recipients          │
  │      │  → ["user1@domain", "user2@..."]│
  │      │                                 │
  │      ├─ Render HTML                    │
  │      │  → EmailTemplate.render_bulletin│
  │      │  → Substitutes all variables    │
  │      │  → Returns complete HTML        │
  │      │                                 │
  │      ├─ Send email                     │
  │      │  → SMTP connection              │
  │      │  → Authenticate                 │
  │      │  → Send MIME message            │
  │      │  → Close connection             │
  │      │                                 │
  │      └─ Log delivery                   │
  │         INSERT INTO bulletin_logs      │
  │         ├─ bulletin_id: 1              │
  │         ├─ action: "SENT"              │
  │         ├─ region: "NORAM"             │
  │         ├─ recipients: 2               │
  │         ├─ message: "Success"          │
  │         └─ created_at: timestamp       │
  │                                        │
  │  If SMTP fails:                        │
  │    ├─ Retry up to 3 times              │
  │    ├─ Wait 60 seconds between retries  │
  │    └─ Log final error                  │
  │                                        │
  │  After all regions:                    │
  │    └─ Update bulletin status to SENT   │
  │                                        │
  ├─ VIEW DELIVERY LOGS ───────────────────┤
  │  GET /api/bulletins/1/logs             │
  │  Returns:                              │
  │  [                                     │
  │    {                                   │
  │      action: "SENT",                   │
  │      region: "NORAM",                  │
  │      recipients: 2,                    │
  │      message: "Delivered",             │
  │      created_at: "2026-01-27T14:35"    │
  │    },                                  │
  │    {                                   │
  │      action: "SENT",                   │
  │      region: "Europe",                 │
  │      recipients: 3,                    │
  │      message: "Delivered",             │
  │      created_at: "2026-01-27T14:35"    │
  │    }                                   │
  │  ]                                     │
  │                                        │
  ├─ EMAILS IN INBOXES ────────────────────┤
  │  Recipients receive:                   │
  │  ├─ From: noreply@ctba.local           │
  │  ├─ Subject: "Critical Vulnerability" │
  │  ├─ HTML with:                         │
  │  │   ├─ Purple gradient header         │
  │  │   ├─ CVE groups by product         │
  │  │   ├─ Severity badges               │
  │  │   ├─ Remediation guidance          │
  │  │   ├─ Statistics (critical/high)    │
  │  │   └─ CTBA footer                   │
  │  └─ Can see all details                │
  │                                        │
  ├─ SCHEDULED REMINDERS ──────────────────┤
  │  Day 7:  POST /bulletins/1/remind      │
  │          └─ Reminder email sent        │
  │          └─ Log: REMINDER_7D           │
  │                                        │
  │  Day 14: POST /bulletins/1/remind      │
  │          └─ Second reminder sent       │
  │          └─ Log: REMINDER_14D          │
  │                                        │
  │  Day 30: POST /bulletins/1/escalate    │
  │          └─ Escalation to manager      │
  │          └─ Log: ESCALATION_30D        │
  │                                        │
  ├─ MANUAL CLOSURE ───────────────────────┤
  │  PUT /api/bulletins/1                  │
  │  ├─ status: "CLOSED"                   │
  │  └─ Updates: closed_at timestamp       │
  │     Data preserved for audit           │
  │                                        │
  └─ END
```

---

## 3. Email Service Internal Flow

```
EmailService.send_bulletin()
│
├─ INPUT VALIDATION
│  ├─ Check to_list not empty
│  ├─ Check subject provided
│  ├─ Check html_body provided
│  └─ Error if missing
│
├─ TEST MODE CHECK
│  ├─ If test_mode = true:
│  │  ├─ Log to file: "[TEST MODE] Would send..."
│  │  ├─ Return success (no SMTP)
│  │  └─ Exit
│  │
│  └─ If test_mode = false:
│     └─ Continue to SMTP
│
├─ CREATE MIME MESSAGE
│  ├─ MIMEMultipart('alternative')
│  ├─ Set headers:
│  │  ├─ Subject: "Critical Vulnerability"
│  │  ├─ From: "noreply@ctba.local"
│  │  ├─ To: "user1@domain, user2@domain"
│  │  └─ Cc/Bcc: (optional)
│  │
│  ├─ Attach plain text (fallback)
│  │  └─ For old email clients
│  │
│  ├─ Attach HTML part
│  │  └─ Main content with styling
│  │
│  └─ Attach files (optional)
│     ├─ Read from disk
│     ├─ Base64 encode
│     └─ Add to message
│
├─ SMTP CONNECTION
│  ├─ Read SMTP configuration:
│  │  ├─ Server: "localhost" (env var)
│  │  ├─ Port: 587 (env var)
│  │  ├─ TLS: true (env var)
│  │  └─ Password: "" (env var)
│  │
│  ├─ If password not set:
│  │  ├─ Log warning
│  │  ├─ Return success (test mode only)
│  │  └─ Exit
│  │
│  └─ If password set:
│     ├─ If TLS mode:
│     │  └─ SMTP() + starttls()
│     │
│     └─ If SSL mode:
│        └─ SMTP_SSL()
│
├─ AUTHENTICATION
│  ├─ server.login(from_email, password)
│  ├─ If fails:
│  │  └─ Return error: "Authentication failed"
│  │
│  └─ If success:
│     └─ Continue
│
├─ SEND MESSAGE
│  ├─ server.send_message(
│  │    msg,
│  │    from_addr=from_email,
│  │    to_addrs=[all recipients]
│  │  )
│  │
│  ├─ If success:
│  │  ├─ Log: "✅ Email sent to N recipients"
│  │  └─ Return success
│  │
│  └─ If fails:
│     ├─ Catch exception
│     ├─ Log error details
│     └─ Return failure
│
└─ CLOSE CONNECTION
   └─ server.quit()
```

---

## 4. Queue Processing Flow

```
BulletinDeliveryEngine.process_queue()
│
├─ FOR max_jobs times:
│  │
│  ├─ Check if queue empty
│  │  └─ If empty: break loop
│  │
│  ├─ Get job from queue
│  │  ├─ job_id: "job_1_1674825600"
│  │  ├─ bulletin_id: 1
│  │  ├─ regions: ["NORAM", "Europe"]
│  │  ├─ attempts: 0
│  │  └─ test_mode: false
│  │
│  ├─ EXECUTE DELIVERY JOB
│  │  │
│  │  ├─ Get bulletin details
│  │  │  ├─ ID: 1
│  │  │  ├─ Title: "Critical..."
│  │  │  ├─ Body: "Please..."
│  │  │  └─ CVEs: [...]
│  │  │
│  │  ├─ FOR EACH region:
│  │  │  │
│  │  │  ├─ Get region object
│  │  │  │  ├─ Name: "NORAM"
│  │  │  │  ├─ Recipients: "user1@d, user2@d"
│  │  │  │  └─ Description: "North America"
│  │  │  │
│  │  │  ├─ Render HTML
│  │  │  │  ├─ Call EmailTemplate.render_bulletin()
│  │  │  │  ├─ Pass: title, region, cves, etc
│  │  │  │  └─ Get: Complete HTML page
│  │  │  │
│  │  │  ├─ Send email
│  │  │  │  ├─ Call EmailService.send_bulletin()
│  │  │  │  ├─ Pass: to_list, subject, html_body
│  │  │  │  └─ Get: success/failure status
│  │  │  │
│  │  │  ├─ Log delivery
│  │  │  │  ├─ INSERT bulletin_logs
│  │  │  │  ├─ action: "SENT" or "FAILED"
│  │  │  │  ├─ region: "NORAM"
│  │  │  │  ├─ recipients: 2
│  │  │  │  └─ message: "Success" or error
│  │  │  │
│  │  │  └─ Repeat for next region
│  │  │
│  │  └─ Update bulletin status
│  │     └─ If all succeeded: status = "SENT"
│  │
│  ├─ CHECK RESULT
│  │  │
│  │  ├─ If success:
│  │  │  └─ Mark complete
│  │  │
│  │  └─ If failed:
│  │     ├─ Increment attempts counter
│  │     ├─ If attempts < max_retries:
│  │     │  ├─ Wait 60 seconds
│  │     │  └─ Re-add to queue
│  │     │
│  │     └─ Else:
│  │        └─ Log final error
│  │
│  └─ Next job
│
└─ RETURN STATISTICS
   ├─ Processed: 5
   ├─ Succeeded: 4
   ├─ Failed: 1
   ├─ Retried: 2
   └─ Queue size: 0
```

---

## 5. HTML Email Template Structure

```
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    /* CSS for responsive design */
    /* Colors: Purple (#667eea), gradients, severity badges */
  </style>
</head>
<body>
  <div class="container">
    
    ┌─────────────────────────────────────┐
    │         HEADER SECTION              │
    │                                     │
    │  ╔═════════════════════════════╗   │
    │  ║ Critical SVG Parser Bug     ║   │
    │  ║                             ║   │
    │  ║   📍 North America          ║   │
    │  ╚═════════════════════════════╝   │
    │                                     │
    │  Purple gradient background         │
    │  White text                         │
    │  Region badge                       │
    └─────────────────────────────────────┘
    
    ┌─────────────────────────────────────┐
    │       CONTENT SECTION               │
    │                                     │
    │  Description paragraph...           │
    │                                     │
    │  ┌─────────────────────────────┐   │
    │  │ 📋 AFFECTED PRODUCTS & CVEs │   │
    │  └─────────────────────────────┘   │
    │                                     │
    │  ┌─────────────────────────────┐   │
    │  │ 📌 SVG Parser v3.2          │   │
    │  │                             │   │
    │  │ CVE-2026-2481 [CRITICAL] ◆  │   │
    │  │ CVE-2026-2482 [HIGH]     ◆  │   │
    │  │                             │   │
    │  │ Remediation:                │   │
    │  │ Upgrade to v4.2+            │   │
    │  └─────────────────────────────┘   │
    │                                     │
    │  ┌─────────────────────────────┐   │
    │  │ 📌 PDF Handler v6.0         │   │
    │  │                             │   │
    │  │ CVE-2026-2483 [MEDIUM]  ◆   │   │
    │  │                             │   │
    │  │ Remediation:                │   │
    │  │ Apply patch 6.1.5           │   │
    │  └─────────────────────────────┘   │
    │                                     │
    │  ┌─────────────────────────────┐   │
    │  │ 📊 SUMMARY                  │   │
    │  │                             │   │
    │  │ Critical: 1  │  High: 1     │   │
    │  │ Medium: 1    │  Low: 0      │   │
    │  └─────────────────────────────┘   │
    └─────────────────────────────────────┘
    
    ┌─────────────────────────────────────┐
    │        FOOTER SECTION               │
    │                                     │
    │  CTBA Security Bulletin             │
    │  Bulletin ID: 1                     │
    │  This is an automated notification  │
    │  Do not reply to this email         │
    │                                     │
    │  © 2024 CTBA Platform               │
    └─────────────────────────────────────┘
```

---

## 6. Database Schema Relationships

```
┌──────────────────────────────────────────┐
│                BULLETINS                 │
│                                          │
│ PK: id                                   │
│     title ─────────────────────────────┐ │
│     body                               │ │
│     regions: "NORAM,Europe" ───┐      │ │
│     status: DRAFT/SENT/CLOSED  │      │ │
│     created_by                 │      │ │
│     created_at                 │      │ │
│     sent_at                    │      │ │
│     last_reminder              │      │ │
└──────────────────────────────────────────┘
       ▲                           │
       │                           │
       │ FK:bulletin_id            │
       │                           │
       │                   ┌───────▼──────────┐
       │                   │   REGIONS        │
       │                   │                  │
       │                   │ PK: id           │
       │              ┌────┤ name             │
       └──────────────┤    │ recipients       │
                      │    │ archived_at      │
  ┌─────────────────────────────────────────┐
  │         BULLETIN_LOGS                   │
  │                                         │
  │ PK: id                                  │
  │     FK: bulletin_id ──────┬─────────────┼────┐
  │     action: SENT/FAILED   │             │    │
  │     region ───────────────┴─────────────┼──┐ │
  │     recipients: 2                       │  │ │
  │     message                             │  │ │
  │     created_at                          │  │ │
  └─────────────────────────────────────────┘  │ │
                                                │ │
    Every region gets separate log entry ────┐ │ │
    Each send action logged ─────────────────┘ │ │
    For audit trail ───────────────────────────┘ │
    Shows which recipients got email ────────────┘
```

---

## 7. State Transitions

```
BULLETIN LIFECYCLE
═════════════════

              CREATE BULLETIN
                    │
                    ▼
         ┌──────────────────┐
         │     DRAFT        │
         │ (Editable)       │
         └──────┬───────────┘
                │
                ├─── EDIT ────────┐
                │  (change fields) │
                │                  │
                ├─── PREVIEW ──────┐
                │  (see HTML)      │
                │                  │
                ├─── DELETE ────────┐
                │  (remove)         │
                │                  │
                └─── SEND ────────────┐
                   (queue delivery)   │
                                      ▼
                         ┌──────────────────┐
                         │     SENT         │
                         │ (Queued delivery)│
                         └──────┬───────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                    ▼           ▼           ▼
                 REMIND      REMIND      ESCALATE
                  (D+7)       (D+14)      (D+30)
                    │           │           │
                    └───────────┼───────────┘
                                │
                                ▼
                    (Manual or Automatic)
                                │
                                ▼
                         ┌──────────────────┐
                         │    CLOSED        │
                         │ (Data preserved) │
                         └──────────────────┘
```

---

## 8. Test Mode vs Real Mode

```
TEST MODE (test_mode: true)
═════════════════════════════════════

  Create Bulletin
         │
         ▼
    POST /send
         │
         ├─ Added to queue ✅
         ├─ Email NOT sent ✅
         ├─ Logged to file ✅
         │  [TEST MODE] Would send to ["user1@d", "user2@d"]
         ├─ Delivery logged ✅
         └─ Status: SENT ✅
         
  ✅ Perfect for:
     - Testing without SMTP
     - Verifying HTML rendering
     - Testing CVE grouping
     - Testing region configuration
     - Testing database operations
     
  ❌ Limitation:
     - No emails actually sent
     - Recipients don't receive anything


REAL MODE (test_mode: false)
════════════════════════════════════════

  Create Bulletin
         │
         ▼
    POST /send
         │
         ├─ Added to queue ✅
         │
         ├─ SMTP Connection Attempt
         │  ├─ Connect to SMTP server
         │  ├─ Authenticate (login)
         │  ├─ Send MIME message
         │  └─ Close connection
         │
         ├─ If Success:
         │  ├─ Email SENT ✅
         │  ├─ Recipients get email ✅
         │  ├─ Delivered to inbox ✅
         │  └─ Logged ✅
         │
         └─ If Failure:
            ├─ Retry up to 3 times ⚠️
            ├─ Log error ✅
            └─ Alert admin ⚠️

  ✅ Requirement:
     - SMTP_SERVER configured
     - SMTP_PASSWORD set
     - SMTP server reachable
     
  ✅ Result:
     - Real emails in real inboxes
     - Recipients can read bulletin
     - Full delivery tracking
```

---

## 9. Error Handling Flow

```
ERROR SCENARIOS & RECOVERY
═══════════════════════════════════════

SCENARIO 1: SMTP Connection Failed
├─ Attempt 1: FAILED
├─ Wait 60 seconds
├─ Attempt 2: FAILED
├─ Wait 60 seconds
├─ Attempt 3: FAILED
├─ Wait 60 seconds
├─ Attempt 4: FAILED
└─ Give up, log error
   Log: action=FAILED, message="Connection refused"

SCENARIO 2: Authentication Failed (Password wrong)
├─ Attempt 1: AUTH FAILED
├─ No retry (not transient)
└─ Log error immediately
   Log: action=FAILED, message="Authentication failed"

SCENARIO 3: Invalid Region
├─ Get region from name
├─ Region not found in database
├─ Skip region
├─ Continue with other regions
└─ Log warning
   Log: action=FAILED, message="Region not found"

SCENARIO 4: No Recipients
├─ Get region
├─ Recipients list is empty
├─ Cannot send to nobody
└─ Log error
   Log: action=FAILED, message="No recipients"

SCENARIO 5: Partial Failure (Some regions fail)
├─ NORAM: Success ✅
├─ Europe: Failed ⚠️
├─ APAC: Success ✅
├─ Update status: PARTIALLY_SENT
└─ Logs show mixed results
   - NORAM: SENT
   - Europe: FAILED
   - APAC: SENT
```

---

## 10. Reminder & Escalation Timeline

```
TIMELINE OF BULLETIN LIFECYCLE
═════════════════════════════════════════════════════

DAY 0:
  ├─ 14:35 - Bulletin sent
  │         Users receive initial bulletin
  │         Status: SENT
  │         Log: action=SENT
  │
  └─ Log saved in bulletin_logs

DAYS 1-6:
  └─ Users read and act on bulletin

DAY 7:
  ├─ 14:35 - Automatic reminder triggered
  │         Email sent to same recipients
  │         1st follow-up message
  │         Log: action=REMINDER_7D
  │
  └─ last_reminder updated to this date

DAYS 8-13:
  └─ Users continue remediation

DAY 14:
  ├─ 14:35 - Automatic reminder triggered
  │         Email sent to same recipients
  │         2nd follow-up message
  │         Log: action=REMINDER_14D
  │
  └─ last_reminder updated to this date

DAYS 15-29:
  └─ Final push to remediate

DAY 30:
  ├─ 14:35 - Automatic escalation triggered
  │         Email sent to managers
  │         Escalation message (urgent)
  │         Log: action=ESCALATION_30D
  │
  └─ last_reminder updated to this date

DAYS 31+:
  ├─ Manual override option
  │ └─ Send additional reminders
  │    POST /bulletins/1/remind
  │
  └─ Analyst can close bulletin
     PUT /bulletins/1 with status=CLOSED
     Data preserved forever
```

---

**Visual diagrams created for reference and documentation purposes**

All flows represent actual implementation in:
- Backend: `app/services/`
- Database: SQLite tables
- Email: SMTP protocol
- API: REST endpoints

