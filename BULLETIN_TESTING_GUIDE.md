# 📬 Bulletin System - Complete Testing Guide

## How Email Sending Works

### Architecture Overview
```
┌─────────────────────┐
│   Create Bulletin   │
│   (REST API)        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Queue Bulletin Send │  BulletinDeliveryEngine.queue_bulletin_send()
│ (Add to queue)      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Process Queue       │  BulletinDeliveryEngine.process_queue()
│ (Background thread) │  Runs automatically or on-demand
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Execute Delivery    │  BulletinDeliveryEngine._execute_delivery_job()
│ - Per region        │  - Get recipients from region
│ - Render HTML       │  - Render email template
│ - Send email        │  - Connect to SMTP
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Email Service       │  EmailService.send_bulletin()
│ - SMTP connection   │  - Send via SMTP or test mode
│ - Send via SMTP     │  - Log response
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Log Delivery        │  BulletinService.log_delivery()
│ (Audit trail)       │  - Record in bulletin_logs table
└─────────────────────┘
```

---

## Step 1: Manual Setup

### 1.1 Start Backend Server
```bash
cd backend
python main.py
```
**Expected Output:**
```
INFO: Started server process [XXXX]
INFO: Uvicorn running on http://0.0.0.0:5000
...
✅ CVE imports: NVD, CVEdetails, CVE.org
✅ Bulletin routes registered
✅ Email service initialized
✅ Delivery engine ready
```

### 1.2 Verify SMTP Configuration
```bash
# Check environment variables
echo $SMTP_SERVER
echo $SMTP_PORT
echo $SMTP_FROM_EMAIL

# Default values (if not set):
# SMTP_SERVER = "localhost"
# SMTP_PORT = 587
# SMTP_FROM_EMAIL = "noreply@ctba.local"
# SMTP_USE_TLS = true
```

**Note:** If you don't have a real SMTP server, system will run in **test mode** (logs emails instead of sending)

---

## Step 2: Test Mode (Recommended First)

### Test 2.1: Create a Test Bulletin
```bash
curl -X POST http://localhost:5000/api/bulletins \
  -H "Content-Type: application/json" \
  -d '{
    "title": "TEST: Critical SVG Parser Vulnerability",
    "body": "This is a test bulletin for system verification.",
    "regions": ["NORAM", "Europe"],
    "cve_ids": ["CVE-2026-2481", "CVE-2026-2482"]
  }'
```

**Expected Response:**
```json
{
  "id": 1,
  "title": "TEST: Critical SVG Parser Vulnerability",
  "status": "DRAFT",
  "regions": ["NORAM", "Europe"],
  "created_at": "2026-01-27T14:30:00",
  "created_by": "admin"
}
```

### Test 2.2: Preview the Bulletin
```bash
curl -X POST http://localhost:5000/api/bulletins/1/preview \
  -H "Content-Type: application/json" \
  -d '{
    "region": "NORAM"
  }'
```

**Expected Response:**
```json
{
  "status": "success",
  "html_preview": "<html>...[full HTML bulletin]...</html>"
}
```

**View HTML Preview:**
1. Copy the HTML from response
2. Save to file: `bulletin_preview.html`
3. Open in browser: File → Open → bulletin_preview.html
4. Verify formatting, colors, CVE grouping, etc.

### Test 2.3: Send in Test Mode
```bash
curl -X POST http://localhost:5000/api/bulletins/1/send \
  -H "Content-Type: application/json" \
  -d '{
    "regions": ["NORAM", "Europe"],
    "test_mode": true
  }'
```

**Expected Response:**
```json
{
  "status": "success",
  "message": "Bulletin queued for delivery",
  "bulletin_id": 1,
  "regions_sent": ["NORAM", "Europe"],
  "test_mode": true
}
```

**Backend Logs Should Show:**
```
[TEST MODE] Would send email to ['ciso@us.company.com', 'security-ops@us.company.com'] 
            with subject 'TEST: Critical SVG Parser Vulnerability'
[TEST MODE] Would send email to ['ciso@eu.company.com', 'security-ops@eu.company.com'] 
            with subject 'TEST: Critical SVG Parser Vulnerability'
✅ Sent bulletin 1 to NORAM (test mode)
✅ Sent bulletin 1 to Europe (test mode)
```

### Test 2.4: Check Delivery Log
```bash
curl http://localhost:5000/api/bulletins/1/logs
```

**Expected Response:**
```json
{
  "logs": [
    {
      "id": 1,
      "bulletin_id": 1,
      "action": "SENT",
      "region": "NORAM",
      "recipients": 2,
      "message": "Test mode - email logged instead of sent",
      "created_at": "2026-01-27T14:35:00"
    },
    {
      "id": 2,
      "bulletin_id": 1,
      "action": "SENT",
      "region": "Europe",
      "recipients": 2,
      "message": "Test mode - email logged instead of sent",
      "created_at": "2026-01-27T14:35:01"
    }
  ]
}
```

---

## Step 3: Real Email Testing

### Step 3.1: Configure SMTP Server

**Option A: Use Local SMTP Server (Linux/Mac)**
```bash
# Python built-in SMTP server for testing
python -m smtpd -n -c DebuggingServer localhost:1025
```

**Option B: Use Gmail SMTP (Cloud)**
```bash
# Set environment variables
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_FROM_EMAIL="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"  # Use Gmail App Password, not regular password
export SMTP_USE_TLS="true"
```

**Option C: Use MailHog (Docker - Best for Testing)**
```bash
# Install/run MailHog
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Set environment variables
export SMTP_SERVER="localhost"
export SMTP_PORT="1025"
export SMTP_FROM_EMAIL="noreply@ctba.local"

# View sent emails: http://localhost:8025
```

**Option D: Use MailTrap (SaaS)**
```bash
# Sign up at mailtrap.io
# Get credentials from dashboard
export SMTP_SERVER="smtp.mailtrap.io"
export SMTP_PORT="465"
export SMTP_FROM_EMAIL="your-mailtrap-email"
export SMTP_PASSWORD="your-mailtrap-password"
export SMTP_USE_TLS="false"
```

### Step 3.2: Create Test Recipients

```bash
# Update NORAM region with test email
curl -X PUT http://localhost:5000/api/regions/1 \
  -H "Content-Type: application/json" \
  -d '{
    "recipients": "test@example.com,admin@example.com"
  }'
```

### Step 3.3: Create and Send Real Bulletin
```bash
# Create bulletin
curl -X POST http://localhost:5000/api/bulletins \
  -H "Content-Type: application/json" \
  -d '{
    "title": "REAL TEST: Critical Vulnerability",
    "body": "Testing real email delivery with actual SMTP",
    "regions": ["NORAM"],
    "cve_ids": ["CVE-2026-2481"]
  }'

# Send bulletin (NOT test mode)
curl -X POST http://localhost:5000/api/bulletins/2/send \
  -H "Content-Type: application/json" \
  -d '{
    "regions": ["NORAM"],
    "test_mode": false
  }'
```

**Expected Response:**
```json
{
  "status": "success",
  "message": "Bulletin queued for delivery",
  "bulletin_id": 2
}
```

**Backend Logs Should Show:**
```
Processing job job_2_1674825600 for bulletin 2
✅ Email sent to 2 recipients
✅ Sent bulletin 2 to NORAM
Bulletin 2 status updated to SENT
```

### Step 3.4: Verify Email Received

**If using MailHog:**
1. Open http://localhost:8025
2. Click on latest email
3. Verify:
   - ✅ Subject: "REAL TEST: Critical Vulnerability"
   - ✅ From: noreply@ctba.local
   - ✅ To: test@example.com, admin@example.com
   - ✅ HTML content with proper styling
   - ✅ CVE details grouped by product
   - ✅ Severity badges (Critical/High/Medium/Low)

**If using Gmail:**
1. Check inbox for email
2. Verify sender and HTML formatting
3. Check spam folder if not found

---

## Step 4: Automated Testing Script

Create [backend/test_bulletin_delivery.py](backend/test_bulletin_delivery.py):

```python
#!/usr/bin/env python3
"""
Bulletin Delivery System - Automated Testing
"""
import sys
import time
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:5000/api"

def test_step(step_num, description):
    print(f"\n{'='*60}")
    print(f"Step {step_num}: {description}")
    print('='*60)

def log_success(message):
    print(f"✅ {message}")

def log_error(message):
    print(f"❌ {message}")
    
def log_info(message):
    print(f"ℹ️  {message}")

# Test 1: Get regions
def test_get_regions():
    test_step(1, "Verify Regions Exist")
    try:
        response = requests.get(f"{BASE_URL}/regions")
        if response.status_code == 200:
            regions = response.json()
            log_success(f"Found {len(regions)} regions")
            for region in regions:
                print(f"  - {region['name']}: {len(region.get('recipients', []))} recipients")
            return regions
        else:
            log_error(f"Failed to get regions: {response.text}")
            return None
    except Exception as e:
        log_error(f"Exception: {e}")
        return None

# Test 2: Create bulletin
def test_create_bulletin():
    test_step(2, "Create Test Bulletin")
    try:
        payload = {
            "title": f"TEST Bulletin {datetime.now().strftime('%H:%M:%S')}",
            "body": "Testing bulletin delivery system",
            "regions": ["NORAM", "Europe"],
            "cve_ids": ["CVE-2026-2481", "CVE-2026-2482"]
        }
        response = requests.post(f"{BASE_URL}/bulletins", json=payload)
        if response.status_code == 201:
            bulletin = response.json()
            log_success(f"Created bulletin ID {bulletin['id']}")
            return bulletin
        else:
            log_error(f"Failed to create bulletin: {response.text}")
            return None
    except Exception as e:
        log_error(f"Exception: {e}")
        return None

# Test 3: Preview bulletin
def test_preview_bulletin(bulletin_id):
    test_step(3, "Preview Bulletin HTML")
    try:
        response = requests.post(
            f"{BASE_URL}/bulletins/{bulletin_id}/preview",
            json={"region": "NORAM"}
        )
        if response.status_code == 200:
            result = response.json()
            log_success(f"Generated HTML preview ({len(result['html_preview'])} bytes)")
            return result
        else:
            log_error(f"Failed to preview: {response.text}")
            return None
    except Exception as e:
        log_error(f"Exception: {e}")
        return None

# Test 4: Send in test mode
def test_send_bulletin_test_mode(bulletin_id):
    test_step(4, "Send Bulletin (TEST MODE)")
    try:
        payload = {
            "regions": ["NORAM", "Europe"],
            "test_mode": True
        }
        response = requests.post(
            f"{BASE_URL}/bulletins/{bulletin_id}/send",
            json=payload
        )
        if response.status_code == 200:
            result = response.json()
            log_success(f"Bulletin queued (test mode)")
            return result
        else:
            log_error(f"Failed to send: {response.text}")
            return None
    except Exception as e:
        log_error(f"Exception: {e}")
        return None

# Test 5: Send in real mode
def test_send_bulletin_real_mode(bulletin_id):
    test_step(5, "Send Bulletin (REAL MODE)")
    try:
        payload = {
            "regions": ["NORAM"],
            "test_mode": False
        }
        response = requests.post(
            f"{BASE_URL}/bulletins/{bulletin_id}/send",
            json=payload
        )
        if response.status_code == 200:
            result = response.json()
            log_success(f"Bulletin queued (real mode)")
            # Wait for queue processing
            time.sleep(2)
            return result
        else:
            log_error(f"Failed to send: {response.text}")
            return None
    except Exception as e:
        log_error(f"Exception: {e}")
        return None

# Test 6: Check delivery logs
def test_check_logs(bulletin_id):
    test_step(6, "Check Delivery Logs")
    try:
        response = requests.get(f"{BASE_URL}/bulletins/{bulletin_id}/logs")
        if response.status_code == 200:
            result = response.json()
            logs = result.get('logs', [])
            log_success(f"Found {len(logs)} log entries")
            for log in logs:
                print(f"  - {log['action']} to {log['region']}: {log['message']}")
            return logs
        else:
            log_error(f"Failed to get logs: {response.text}")
            return None
    except Exception as e:
        log_error(f"Exception: {e}")
        return None

# Test 7: Verify bulletin status
def test_check_bulletin_status(bulletin_id):
    test_step(7, "Verify Bulletin Status")
    try:
        response = requests.get(f"{BASE_URL}/bulletins/{bulletin_id}")
        if response.status_code == 200:
            bulletin = response.json()
            log_success(f"Bulletin status: {bulletin['status']}")
            log_info(f"Created: {bulletin['created_at']}")
            if bulletin.get('sent_at'):
                log_info(f"Sent: {bulletin['sent_at']}")
            return bulletin
        else:
            log_error(f"Failed to get bulletin: {response.text}")
            return None
    except Exception as e:
        log_error(f"Exception: {e}")
        return None

# Main
def main():
    print("\n")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║       BULLETIN DELIVERY SYSTEM - AUTOMATED TEST           ║")
    print("╚══════════════════════════════════════════════════════════╝")
    
    # Run tests
    regions = test_get_regions()
    if not regions:
        log_error("Cannot continue without regions")
        return 1
    
    bulletin = test_create_bulletin()
    if not bulletin:
        log_error("Cannot continue without bulletin")
        return 1
    
    bulletin_id = bulletin['id']
    
    preview = test_preview_bulletin(bulletin_id)
    if not preview:
        log_error("Preview failed")
        return 1
    
    send_test = test_send_bulletin_test_mode(bulletin_id)
    if not send_test:
        log_error("Test mode send failed")
        return 1
    
    logs = test_check_logs(bulletin_id)
    
    # Optional: real mode
    log_info("\n" + "="*60)
    log_info("Ready to test REAL MODE sending?")
    log_info("Configure SMTP first: export SMTP_SERVER=...")
    log_info("Then run: send_bulletin_real_mode()")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

**Run the test:**
```bash
cd backend
python test_bulletin_delivery.py
```

**Expected Output:**
```
============================================================
Step 1: Verify Regions Exist
============================================================
✅ Found 4 regions
  - NORAM: 2 recipients
  - LATAM: 2 recipients
  - Europe: 2 recipients
  - APMEA: 2 recipients

============================================================
Step 2: Create Test Bulletin
============================================================
✅ Created bulletin ID 1

============================================================
Step 3: Preview Bulletin HTML
============================================================
✅ Generated HTML preview (3456 bytes)

============================================================
Step 4: Send Bulletin (TEST MODE)
============================================================
✅ Bulletin queued (test mode)

============================================================
Step 6: Check Delivery Logs
============================================================
✅ Found 2 log entries
  - SENT to NORAM: Test mode - email logged instead of sent
  - SENT to Europe: Test mode - email logged instead of sent
```

---

## Step 5: Manual Testing Checklist

### Phase 1: Creation & Preview
- [ ] Create bulletin with title and body
- [ ] Add multiple CVEs (5+)
- [ ] Select multiple regions (3+)
- [ ] Preview renders without errors
- [ ] HTML shows proper styling:
  - [ ] Header with purple gradient
  - [ ] CVE groups indented
  - [ ] Severity badges colored correctly
  - [ ] Statistics displayed
  - [ ] Footer with CTBA branding

### Phase 2: Test Mode Sending
- [ ] Send in test mode
- [ ] Check backend logs show `[TEST MODE]`
- [ ] Verify logs created in bulletin_logs table
- [ ] Status changes to SENT
- [ ] Each region logged separately

### Phase 3: Real Email Sending
- [ ] Configure SMTP (MailHog recommended)
- [ ] Send real email
- [ ] Email arrives in inbox
- [ ] Email contains:
  - [ ] Correct subject
  - [ ] HTML formatted correctly
  - [ ] All CVEs grouped properly
  - [ ] Recipient list accurate
- [ ] Delivery log records success

### Phase 4: Reminders & Follow-up
- [ ] Trigger reminder manually: `POST /api/bulletins/{id}/remind`
- [ ] Reminder email sent to same recipients
- [ ] Reminder log entry created
- [ ] System prevents duplicate reminders

### Phase 5: Error Handling
- [ ] Send to non-existent region → error logged
- [ ] Invalid email address → error logged
- [ ] SMTP connection failure → retry logic triggered
- [ ] Failed send after max retries → error recorded

---

## Step 6: Email Content Verification

### HTML Email Checklist
```html
✅ DOCTYPE and encoding correct
✅ Responsive design (max-width: 700px)
✅ Header section
   - Title in white on gradient background
   - Region badge
✅ Content section
   - Body text
   - CVE groups
     - Product name
     - CVE list with IDs
     - CVSS/Severity badge
     - Remediation text
   - Statistics table
✅ Footer section
   - CTBA branding
   - Bulletin ID
   - "Do not reply" notice
✅ Colors
   - Purple gradient (#667eea, #764ba2)
   - Critical red (#d32f2f)
   - High orange (#f57c00)
   - Medium yellow (#fbc02d)
   - Low green (#689f38)
```

### Test in Email Client

**Gmail:**
```
1. Create test email account
2. Send test bulletin
3. Verify HTML renders correctly
4. Check responsive design on mobile view
5. Test all links if any
```

**Outlook:**
```
1. Test in different versions (Web, Desktop)
2. Verify colors render correctly
3. Check table formatting
4. Verify embedded styles work
```

**Apple Mail:**
```
1. Test on macOS
2. Test on iOS
3. Verify responsive design
4. Check image display
```

---

## Step 7: Database Verification

### Check Bulletins Created
```sql
SELECT id, title, status, created_at, sent_at 
FROM bulletins 
ORDER BY id DESC 
LIMIT 5;
```

### Check Delivery Logs
```sql
SELECT 
  bulletin_id,
  action,
  region,
  recipients,
  message,
  created_at
FROM bulletin_logs
WHERE bulletin_id = ?
ORDER BY created_at DESC;
```

### Check Regions
```sql
SELECT id, name, recipients, archived_at 
FROM regions
WHERE archived_at IS NULL;
```

### Statistics
```sql
-- Count by status
SELECT status, COUNT(*) as count 
FROM bulletins 
GROUP BY status;

-- Most recent sends
SELECT 
  DATE(sent_at) as send_date,
  COUNT(*) as count
FROM bulletins
WHERE status = 'SENT'
GROUP BY DATE(sent_at)
ORDER BY send_date DESC;
```

---

## Troubleshooting

### ❌ Email Not Sending
```
1. Check SMTP configuration:
   echo $SMTP_SERVER $SMTP_PORT
   
2. Check backend logs:
   grep "Error sending" logs/app.log
   
3. Test SMTP connection:
   python -c "import smtplib; s = smtplib.SMTP('localhost', 587); print('OK')"
   
4. Check if test_mode=true:
   Logs show "[TEST MODE]" if test mode enabled
```

### ❌ Queue Not Processing
```
1. Verify delivery engine thread started:
   grep "Delivery engine ready" logs/app.log
   
2. Check queue size:
   curl http://localhost:5000/api/bulletins/queue-stats
   
3. Process queue manually:
   curl -X POST http://localhost:5000/api/bulletins/process-queue
```

### ❌ Recipients Not Found
```
1. Check region exists:
   curl http://localhost:5000/api/regions | grep NORAM
   
2. Check recipients configured:
   sqlite3 data/cves.db "SELECT recipients FROM regions WHERE name='NORAM';"
   
3. Add recipients:
   curl -X PUT http://localhost:5000/api/regions/1 \
     -d '{"recipients": "user@example.com"}'
```

### ❌ HTML Not Rendering
```
1. Check template syntax:
   grep "Template" logs/app.log
   
2. Verify variables passed:
   See test output for html_preview
   
3. Check email client support:
   Some older clients don't support CSS grid
   Use simpler layout if needed
```

---

## Performance Testing

### Load Test: Send 100 Bulletins
```bash
for i in {1..100}; do
  curl -X POST http://localhost:5000/api/bulletins \
    -H "Content-Type: application/json" \
    -d "{
      \"title\": \"Load Test Bulletin $i\",
      \"body\": \"Testing performance\",
      \"regions\": [\"NORAM\"],
      \"cve_ids\": [\"CVE-2026-2481\"]
    }"
  echo "Created bulletin $i"
done
```

### Measure Queue Performance
```bash
# Send 10 bulletins to queue
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/bulletins/$i/send \
    -H "Content-Type: application/json" \
    -d '{"regions": ["NORAM"], "test_mode": true}'
done

# Process and time
time curl -X POST http://localhost:5000/api/bulletins/process-queue \
  -d '{"max_jobs": 10}'
```

**Expected Performance:**
- Queue processing: ~50-100ms per job
- HTML rendering: ~10-20ms per bulletin
- SMTP send: ~500-1000ms per recipient
- Total per bulletin: ~1-2 seconds

---

## Success Criteria

✅ **System is ready for production when:**
- All steps 1-7 complete without errors
- Test bulletin previews correctly
- Test mode logging works
- Real emails send and arrive
- Delivery logs accurate
- No exceptions in logs
- Response times under 500ms
- Queue processes reliably
- All regions get recipients
- HTML renders in email client

---

**Ready to start testing?** Begin with **Step 2: Test Mode** ✅

