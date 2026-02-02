# 📬 Bulletin System - Quick Reference Card

## Email Delivery Flow (5 Minutes Overview)

### How It Works:
```
1. CREATE BULLETIN
   ↓
   POST /api/bulletins
   {title, body, regions, cve_ids}
   
2. QUEUE FOR DELIVERY
   ↓
   POST /api/bulletins/{id}/send
   {regions, test_mode}
   → Added to delivery_queue
   
3. PROCESS QUEUE (Background)
   ↓
   BulletinDeliveryEngine.process_queue()
   For each job:
     - Get bulletin & regions
     - Render HTML template
     - Send via SMTP (or test mode)
     - Log delivery
   
4. EMAIL RECEIVED
   ↓
   User gets HTML email with:
   - CVE groups by product
   - Severity badges
   - Remediation guidance
   - Statistics
   
5. FOLLOW-UP
   ↓
   Reminders: D+7, D+14
   Escalation: D+30
```

---

## Test in 3 Steps

### Step 1: Start Server (30 seconds)
```bash
cd backend
python main.py
# Wait for: "✅ Email service initialized"
```

### Step 2: Run Auto Test (2 minutes)
```bash
cd backend
python test_bulletin_delivery.py
```
**Output:**
```
✅ Passed: 7
❌ Failed: 0
⚠️  Warnings: 0
✅ ALL TESTS PASSED!
```

### Step 3: Send Real Email (5 minutes)
```bash
# Manual test via API
curl -X POST http://localhost:5000/api/bulletins \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Bulletin",
    "body": "Testing email delivery",
    "regions": ["NORAM"],
    "cve_ids": ["CVE-2026-2481"]
  }'

# Send it
curl -X POST http://localhost:5000/api/bulletins/1/send \
  -d '{"regions": ["NORAM"], "test_mode": false}'

# Check if it sent
curl http://localhost:5000/api/bulletins/1/logs
```

---

## Configuration

### SMTP Settings
```bash
# Environment Variables
export SMTP_SERVER="localhost"        # or gmail, mailtrap, etc
export SMTP_PORT="587"                 # 587=TLS, 465=SSL
export SMTP_FROM_EMAIL="noreply@ctba.local"
export SMTP_PASSWORD="your-password"   # Leave empty for test mode
export SMTP_USE_TLS="true"             # true for TLS, false for SSL
```

### Test SMTP Servers (No Password Needed)

**MailHog (Docker - RECOMMENDED):**
```bash
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
export SMTP_SERVER="localhost"
export SMTP_PORT="1025"
# View emails: http://localhost:8025
```

**Python Debug Server:**
```bash
python -m smtpd -n -c DebuggingServer localhost:1025
# Output: Shows email content in terminal
```

---

## API Endpoints

### Bulletins
```
POST   /api/bulletins                     Create
GET    /api/bulletins                     List all
GET    /api/bulletins/{id}                Get details
PUT    /api/bulletins/{id}                Update (DRAFT only)
DELETE /api/bulletins/{id}                Delete
POST   /api/bulletins/{id}/send           Send/queue
POST   /api/bulletins/{id}/preview        Preview HTML
POST   /api/bulletins/{id}/remind         Send reminder
GET    /api/bulletins/{id}/logs           View delivery logs
```

### Regions
```
GET    /api/regions                       List all
POST   /api/regions                       Create
PUT    /api/regions/{id}                  Update
DELETE /api/regions/{id}                  Delete (soft)
```

---

## Common Commands

### Create Bulletin
```bash
curl -X POST http://localhost:5000/api/bulletins \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Critical Vulnerability Alert",
    "body": "Please review and take action",
    "regions": ["NORAM", "Europe"],
    "cve_ids": ["CVE-2026-2481", "CVE-2026-2482"]
  }'
```

### Send (Test Mode - No SMTP Needed)
```bash
curl -X POST http://localhost:5000/api/bulletins/1/send \
  -H "Content-Type: application/json" \
  -d '{
    "regions": ["NORAM"],
    "test_mode": true
  }'
```

### Send (Real Email)
```bash
curl -X POST http://localhost:5000/api/bulletins/1/send \
  -H "Content-Type: application/json" \
  -d '{
    "regions": ["NORAM", "Europe"],
    "test_mode": false
  }'
```

### Preview
```bash
curl -X POST http://localhost:5000/api/bulletins/1/preview \
  -H "Content-Type: application/json" \
  -d '{"region": "NORAM"}' \
  | python -m json.tool | grep html_preview | head -c 500
```

### Check Logs
```bash
curl http://localhost:5000/api/bulletins/1/logs | python -m json.tool
```

### Add Region
```bash
curl -X POST http://localhost:5000/api/regions \
  -H "Content-Type: application/json" \
  -d '{
    "name": "APAC",
    "description": "Asia-Pacific",
    "recipients": "ciso@ap.company.com,sec@ap.company.com"
  }'
```

---

## Logging & Debugging

### Check Logs
```bash
tail -f logs/app.log

# Or filter
tail -f logs/app.log | grep -i "bulletin\|email"
tail -f logs/app.log | grep -E "ERROR|✅|❌"
```

### Common Log Messages
```
✅ Email sent to 2 recipients          → Success
[TEST MODE] Would send email to...     → Test mode active
❌ Failed to send bulletin             → SMTP error
Bulletin 1 status updated to SENT      → Status changed
Found 2 delivery log entries           → Logs created
```

### Verify Email Service
```bash
python -c "from app.services.email_service import EmailService; es = EmailService(); print(f'SMTP: {es.smtp_server}:{es.smtp_port}')"
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Cannot connect to localhost:5000" | Start server: `python main.py` |
| "Email not sending" | Check SMTP password configured |
| "No regions found" | Create region: `POST /api/regions` |
| "Test mode showing" | Set `test_mode: false` in send request |
| "Email in spam" | Add sender to whitelist |
| "HTML not rendering" | Try simpler email client (Gmail) |
| "Attachment fails" | Verify file path exists |
| "Timeout sending email" | Increase SMTP_PORT timeout |

---

## Email Content

### HTML Template Includes:
- ✅ Professional header with purple gradient
- ✅ CVE groups by product
- ✅ Severity badges (Critical/High/Medium/Low)
- ✅ Remediation guidance
- ✅ Statistics (critical/high count)
- ✅ CTBA footer with bulletin ID
- ✅ Responsive design (mobile-friendly)
- ✅ Plain text fallback for old clients

### Customization:
Edit: `app/services/email_service.py` → `EmailTemplate.BULLETIN_TEMPLATE`

---

## Database Queries

### List Bulletins
```sql
SELECT id, title, status, created_at, sent_at 
FROM bulletins 
ORDER BY id DESC;
```

### Delivery Statistics
```sql
SELECT 
  action,
  region,
  COUNT(*) as count,
  DATE(created_at) as date
FROM bulletin_logs
GROUP BY action, region, DATE(created_at)
ORDER BY date DESC;
```

### Pending Reminders
```sql
SELECT * FROM bulletins
WHERE status = 'SENT'
  AND (last_reminder IS NULL 
    OR last_reminder < datetime('now', '-7 days'));
```

---

## Performance

| Operation | Time |
|-----------|------|
| Create bulletin | <50ms |
| Preview HTML | 10-20ms |
| Queue send | <10ms |
| Process job | 50-100ms |
| SMTP send | 500-1000ms |
| **Total per bulletin** | **~1-2 seconds** |

---

## Security Notes

### Current:
- ✅ Email via SMTP (TLS supported)
- ✅ Delivery logging
- ✅ Audit trail
- ⚠️ No authentication on API (development)

### Recommended:
- [ ] Add API key authentication
- [ ] Rate limiting on endpoints
- [ ] Encrypt SMTP password
- [ ] SSL/TLS on API endpoints
- [ ] Validate email addresses
- [ ] Add CORS headers

---

## Next Steps

1. **Test it now:** `python test_bulletin_delivery.py`
2. **Configure SMTP:** Set environment variables
3. **Send real email:** Use non-test mode
4. **Monitor logs:** Watch delivery in real-time
5. **Check inbox:** Verify HTML rendering
6. **Deploy:** Copy to production server
7. **Scale:** Add more regions as needed

---

## Support

**Quick Tests:**
```bash
# Is server running?
curl http://localhost:5000/api/bulletins

# SMTP working?
python -m smtplib localhost 587

# Database OK?
sqlite3 data/cves.db "SELECT COUNT(*) FROM bulletins;"

# Email configured?
python test_bulletin_delivery.py
```

**Files to Check:**
- Backend logs: `logs/app.log`
- Email service: `app/services/email_service.py`
- Delivery engine: `app/services/delivery_engine.py`
- Bulletin routes: `app/api/bulletin_routes.py`

---

**Made with ❤️ for CTBA Platform | January 2026**

Print this card for your desk! →
```
╔══════════════════════════════════════════╗
║ BULLETIN DELIVERY QUICK REFERENCE         ║
║                                          ║
║ Test:  python test_bulletin_delivery.py  ║
║ Logs:  tail -f logs/app.log              ║
║ API:   http://localhost:5000/api         ║
║                                          ║
║ Create → Queue → Send → Log → Done ✅    ║
╚══════════════════════════════════════════╝
```

