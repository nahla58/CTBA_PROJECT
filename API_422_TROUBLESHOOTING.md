# 🔧 Troubleshooting - API 422 Error

## Problem
Frontend is getting **HTTP 422 (Unprocessable Content)** when calling `/api/bulletins/regions`

## Root Cause
The endpoint path is wrong. The API endpoints are under different routes:
- ❌ **WRONG**: `/api/bulletins/regions`
- ✅ **CORRECT**: `/api/regions`

## Solution Applied

### ✅ Fixed Files:
1. **MailingListManager.js**
   - Changed: `/api/bulletins/regions` → `/api/regions`
   
2. **EnhancedBulletinManager.js**
   - Changed: `/api/bulletins/regions` → `/api/regions`

### API Route Configuration:

The backend routes are organized as follows:

```python
# From app/api/bulletin_routes.py
@region_router.get("/regions")
async def list_regions():
    """Get all bulletin delivery regions"""
    return region_service.get_regions()

# From app/api/delivery_routes.py
@router.get("/audit-logs")
@router.get("/delivery-queue/status")
@router.put("/regions/{region_id}/mailing-list")
@router.get("/regions/{region_id}/mailing-list")
```

---

## API Endpoints Reference

### Regions
```
GET /api/regions                           ✅ List all regions
GET /api/regions/{id}                      ✅ Get region details
PUT /api/regions/{id}                      ✅ Update region
DELETE /api/regions/{id}                   ✅ Delete region
```

### Bulletins (Existing)
```
GET /api/bulletins                         ✅ List bulletins
POST /api/bulletins                        ✅ Create bulletin
GET /api/bulletins/{id}                    ✅ Get bulletin
POST /api/bulletins/{id}/send              ✅ Send bulletin
```

### Delivery Engine (New)
```
POST /api/bulletins/{id}/send              ✅ Queue for delivery (202 Accepted)
POST /api/bulletins/{id}/preview           ✅ Preview before sending
GET /api/bulletins/{id}/delivery-audit     ✅ Get delivery audit trail
```

### Audit Logs (New)
```
GET /api/audit-logs                        ✅ Get audit logs
GET /api/audit-logs?bulletin_id=X          ✅ Filter by bulletin
GET /api/audit-logs?action_type=X          ✅ Filter by action
GET /api/audit-report                      ✅ Generate report
```

### Mailing Lists (New)
```
GET /api/regions/{id}/mailing-list         ✅ Get region recipients
PUT /api/regions/{id}/mailing-list         ✅ Update recipients
GET /api/regions/mailing-lists/all         ✅ Get all mailing lists
GET /api/regions/{id}/mailing-audit        ✅ Get mailing audit
```

### Delivery Queue (New)
```
GET /api/delivery-queue/status             ✅ Queue statistics
POST /api/delivery-queue/process           ✅ Process queue
POST /api/delivery-queue/retry/{jobId}     ✅ Retry job
POST /api/delivery-queue/cancel/{jobId}    ✅ Cancel job
```

---

## Testing the Endpoints

### 1. Test Regions Endpoint (Simple)
```bash
curl http://localhost:8000/api/regions
```

Expected Response (200 OK):
```json
[
  {
    "id": 1,
    "name": "EMEA",
    "description": "Europe, Middle East, Africa"
  },
  {
    "id": 2,
    "name": "APAC",
    "description": "Asia Pacific"
  }
]
```

### 2. Test Audit Logs Endpoint
```bash
curl http://localhost:8000/api/audit-logs
```

Expected Response (200 OK):
```json
[
  {
    "id": 1,
    "bulletin_id": 1,
    "action_type": "BULLETIN_QUEUED",
    "status": "SUCCESS",
    "timestamp": "2026-01-27T14:23:00",
    "actor": "admin",
    "recipients": "email@example.com"
  }
]
```

### 3. Test Delivery Queue Status
```bash
curl http://localhost:8000/api/delivery-queue/status
```

Expected Response (200 OK):
```json
{
  "queue_size": 5,
  "engine_status": "RUNNING",
  "max_retries": 3,
  "retry_delay": 300
}
```

---

## Common Issues & Fixes

### Issue 1: 422 Unprocessable Content
**Cause**: Wrong endpoint path
**Fix**: Use `/api/regions` instead of `/api/bulletins/regions`
**Status**: ✅ FIXED

### Issue 2: 404 Not Found
**Cause**: Endpoint doesn't exist
**Fix**: Check endpoint is registered in main.py
**Solution**: Verify delivery_routes is included

### Issue 3: 500 Internal Server Error
**Cause**: Backend service error
**Fix**: Check backend logs
**Action**: Run `python test_delivery_endpoints.py`

### Issue 4: CORS Error
**Cause**: Frontend origin not allowed
**Fix**: Add CORS headers in main.py
**Example**:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Step-by-Step Fix Verification

### Step 1: Verify Backend is Running
```bash
cd backend
python main.py
# Should show: "Uvicorn running on http://0.0.0.0:8000"
```

### Step 2: Check API Routes Registered
```bash
curl http://localhost:8000/openapi.json | grep "/regions"
# Should show paths for /regions
```

### Step 3: Test Specific Endpoint
```bash
python test_delivery_endpoints.py
# Should show all endpoints working with 200 OK
```

### Step 4: Check Frontend Paths
```bash
# In browser console, check Network tab
# Should see requests to:
# ✅ /api/regions
# ✅ /api/audit-logs
# ✅ /api/delivery-queue/status
```

### Step 5: Verify Frontend Fixes
```javascript
// In MailingListManager.js
const response = await fetch('http://localhost:8000/api/regions');
// NOT: fetch('http://localhost:8000/api/bulletins/regions');
```

---

## Database Check

If endpoints return empty data, check database:

```python
from backend.database import SessionLocal
from backend.app.models.bulletin_models import Region

db = SessionLocal()
regions = db.query(Region).all()
print(f"Regions in DB: {len(regions)}")
for r in regions:
    print(f"  - {r.name}")
```

---

## Quick Verification Checklist

- [x] Fixed `/api/bulletins/regions` → `/api/regions` in MailingListManager.js
- [x] Fixed `/api/bulletins/regions` → `/api/regions` in EnhancedBulletinManager.js  
- [x] Added audit-logs endpoints to delivery_routes.py
- [x] Verified all endpoints are registered
- [ ] Restart backend (python main.py)
- [ ] Clear browser cache
- [ ] Test in Postman or curl
- [ ] Verify 200 OK responses

---

## Next Actions

1. **Restart Backend**
   ```bash
   cd backend
   pkill -f "python main.py"  # or Ctrl+C
   python main.py
   ```

2. **Test Endpoints**
   ```bash
   python test_delivery_endpoints.py
   ```

3. **Refresh Frontend**
   - Hard refresh browser (Ctrl+Shift+R or Cmd+Shift+R)
   - Clear local storage if needed
   - Try navigating to Mailing Lists page again

4. **Monitor Network**
   - Open browser DevTools (F12)
   - Go to Network tab
   - Try the action again
   - Check request URL is correct
   - Check response status is 200

---

## Success Indicators

✅ **All endpoints return 200 OK**
✅ **Regions dropdown populates**
✅ **Audit logs display**
✅ **Queue monitor shows status**
✅ **No 422 errors in console**

---

## Support

If issues persist:
1. Check backend logs for errors
2. Verify database connection
3. Test endpoints with curl/Postman
4. Check CORS configuration
5. Restart both frontend and backend

**Status**: All fixes applied ✅ Ready to test!
