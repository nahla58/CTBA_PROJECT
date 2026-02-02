"""
Direct test of the PUT endpoint logic without API server
Tests the Pydantic model and service layer directly
"""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.audit_logger import AuditActionType

print("✅ Successfully imported AuditActionType")
print(f"📊 Available actions:")
for action in AuditActionType:
    print(f"   - {action.name} = {action.value}")

# Test that MAILING_LIST_UPDATED exists
try:
    action = AuditActionType.MAILING_LIST_UPDATED
    print(f"\n✅ MAILING_LIST_UPDATED found: {action.value}")
except AttributeError as e:
    print(f"\n❌ MAILING_LIST_UPDATED not found: {e}")

# Test Pydantic model
from app.api.delivery_routes import MailingListUpdate

try:
    data = MailingListUpdate(
        to_recipients=["test1@example.com", "test2@example.com"],
        cc_recipients=["cc@example.com"],
        bcc_recipients=[],
        updated_by="test_user"
    )
    print(f"\n✅ MailingListUpdate model created successfully")
    print(f"   to_recipients: {data.to_recipients}")
    print(f"   cc_recipients: {data.cc_recipients}")
    print(f"   bcc_recipients: {data.bcc_recipients}")
    print(f"   updated_by: {data.updated_by}")
except Exception as e:
    print(f"\n❌ MailingListUpdate model failed: {e}")
