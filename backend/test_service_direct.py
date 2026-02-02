"""Test service directly"""
import os
import sys
os.chdir('C:\\essai\\CTBA_PROJECT\\backend')
sys.path.insert(0, '.')

from app.services.region_mailing_service import RegionMailingService

service = RegionMailingService()

# Test getting mailing list for region 8 (EUROPE)
print("Testing region 8 (EUROPE):")
result = service.get_region_mailing_lists(region_id=8)
print(f"  Result: {result}")
if result:
    print(f"  Result type: {type(result)}")
    print(f"  Result dict: {result.to_dict()}")
else:
    print("  ❌ Returned None")

print("\nTesting all regions (6,7,8,9):")
for rid in [6, 7, 8, 9]:
    result = service.get_region_mailing_lists(region_id=rid)
    print(f"  Region {rid}: {result is not None}")
