#!/usr/bin/env python3
"""
Quick test script for Requirement 2.4 API endpoints
Tests the newly created delivery engine endpoints
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000/api"

def test_regions_endpoint():
    """Test GET /regions endpoint"""
    print("\n" + "="*60)
    print("Testing: GET /api/regions")
    print("="*60)
    
    try:
        response = requests.get(f"{BASE_URL}/regions")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ SUCCESS")
        else:
            print(f"❌ FAILED: {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")


def test_audit_logs_endpoint():
    """Test GET /audit-logs endpoint"""
    print("\n" + "="*60)
    print("Testing: GET /api/audit-logs")
    print("="*60)
    
    try:
        response = requests.get(f"{BASE_URL}/audit-logs")
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"Response (truncated): {json.dumps(data[:2] if isinstance(data, list) else data, indent=2)}")
        
        if response.status_code == 200:
            print("✅ SUCCESS")
        else:
            print(f"❌ FAILED: {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")


def test_delivery_queue_status():
    """Test GET /delivery-queue/status endpoint"""
    print("\n" + "="*60)
    print("Testing: GET /api/delivery-queue/status")
    print("="*60)
    
    try:
        response = requests.get(f"{BASE_URL}/delivery-queue/status")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ SUCCESS")
        else:
            print(f"❌ FAILED: {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")


def test_mailing_list_endpoint():
    """Test GET /regions/{id}/mailing-list endpoint"""
    print("\n" + "="*60)
    print("Testing: GET /api/regions/1/mailing-list")
    print("="*60)
    
    try:
        response = requests.get(f"{BASE_URL}/regions/1/mailing-list")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ SUCCESS")
        else:
            print(f"❌ FAILED: {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")


if __name__ == "__main__":
    print("\n" + "🔧 REQUIREMENT 2.4 API ENDPOINT TESTS".center(60, "="))
    print(f"Testing at {BASE_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    test_regions_endpoint()
    test_audit_logs_endpoint()
    test_delivery_queue_status()
    test_mailing_list_endpoint()
    
    print("\n" + "="*60)
    print("Testing completed!")
    print("="*60)
