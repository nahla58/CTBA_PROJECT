#!/usr/bin/env python3
"""
Bulletin Delivery System - Automated Testing Script
Tests all aspects of bulletin creation, preview, and delivery
"""
import sys
import time
import json
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import requests
except ImportError:
    print("❌ requests library not installed. Install with: pip install requests")
    sys.exit(1)

BASE_URL = "http://localhost:5000/api"
TIMEOUT = 10

class Colors:
    """Console color codes"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def test_section(title):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")

def success(message):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def error(message):
    """Print error message"""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

def info(message):
    """Print info message"""
    print(f"{Colors.YELLOW}ℹ️  {message}{Colors.END}")

def warning(message):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

class BulletinTester:
    """Bulletin delivery system tester"""
    
    def __init__(self):
        self.regions = None
        self.bulletin = None
        self.results = {
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }
    
    def check_server(self):
        """Verify server is running"""
        test_section("STEP 1: Server Connectivity")
        try:
            response = requests.get(f"{BASE_URL}/bulletins", timeout=TIMEOUT)
            if response.status_code in [200, 401, 403]:  # Any response means server is up
                success(f"Server is running on {BASE_URL}")
                self.results['passed'] += 1
                return True
            else:
                error(f"Server returned unexpected status: {response.status_code}")
                self.results['failed'] += 1
                return False
        except requests.exceptions.ConnectionError:
            error(f"Cannot connect to {BASE_URL}")
            error("Make sure backend is running: python main.py")
            self.results['failed'] += 1
            return False
        except Exception as e:
            error(f"Connection error: {e}")
            self.results['failed'] += 1
            return False
    
    def get_regions(self):
        """Get available regions"""
        test_section("STEP 2: Verify Regions")
        try:
            response = requests.get(f"{BASE_URL}/regions", timeout=TIMEOUT)
            response.raise_for_status()
            
            if isinstance(response.json(), list):
                self.regions = response.json()
            else:
                self.regions = response.json().get('regions', [])
            
            if not self.regions:
                warning("No regions configured")
                self.results['warnings'] += 1
                # Create default regions
                return self._create_default_regions()
            
            success(f"Found {len(self.regions)} regions:")
            for region in self.regions:
                recipients = region.get('recipients', [])
                if isinstance(recipients, str):
                    recipient_list = recipients.split(',')
                else:
                    recipient_list = recipients
                
                count = len(recipient_list) if recipient_list else 0
                print(f"  • {region['name']}: {count} recipient(s)")
            
            self.results['passed'] += 1
            return True
        
        except Exception as e:
            error(f"Failed to get regions: {e}")
            self.results['failed'] += 1
            return False
    
    def _create_default_regions(self):
        """Create default regions if none exist"""
        try:
            default_regions = [
                {
                    "name": "NORAM",
                    "description": "North America",
                    "recipients": "test-noram@example.com"
                },
                {
                    "name": "Europe",
                    "description": "European Operations",
                    "recipients": "test-europe@example.com"
                }
            ]
            
            for region in default_regions:
                response = requests.post(f"{BASE_URL}/regions", json=region, timeout=TIMEOUT)
                if response.status_code == 201:
                    success(f"Created region: {region['name']}")
            
            # Re-fetch regions
            response = requests.get(f"{BASE_URL}/regions", timeout=TIMEOUT)
            self.regions = response.json() if isinstance(response.json(), list) else response.json().get('regions', [])
            self.results['passed'] += 1
            return True
        
        except Exception as e:
            error(f"Failed to create default regions: {e}")
            self.results['failed'] += 1
            return False
    
    def create_bulletin(self):
        """Create a test bulletin"""
        test_section("STEP 3: Create Test Bulletin")
        try:
            payload = {
                "title": f"TEST Bulletin {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "body": "This is an automated test bulletin for delivery system verification.",
                "regions": [r['name'] for r in self.regions[:2]] if self.regions else ["NORAM"],
                "cve_ids": ["CVE-2026-2481", "CVE-2026-2482"]  # Use existing CVEs from database
            }
            
            response = requests.post(f"{BASE_URL}/bulletins", json=payload, timeout=TIMEOUT)
            response.raise_for_status()
            
            self.bulletin = response.json()
            success(f"Created bulletin ID {self.bulletin['id']}")
            print(f"  • Title: {self.bulletin['title']}")
            print(f"  • Status: {self.bulletin['status']}")
            print(f"  • Regions: {', '.join(self.bulletin.get('regions', []))}")
            
            self.results['passed'] += 1
            return True
        
        except Exception as e:
            error(f"Failed to create bulletin: {e}")
            self.results['failed'] += 1
            return False
    
    def preview_bulletin(self):
        """Preview bulletin HTML"""
        test_section("STEP 4: Preview Bulletin HTML")
        if not self.bulletin:
            error("No bulletin to preview")
            self.results['failed'] += 1
            return False
        
        try:
            response = requests.post(
                f"{BASE_URL}/bulletins/{self.bulletin['id']}/preview",
                json={"region": self.bulletin.get('regions', ['NORAM'])[0]},
                timeout=TIMEOUT
            )
            response.raise_for_status()
            
            result = response.json()
            if 'html_preview' in result:
                html = result['html_preview']
            elif 'html' in result:
                html = result['html']
            else:
                html = str(result)
            
            html_size = len(html)
            success(f"Generated HTML preview ({html_size} bytes)")
            
            # Validate HTML content
            checks = [
                ('<!DOCTYPE html>', "HTML doctype"),
                ('</html>', "HTML closure"),
                (self.bulletin['title'], "Bulletin title"),
                ('CVE-2026', "CVE references"),
                ('padding', "CSS styling"),
            ]
            
            for check_str, description in checks:
                if check_str in html:
                    success(f"  ✓ {description} found")
                else:
                    warning(f"  ⚠ {description} not found")
            
            # Save preview for manual inspection
            with open('bulletin_preview.html', 'w') as f:
                f.write(html)
            info(f"Saved preview to: bulletin_preview.html")
            
            self.results['passed'] += 1
            return True
        
        except Exception as e:
            error(f"Failed to preview bulletin: {e}")
            self.results['failed'] += 1
            return False
    
    def send_test_mode(self):
        """Send bulletin in test mode"""
        test_section("STEP 5: Send Bulletin (TEST MODE)")
        if not self.bulletin:
            error("No bulletin to send")
            self.results['failed'] += 1
            return False
        
        try:
            payload = {
                "regions": self.bulletin.get('regions', ['NORAM']),
                "test_mode": True
            }
            
            response = requests.post(
                f"{BASE_URL}/bulletins/{self.bulletin['id']}/send",
                json=payload,
                timeout=TIMEOUT
            )
            response.raise_for_status()
            
            result = response.json()
            success(f"Bulletin queued for delivery (test mode)")
            print(f"  • Message: {result.get('message', 'N/A')}")
            
            # Wait for queue processing
            time.sleep(2)
            
            self.results['passed'] += 1
            return True
        
        except Exception as e:
            error(f"Failed to send bulletin: {e}")
            self.results['failed'] += 1
            return False
    
    def check_delivery_logs(self):
        """Check delivery logs"""
        test_section("STEP 6: Check Delivery Logs")
        if not self.bulletin:
            error("No bulletin to check")
            self.results['failed'] += 1
            return False
        
        try:
            response = requests.get(
                f"{BASE_URL}/bulletins/{self.bulletin['id']}/logs",
                timeout=TIMEOUT
            )
            response.raise_for_status()
            
            result = response.json()
            logs = result.get('logs', [])
            
            if logs:
                success(f"Found {len(logs)} delivery log entries:")
                for log in logs:
                    action = log.get('action', 'UNKNOWN')
                    region = log.get('region', 'N/A')
                    message = log.get('message', 'N/A')
                    print(f"  • {action} to {region}: {message}")
                
                self.results['passed'] += 1
                return True
            else:
                warning("No delivery logs found")
                self.results['warnings'] += 1
                return False
        
        except Exception as e:
            error(f"Failed to get delivery logs: {e}")
            self.results['failed'] += 1
            return False
    
    def check_bulletin_status(self):
        """Check bulletin status"""
        test_section("STEP 7: Verify Bulletin Status")
        if not self.bulletin:
            error("No bulletin to check")
            self.results['failed'] += 1
            return False
        
        try:
            response = requests.get(
                f"{BASE_URL}/bulletins/{self.bulletin['id']}",
                timeout=TIMEOUT
            )
            response.raise_for_status()
            
            bulletin = response.json()
            success(f"Bulletin status: {bulletin.get('status', 'UNKNOWN')}")
            print(f"  • ID: {bulletin.get('id')}")
            print(f"  • Title: {bulletin.get('title')}")
            print(f"  • Status: {bulletin.get('status')}")
            print(f"  • Created: {bulletin.get('created_at')}")
            if bulletin.get('sent_at'):
                print(f"  • Sent: {bulletin.get('sent_at')}")
            
            self.results['passed'] += 1
            return True
        
        except Exception as e:
            error(f"Failed to get bulletin status: {e}")
            self.results['failed'] += 1
            return False
    
    def test_reminder(self):
        """Test manual reminder"""
        test_section("STEP 8: Test Manual Reminder")
        if not self.bulletin:
            error("No bulletin to remind")
            self.results['failed'] += 1
            return False
        
        try:
            response = requests.post(
                f"{BASE_URL}/bulletins/{self.bulletin['id']}/remind",
                json={},
                timeout=TIMEOUT
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                success(f"Reminder sent successfully")
                print(f"  • Message: {result.get('message', 'N/A')}")
                self.results['passed'] += 1
                return True
            else:
                warning(f"Reminder endpoint returned {response.status_code}")
                self.results['warnings'] += 1
                return True  # Not critical
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                warning("Reminder endpoint not available (optional feature)")
                self.results['warnings'] += 1
                return True
            else:
                error(f"Failed to send reminder: {e}")
                self.results['failed'] += 1
                return False
        except Exception as e:
            warning(f"Could not test reminder: {e}")
            self.results['warnings'] += 1
            return True  # Not critical
    
    def print_summary(self):
        """Print test summary"""
        test_section("TEST SUMMARY")
        
        total = self.results['passed'] + self.results['failed'] + self.results['warnings']
        
        print(f"{Colors.GREEN}✅ Passed: {self.results['passed']}{Colors.END}")
        print(f"{Colors.RED}❌ Failed: {self.results['failed']}{Colors.END}")
        print(f"{Colors.YELLOW}⚠️  Warnings: {self.results['warnings']}{Colors.END}")
        print(f"\n{Colors.BOLD}Total: {total} checks{Colors.END}\n")
        
        if self.results['failed'] == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}✅ ALL TESTS PASSED!{Colors.END}")
            if self.results['warnings'] > 0:
                print(f"\n{Colors.YELLOW}⚠️  {self.results['warnings']} warnings - review above{Colors.END}")
            return 0
        else:
            print(f"{Colors.RED}{Colors.BOLD}❌ SOME TESTS FAILED - REVIEW ABOVE{Colors.END}")
            return 1
    
    def run_all(self):
        """Run all tests"""
        print(f"\n{Colors.BOLD}")
        print("╔════════════════════════════════════════════════════════════════╗")
        print("║     BULLETIN DELIVERY SYSTEM - AUTOMATED TEST SUITE            ║")
        print("║               Testing creation, preview, and sending           ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}\n")
        
        tests = [
            ("Server Connection", self.check_server),
            ("Regions Configuration", self.get_regions),
            ("Bulletin Creation", self.create_bulletin),
            ("HTML Preview", self.preview_bulletin),
            ("Test Mode Send", self.send_test_mode),
            ("Delivery Logs", self.check_delivery_logs),
            ("Bulletin Status", self.check_bulletin_status),
            ("Manual Reminder", self.test_reminder),
        ]
        
        for test_name, test_func in tests:
            try:
                test_func()
            except Exception as e:
                error(f"Unexpected error in {test_name}: {e}")
                self.results['failed'] += 1
        
        return self.print_summary()

def main():
    """Main entry point"""
    tester = BulletinTester()
    return tester.run_all()

if __name__ == "__main__":
    sys.exit(main())
