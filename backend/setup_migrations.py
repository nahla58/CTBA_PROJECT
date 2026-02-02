#!/usr/bin/env python3
"""
Complete setup: Apply migrations and fix CVE dates from CVE.org
Run this once after pulling the latest code
"""
import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and report status"""
    print(f"\n{'='*70}")
    print(f"🔧 {description}")
    print(f"{'='*70}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=False, text=True)
        if result.returncode == 0:
            print(f"✅ {description} completed successfully")
            return True
        else:
            print(f"❌ {description} failed with return code {result.returncode}")
            return False
    except Exception as e:
        print(f"❌ Error running {description}: {e}")
        return False

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    print("\n" + "="*70)
    print("🚀 CTBA DATABASE SETUP AND MIGRATION")
    print("="*70)
    
    steps = [
        ("python apply_migration.py", "Apply database migration (add columns)"),
        ("python fix_cve_dates.py", "Fix CVE dates from CVE.org API"),
    ]
    
    failed = []
    
    for cmd, description in steps:
        if not run_command(cmd, description):
            failed.append(description)
    
    print(f"\n{'='*70}")
    print("📊 SETUP SUMMARY")
    print(f"{'='*70}")
    
    if failed:
        print(f"❌ {len(failed)} step(s) failed:")
        for desc in failed:
            print(f"  - {desc}")
        return 1
    else:
        print("✅ All steps completed successfully!")
        print("\n🎉 You can now run the backend with: python main.py")
        return 0

if __name__ == "__main__":
    sys.exit(main())
