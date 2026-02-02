#!/usr/bin/env python3
"""
Setup script for CVE.org PRIMARY source system
Cleans database and initializes fresh import with CVE.org as primary
"""
import os
import sqlite3

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ctba_platform.db")

def reset_database():
    """Reset database for fresh CVE.org import"""
    
    print("\n" + "="*60)
    print("🔄 RESETTING DATABASE FOR CVEORG PRIMARY SYSTEM")
    print("="*60)
    
    if os.path.exists(DB_FILE):
        print(f"\n⚠️ Backing up existing database...")
        backup_file = DB_FILE + ".backup"
        if os.path.exists(backup_file):
            os.remove(backup_file)
        os.rename(DB_FILE, backup_file)
        print(f"   ✅ Backup created: {backup_file}")
    
    print("\n✅ Database will be recreated on next startup")
    print("\nNext steps:")
    print("  1. Run: python main.py")
    print("  2. Wait for CVE.org import to complete (PRIMARY source)")
    print("  3. Then NVD and CVEdetails imports will merge data")
    print("  4. Run: python test_cveorg_primary.py")
    print("     to verify the system is working correctly")
    
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    reset_database()
