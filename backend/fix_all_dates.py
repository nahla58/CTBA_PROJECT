#!/usr/bin/env python
"""
Fix dates in existing CVEs by fetching correct published_date from CVE.org
"""

import sqlite3
import requests
import time
from datetime import datetime
import pytz

DB_FILE = 'ctba_platform.db'

def format_date_for_storage(date_str):
    """Convert any date format to storage format with explicit UTC marker"""
    if not date_str:
        return None
    
    try:
        date_str = str(date_str).strip()
        
        # Handle different formats
        if date_str.endswith('Z'):
            # ISO format with Z
            dt = datetime.fromisoformat(date_str[:-1] + '+00:00')
        elif '+' in date_str or date_str.endswith('+00:00'):
            # Already has timezone
            if '..' in date_str:
                date_str = date_str.replace('..', '.')
            dt = datetime.fromisoformat(date_str)
        else:
            # Try parsing without timezone
            try:
                dt = datetime.fromisoformat(date_str)
            except:
                return None
        
        # Ensure UTC timezone
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.UTC)
        else:
            dt = dt.astimezone(pytz.UTC)
        
        # Return in ISO format with explicit +00:00
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '+00:00'
    except Exception as e:
        print(f"Error formatting date '{date_str}': {e}")
        return None

def fix_cve_dates():
    """Fetch correct dates from CVE.org and update database"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all CVEs
    cursor.execute('SELECT cve_id, published_date FROM cves WHERE source_primary IN ("NVD", "cveorg")')
    cves = cursor.fetchall()
    
    fixed = 0
    failed = 0
    
    print(f"Total CVEs to check: {len(cves)}")
    print("-" * 80)
    
    for i, row in enumerate(cves):
        cve_id = row['cve_id']
        old_date = row['published_date']
        
        try:
            # Fetch from CVE.org
            url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                print(f"[{i+1}/{len(cves)}] ❌ {cve_id}: CVE.org returned {response.status_code}")
                failed += 1
                time.sleep(0.5)
                continue
            
            cveorg_data = response.json()
            cve_metadata = cveorg_data.get('cveMetadata', {})
            date_published = cve_metadata.get('datePublished', '')
            date_updated = cve_metadata.get('dateUpdated', '')
            
            if not date_published:
                print(f"[{i+1}/{len(cves)}] ⚠️ {cve_id}: No datePublished in CVE.org")
                failed += 1
                time.sleep(0.5)
                continue
            
            # Format for storage
            new_pub_date = format_date_for_storage(date_published)
            new_upd_date = format_date_for_storage(date_updated) if date_updated else new_pub_date
            
            if not new_pub_date:
                print(f"[{i+1}/{len(cves)}] ⚠️ {cve_id}: Could not parse dates from CVE.org")
                failed += 1
                time.sleep(0.5)
                continue
            
            # Update database
            cursor.execute('''
                UPDATE cves 
                SET published_date = ?, last_updated = ?
                WHERE cve_id = ?
            ''', (new_pub_date, new_upd_date, cve_id))
            
            # Extract short dates for display
            pub_short = new_pub_date[:10]
            old_short = old_date[:10] if old_date else 'N/A'
            
            if pub_short != old_short:
                print(f"[{i+1}/{len(cves)}] ✅ {cve_id}: {old_short} → {pub_short}")
                fixed += 1
            else:
                print(f"[{i+1}/{len(cves)}] ℹ️ {cve_id}: Already correct ({pub_short})")
            
            time.sleep(0.5)  # Rate limiting
            
        except requests.exceptions.Timeout:
            print(f"[{i+1}/{len(cves)}] ⏱️ {cve_id}: Timeout")
            failed += 1
        except Exception as e:
            print(f"[{i+1}/{len(cves)}] ❌ {cve_id}: {str(e)[:50]}")
            failed += 1
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 80)
    print(f"SUMMARY:")
    print(f"  ✅ Fixed: {fixed}")
    print(f"  ❌ Failed: {failed}")
    print(f"  ℹ️ Total: {len(cves)}")
    print("=" * 80)

if __name__ == '__main__':
    fix_cve_dates()
