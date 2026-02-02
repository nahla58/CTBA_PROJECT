#!/usr/bin/env python3
"""
Fix CVE dates by fetching the correct dates from CVE.org API
This will update published_date and last_updated from CVE.org metadata

This is a standalone script - it doesn't import main.py to avoid circular dependencies
"""
import sqlite3
import requests
from datetime import datetime, timezone
import time
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Get the database file path (same directory as this script)
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ctba_platform.db")

def format_date_for_storage(date_str: str) -> str:
    """
    Format a date for storage in database.
    Returns format: YYYY-MM-DDTHH:MM:SS.ffffffZ (ISO 8601 with Z suffix)
    This matches the existing database format
    """
    if not date_str:
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    try:
        # Handle both API format (Z) and other formats
        date_str = date_str.strip()
        if date_str.endswith('Z'):
            date_str = date_str[:-1] + '+00:00'
        
        # Parse the date
        dt = datetime.fromisoformat(date_str)
        
        # Ensure it's UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        
        # Format in ISO 8601 with Z suffix (matches existing database format)
        # Include microseconds to match existing records
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
    except Exception as e:
        logger.warning(f"Error formatting date {date_str}: {e}")
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def fix_cve_dates():
    """Fix dates for all CVEs in database by fetching from CVE.org"""
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        logger.info("🚀 Starting CVE date correction...")
        
        # Get all CVEs
        cursor.execute('SELECT cve_id, published_date, last_updated FROM cves ORDER BY cve_id')
        cves = cursor.fetchall()
        
        logger.info(f"📊 Found {len(cves)} CVEs to check/update")
        
        updated_count = 0
        skipped_count = 0
        error_count = 0
        
        for idx, row in enumerate(cves):
            cve_id = row['cve_id']
            
            # Fetch from CVE.org
            try:
                cveorg_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
                response = requests.get(cveorg_url, timeout=10)
                
                if response.status_code == 200:
                    cveorg_data = response.json()
                    cve_metadata = cveorg_data.get('cveMetadata', {})
                    
                    date_published = cve_metadata.get('datePublished', '')
                    date_updated = cve_metadata.get('dateUpdated', '')
                    
                    if date_published or date_updated:
                        # Format dates
                        pub_date = format_date_for_storage(date_published) if date_published else None
                        upd_date = format_date_for_storage(date_updated) if date_updated else None
                        
                        # Update database
                        update_query = "UPDATE cves SET "
                        update_params = []
                        
                        if pub_date:
                            update_query += "published_date = ?, "
                            update_params.append(pub_date)
                        
                        if upd_date:
                            update_query += "last_updated = ?, "
                            update_params.append(upd_date)
                        
                        update_query = update_query.rstrip(', ')
                        update_query += " WHERE cve_id = ?"
                        update_params.append(cve_id)
                        
                        if update_params[:-1]:  # If there's at least one date to update
                            cursor.execute(update_query, update_params)
                            updated_count += 1
                            logger.info(f"[{idx+1}/{len(cves)}] ✅ Updated {cve_id}")
                        else:
                            logger.debug(f"[{idx+1}/{len(cves)}] ⏭️ Skipped {cve_id} (no dates found)")
                            skipped_count += 1
                    else:
                        logger.debug(f"[{idx+1}/{len(cves)}] ⏭️ Skipped {cve_id} (no dates in CVE.org)")
                        skipped_count += 1
                else:
                    logger.warning(f"[{idx+1}/{len(cves)}] ⚠️ CVE.org returned {response.status_code} for {cve_id}")
                    error_count += 1
                
                # Rate limiting - be nice to CVE.org API
                time.sleep(0.5)
                    
            except requests.exceptions.Timeout:
                logger.warning(f"[{idx+1}/{len(cves)}] ⏱️ Timeout fetching {cve_id}")
                error_count += 1
            except Exception as e:
                logger.error(f"[{idx+1}/{len(cves)}] ❌ Error processing {cve_id}: {e}")
                error_count += 1
        
        # Commit changes
        conn.commit()
        logger.info(f"\n✅ Date correction complete!")
        logger.info(f"📊 Updated: {updated_count} | Skipped: {skipped_count} | Errors: {error_count}")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == "__main__":
    fix_cve_dates()
