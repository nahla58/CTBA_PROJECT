#!/usr/bin/env python3
"""
Script to clean up corrupted affected_products entries from the database.
Removes products that contain noise/invalid patterns like Vuldb, ?, etc.
"""

import sqlite3
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB_PATH = 'ctba_platform.db'

def is_valid_product(vendor: str, product: str) -> bool:
    """Check if product is valid (same logic as in main.py)"""
    if not vendor or not product:
        return False
    
    noise_patterns = [
        'vuldb', '?ctiid', '?id', '?submit', 'ctiid', 'submit',
        'user attachments', 'prior', 'dev', 'esm.sh', 'lx 66 lx',
        'davcloudz', 'github', 'github:', 'bugzilla'
    ]
    
    vendor_lower = vendor.lower()
    product_lower = product.lower()
    
    # Check if vendor or product contains noise
    for pattern in noise_patterns:
        if pattern in vendor_lower or pattern in product_lower:
            return False
    
    # Reject if contains special characters
    if '?' in product or '?' in vendor:
        return False
    
    # Vendor should be at least 2 chars and reasonably short
    if len(vendor) < 2 or len(vendor) > 100:
        return False
    
    # Product should be at least 2 chars
    if len(product) < 2:
        return False
    
    # Both should contain at least one alphanumeric character
    if not any(c.isalnum() for c in vendor) or not any(c.isalnum() for c in product):
        return False
    
    # Reject if vendor == product
    if vendor_lower == product_lower:
        return False
    
    return True

def clean_affected_products():
    """Remove corrupted affected_products entries"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all affected products
        cursor.execute("SELECT id, cve_id, vendor, product FROM affected_products")
        rows = cursor.fetchall()
        
        total = len(rows)
        deleted = 0
        
        logger.info(f"📊 Found {total} affected_products entries")
        
        # Check each one
        for row in rows:
            product_id = row['id']
            cve_id = row['cve_id']
            vendor = row['vendor']
            product = row['product']
            
            if not is_valid_product(vendor, product):
                cursor.execute("DELETE FROM affected_products WHERE id = ?", (product_id,))
                logger.info(f"🗑️  Deleted corrupted: {cve_id} -> {vendor}:{product}")
                deleted += 1
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Cleanup complete: Deleted {deleted}/{total} corrupted entries")
        return deleted
        
    except Exception as e:
        logger.error(f"❌ Error during cleanup: {e}")
        return 0

if __name__ == '__main__':
    logger.info("🚀 Starting affected_products cleanup...")
    cleaned = clean_affected_products()
    logger.info(f"📈 Result: {cleaned} corrupted entries removed")
