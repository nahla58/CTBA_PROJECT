"""
Initialize region mailing lists from regions
Maps existing regions to mailing lists with To/Cc/Bcc support
"""
import sqlite3
import logging
import os
import sys

# Ensure we're in the backend directory
backend_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(backend_dir)

from services.region_mailing_service import RegionMailingService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_region_mailing_lists():
    """Initialize mailing lists for all regions"""
    try:
        mailing_service = RegionMailingService()
        
        # Get all existing regions
        db_path = 'ctba_platform.db'
        if not os.path.exists(db_path):
            logger.error(f"❌ Database not found: {db_path}")
            logger.info(f"📁 Current directory: {os.getcwd()}")
            return False
            
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, name, recipients FROM regions')
        regions = cursor.fetchall()
        conn.close()
        
        logger.info(f"📧 Initializing mailing lists for {len(regions)} region(s)...")
        
        for region_id, region_name, recipients_str in regions:
            try:
                # Parse recipients from CSV
                to_recipients = [e.strip() for e in recipients_str.split(',') if e.strip()]
                
                if not to_recipients:
                    logger.warning(f"Skipping {region_name}: no recipients")
                    continue
                
                # Setup mailing list with default structure:
                # To = all recipients (security team)
                # Cc = optional (managers)
                # Bcc = optional (audit)
                
                mailing_service.setup_region_mailing(
                    region_id=region_id,
                    to_recipients=to_recipients,
                    cc_recipients=None,
                    bcc_recipients=None,
                    changed_by='INIT'
                )
                
                logger.info(
                    f"✅ Initialized {region_name}: "
                    f"To={len(to_recipients)} recipients"
                )
            
            except Exception as e:
                logger.error(f"Error initializing {region_name}: {e}")
        
        logger.info("✅ Region mailing lists initialization complete!")
        
    except Exception as e:
        logger.error(f"Error initializing mailing lists: {e}")
        raise


if __name__ == '__main__':
    init_region_mailing_lists()
