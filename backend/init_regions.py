#!/usr/bin/env python3
"""
Initialize bulletin regions in the database
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.bulletin_service import RegionService

def initialize_regions():
    """Create default regions per specification"""
    region_service = RegionService()
    
    # Define regions per specification: NORAM, LATAM, Europe, APMEA
    default_regions = [
        {
            "name": "NORAM",
            "description": "North American region",
            "recipients": "admin@noram.local,security@noram.local"
        },
        {
            "name": "LATAM",
            "description": "Latin American region",
            "recipients": "admin@latam.local,security@latam.local"
        },
        {
            "name": "EUROPE",
            "description": "European region",
            "recipients": "admin@europe.local,security@europe.local"
        },
        {
            "name": "APMEA",
            "description": "Asia-Pacific and Middle East & Africa region",
            "recipients": "admin@apmea.local,security@apmea.local"
        }
    ]
    
    print("Initializing regions per specification...")
    
    # Clear existing regions
    try:
        conn = region_service._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM regions")
        conn.commit()
        conn.close()
        print("✓ Cleared existing regions")
    except Exception as e:
        print(f"Note: Could not clear existing regions: {e}")
    
    existing_regions = region_service.get_regions()
    existing_names = {r['name'] for r in existing_regions}
    
    for region_data in default_regions:
        try:
            if region_data["name"] in existing_names:
                print(f"✓ Region '{region_data['name']}' already exists")
                continue
            
            region = region_service.create_region(
                name=region_data["name"],
                description=region_data["description"],
                recipients=region_data["recipients"]
            )
            print(f"✓ Created region: {region_data['name']}")
        except ValueError as e:
            print(f"ℹ Region already exists: {region_data['name']}")
        except Exception as e:
            print(f"✗ Error creating region {region_data['name']}: {e}")
    
    # Display all regions
    print("\nAll regions:")
    regions = region_service.get_regions()
    for region in regions:
        print(f"  - {region.get('name', 'Unknown')}: {region.get('description', '')}")
    
    print(f"\nTotal regions: {len(regions)}")

if __name__ == "__main__":
    initialize_regions()
