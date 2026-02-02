#!/usr/bin/env python3
"""
QUICK START: CVE.org PRIMARY Source System

This script guides you through setting up and testing the new CVE.org primary source system.
"""

def print_header(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def print_step(num, title):
    print(f"\n📌 STEP {num}: {title}")
    print("-" * 70)

def main():
    print_header("🌟 CVE.org PRIMARY SOURCE SYSTEM - QUICK START")
    
    print("""
This implementation makes CVE.org the PRIMARY source for all CVE data,
with NVD, CVEdetails, MSRC, and Hackuity as SECONDARY sources.

KEY FEATURES:
  ✅ CVE.org is ALWAYS the primary source
  ✅ Accurate dates from MITRE (datePublished, dateUpdated)
  ✅ CVSS scores: uses MAXIMUM from all sources
  ✅ Multi-source tracking in sources_secondary
  ✅ Parallel import for faster data collection
  ✅ Automatic merging of conflicting data
    """)
    
    print_step(1, "Backup Current Database (Optional)")
    print("""
If you have existing data you want to keep, back it up first:

    cd c:\\essai\\CTBA_PROJECT\\backend
    copy ctba_platform.db ctba_platform.db.backup
    """)
    
    print_step(2, "Reset Database for Fresh Import")
    print("""
Run the setup script to prepare for CVE.org primary import:

    python setup_cveorg_primary.py
    """)
    
    print_step(3, "Start the API Server")
    print("""
Launch the API with the new CVE.org primary source system:

    python main.py
    
You should see output like:
    
    🌟 Launching CVE.org as PRIMARY source...
    🚀 Starting CVE.org import as PRIMARY source...
    📡 Fetching recent CVEs from CVE.org...
    📊 Found 150 CVEs from CVE.org
    ✅ CVE.org import completed in 23.45s
    
    ⚙️ Launching secondary sources in parallel...
    🚀 Starting NVD import...
    🚀 Starting CVE Details import...
    """)
    
    print_step(4, "Verify Multi-Source System")
    print("""
In another terminal, run the verification script:

    python test_cveorg_primary.py
    
This will show:
    - Number of CVEs from CVE.org (PRIMARY)
    - Number of CVEs from NVD (SECONDARY)
    - Number of CVEs from CVEdetails (SECONDARY)
    - Examples of multi-source CVEs
    - CVSS score merging verification
    - Date format verification
    """)
    
    print_step(5, "Check the API Response")
    print("""
View the dashboard to see the new system in action:

    http://localhost:5000/dashboard
    
You should see:
    - [CVEORG badge] for primary source
    - +2 (or more) for additional secondary sources
    - Hover over the badge to see all sources
    - Dates now match CVE.org official publication dates
    """)
    
    print_step(6, "Fix Dates if Needed")
    print("""
If you need to update dates from CVE.org for existing CVEs:

    python fix_cve_dates.py
    
This will:
    - Fetch correct dates from CVE.org API
    - Update published_date and last_updated
    - Process all CVEs in the database
    """)
    
    print_header("📊 SYSTEM ARCHITECTURE")
    
    print("""
IMPORT PRIORITY:
    
    1️⃣  CVE.org (PRIMARY)
        └─ Official MITRE CVE registry
        └─ Authoritative dates and information
        └─ Source tag: 'CVEORG'
    
    2️⃣  NVD (SECONDARY)
        └─ National Vulnerability Database
        └─ Merged with CVE.org data
        └─ Added to sources_secondary
    
    3️⃣  CVEdetails (SECONDARY)
        └─ Additional vulnerability context
        └─ Risk metrics from independent source
        └─ Added to sources_secondary
    
    4️⃣  MSRC (SECONDARY)
        └─ Microsoft-specific vulnerabilities
    
    5️⃣  Hackuity (SECONDARY)
        └─ Threat intelligence data

DATA MERGING RULES:
    
    When a CVE appears in multiple sources:
    
    • Source Priority: CVE.org is ALWAYS primary
    • CVSS Score: Use MAXIMUM score from all sources
    • Dates: Use dates from CVE.org (authoritative)
    • Tracking: Secondary sources stored in sources_secondary JSON
    
EXAMPLE:

    CVE-2026-1234:
    ├─ PRIMARY (source='CVEORG')
    │  ├─ CVSS Score: 8.5 (v3.1)
    │  ├─ Published: 2026-01-27T01:16:03Z
    │  └─ Updated: 2026-01-27T09:10:42Z
    │
    ├─ SECONDARY: NVD
    │  ├─ CVSS Score: 8.2 (v3.1)
    │  └─ Found: 2026-01-27T09:10:41
    │
    └─ SECONDARY: CVEdetails
       ├─ CVSS Score: 8.7 (v3.1)
       └─ Found: 2026-01-27T09:10:45
    
    FINAL RESULT:
    ├─ Primary: CVEORG
    ├─ CVSS Score: 8.7 (MAX from all sources)
    ├─ Dates: From CVE.org (authoritative)
    └─ Sources: [NVD, CVEdetails]
    """)
    
    print_header("🔧 CONFIGURATION")
    
    print("""
NO SPECIAL CONFIGURATION NEEDED!

The system automatically:
    ✅ Prioritizes CVE.org for all CVEs
    ✅ Launches secondary importers in parallel
    ✅ Merges data on conflicts
    ✅ Uses CVE.org dates as reference
    ✅ Compares and selects max CVSS scores

Optional environment variables:

    CVEDETAILS_API_TOKEN=your_token    # For CVEdetails API
    """)
    
    print_header("📖 FILES REFERENCE")
    
    print("""
NEW/MODIFIED FILES:

    1. main.py
       └─ Added: import_from_cveorg() function
       └─ Modified: import startup order (CVE.org first)
       └─ Modified: run_importers() scheduler function
    
    2. fix_cve_dates.py
       └─ Uses CVE.org as date reference
       └─ Formats dates correctly for storage
    
    3. setup_cveorg_primary.py
       └─ Script to reset database for fresh import
    
    4. test_cveorg_primary.py
       └─ Test and verification script
    
    5. CVEORG_PRIMARY_SYSTEM.md
       └─ Complete documentation
    
    6. QUICKSTART_CVEORG.py
       └─ This file
    """)
    
    print_header("🐛 TROUBLESHOOTING")
    
    print("""
ISSUE: CVE.org API is slow or timing out
    SOLUTION: System will timeout gracefully and continue with other sources
    FALLBACK: NVD and CVEdetails will still import normally
    
ISSUE: Dates don't match CVE.org
    SOLUTION: Run: python fix_cve_dates.py
    CHECK: Verify dates are in UTC format with Z suffix
    
ISSUE: CVSS scores seem incorrect
    SOLUTION: Check if multiple sources have different scores
    EXPECTED: Should see maximum score from all sources
    
ISSUE: Database conflicts
    SOLUTION: Run: python setup_cveorg_primary.py
    RESULT: Old database backed up, fresh database created
    
ISSUE: Secondary sources not showing
    SOLUTION: Wait for secondary importers to complete (~15-30 seconds)
    CHECK: Run: python test_cveorg_primary.py
    
LOGS: Check console output for detailed import information
    Look for: ✅, 📊, ❌, ⚠️ markers
    """)
    
    print_header("📈 PERFORMANCE")
    
    print("""
STARTUP TIME:
    • CVE.org PRIMARY import:  20-30 seconds
    • Secondary imports (parallel): 5-15 seconds each
    • Total: 30-40 seconds
    
SCHEDULED IMPORTS:
    • Run every 30 minutes
    • CVE.org fetched first
    • Secondary sources parallel
    • Rate limiting: respectful API usage
    
METRICS:
    • ~500 CVEs per import from CVE.org
    • ~100-200 additional from NVD
    • ~50-100 from CVEdetails
    • Total active CVEs: 500-800
    """)
    
    print_header("✅ NEXT STEPS")
    
    print("""
1. Run setup_cveorg_primary.py
   └─ Backs up your existing database
   └─ Prepares for fresh import

2. Start the API (python main.py)
   └─ Wait for CVE.org import to complete
   └─ Secondary sources run in parallel

3. Verify the system (python test_cveorg_primary.py)
   └─ Check CVE counts from each source
   └─ Verify multi-source merging
   └─ Confirm dates are correct

4. Use the dashboard
   └─ View CVEs with multiple source badges
   └─ Check accurate dates from CVE.org
   └─ See CVSS scores from all sources

5. Monitor logs
   └─ Watch console for import status
   └─ Scheduled imports run every 30 minutes
   └─ Check for any errors or warnings
    
6. Read the full documentation
   └─ See: CVEORG_PRIMARY_SYSTEM.md
   └─ Complete architecture details
   └─ Database schema information
   └─ API response formats
    """)
    
    print_header("🎉 YOU'RE READY!")
    
    print("""
The CVE.org PRIMARY source system is ready to deploy.
    
Start with:
    
    python setup_cveorg_primary.py
    python main.py
    
Then verify with:
    
    python test_cveorg_primary.py
    
Questions or issues? Check CVEORG_PRIMARY_SYSTEM.md for detailed docs.
    """)
    
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()
