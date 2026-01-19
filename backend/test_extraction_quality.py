#!/usr/bin/env python
"""Test the improved extraction quality"""

import sys
sys.path.insert(0, '.')

from nlp_extractor import nlp_extractor

# Test cases based on real CVE examples
test_cases = [
    {
        'cve': 'CVE-2026-23733',
        'description': 'A vulnerability in the Java runtime engine allows remote attackers to execute arbitrary code.',
        'expected': [('Oracle', 'Java')]
    },
    {
        'cve': 'CVE-2026-23644',
        'description': 'A critical vulnerability discovered in Esm.Sh module affecting Node.js applications.',
        'expected': [('Node.js', 'Runtime')]
    },
    {
        'cve': 'CVE-2026-0863',
        'description': 'A high severity vulnerability in the Python runtime environment.',
        'expected': [('Python', 'Runtime')]
    },
    {
        'cve': 'CVE-2026-1125',
        'description': 'Multiple vulnerabilities affecting Apache HTTP Server versions before 2.4.56.',
        'expected': [('Apache', 'HTTP Server')]
    },
    {
        'cve': 'CVE-2026-1119',
        'description': 'A vulnerability in PHP runtime engine.',
        'expected': [('PHP', 'Runtime')]
    },
    {
        'cve': 'CVE-2025-15538',
        'description': 'A vulnerability in Assimp library for 3D model loading.',
        'expected': [('Assimp', 'Library')]
    },
]

print("🔍 Testing Improved Product Extraction")
print("=" * 80)

nlp_extractor.initialize()

correct = 0
partial = 0
incorrect = 0

for test in test_cases:
    print(f"\n📌 {test['cve']}")
    print(f"   Description: {test['description'][:70]}...")
    
    results = nlp_extractor.extract_products(test['description'], test['cve'])
    
    if results:
        print(f"   ✅ Found {len(results)} product(s):")
        for product in results[:3]:  # Show top 3
            print(f"      • {product['vendor']}/{product['product']} (confidence: {product['confidence']:.2f}, source: {product['source']})")
        
        # Check if expected matches
        extracted = [(p['vendor'], p['product']) for p in results]
        matched = any(exp in extracted for exp in test['expected'])
        
        if matched:
            correct += 1
            print(f"   ✓ CORRECT (found expected product)")
        else:
            partial += 1
            print(f"   ⚠ PARTIAL (found products but not exact match)")
    else:
        print(f"   ❌ No products extracted")
        incorrect += 1

print("\n" + "=" * 80)
print(f"📊 Results: {correct} correct, {partial} partial, {incorrect} incorrect")
print(f"   Success rate: {(correct + partial) / len(test_cases) * 100:.1f}%")
print("=" * 80)
