# Fichier : populate_blacklist.py
import sqlite3

def populate_initial_blacklist():
    """Ajoute des produits courants à la blacklist"""
    conn = sqlite3.connect("ctba.db")
    cursor = conn.cursor()
    
    # Produits souvent hors scope
    blacklisted = [
        ("Adobe", "Flash Player", "Déprécié et hors scope"),
        ("Oracle", "Java SE 8", "Ancienne version non supportée"),
        ("Microsoft", "Internet Explorer", "Navigateur déprécié"),
        ("Apple", "QuickTime", "Logiciel déprécié"),
    ]
    
    for vendor, product, reason in blacklisted:
        cursor.execute('''
            INSERT OR IGNORE INTO blacklisted_products (vendor, product, reason)
            VALUES (?, ?, ?)
        ''', (vendor, product, reason))
    
    conn.commit()
    
    # Afficher
    cursor.execute("SELECT vendor, product, reason FROM blacklisted_products")
    print("📋 Produits blacklistés :")
    for row in cursor.fetchall():
        print(f"  • {row[0]}/{row[1]} - {row[2]}")
    
    conn.close()

if __name__ == "__main__":
    populate_initial_blacklist()