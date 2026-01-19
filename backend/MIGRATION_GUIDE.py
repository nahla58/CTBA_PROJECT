#!/usr/bin/env python3
"""
GUIDE DE MIGRATION: SQLite → PostgreSQL
Étapes complètes pour migrer votre base de données
"""

import subprocess
import sys
import os
from pathlib import Path

def print_section(title):
    """Affiche un titre de section"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def run_command(cmd, description):
    """Exécute une commande et affiche le résultat"""
    print(f"▶️  {description}")
    print(f"   Command: {cmd}\n")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"❌ Erreur lors de: {description}")
        return False
    print(f"✅ {description} - Réussi\n")
    return True

def main():
    """Affiche le guide complet"""
    
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + "  GUIDE COMPLET: Migration SQLite → PostgreSQL".center(68) + "║")
    print("║" + "  CTBA Platform".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    
    # ÉTAPE 1: Installation PostgreSQL
    print_section("ÉTAPE 1: Installation PostgreSQL")
    
    print("OPTIONS D'INSTALLATION:\n")
    
    print("Option A: Chocolatey (Windows - Recommandé)")
    print("-" * 70)
    print("""
choco install postgresql --params '/Password:ctba_admin123' /Y

Cela installe:
  ✓ PostgreSQL Server
  ✓ pgAdmin4 (interface web)
  ✓ Command line tools
  ✓ Initdb
""")
    
    print("\nOption B: Docker (Plus rapide pour test)")
    print("-" * 70)
    print("""
docker run --name postgres-ctba \\
  -e POSTGRES_USER=ctba_user \\
  -e POSTGRES_PASSWORD=ctba_password123 \\
  -e POSTGRES_DB=ctba_platform \\
  -p 5432:5432 \\
  -d postgres:15

Avantages:
  ✓ Installation instantanée
  ✓ Aucune modification système
  ✓ Facile de nettoyer (docker rm postgres-ctba)
""")
    
    print("\nOption C: Télécharge manuel")
    print("-" * 70)
    print("""
1. Visiter: https://www.postgresql.org/download/windows/
2. Télécharger PostgreSQL 15+
3. Exécuter l'installer
4. Noter le mot de passe pour user 'postgres'
5. Ajouter C:\\Program Files\\PostgreSQL\\15\\bin au PATH
""")
    
    # ÉTAPE 2: Créer la base de données
    print_section("ÉTAPE 2: Créer la Base de Données")
    
    print("""
Après installation, créer la base de données:

A) Avec Command Line (psql):
""")
    print("   psql -U postgres -h localhost")
    print("   Password: <le mot de passe installé>")
    print("   postgres=# CREATE DATABASE ctba_platform;")
    print("   postgres=# CREATE USER ctba_user WITH PASSWORD 'ctba_password123';")
    print("   postgres=# GRANT ALL PRIVILEGES ON DATABASE ctba_platform TO ctba_user;")
    print("   postgres=# \\q")
    
    print("""
B) Avec pgAdmin4 (interface graphique):
   1. Lancer pgAdmin4 (vient avec PostgreSQL)
   2. Login avec vos credentials
   3. Right-click "Databases" → Create → Database
   4. Nom: ctba_platform
   5. Propriétaire: postgres
   6. Créer!
""")
    
    # ÉTAPE 3: Configurer les variables d'environnement
    print_section("ÉTAPE 3: Configurer .env")
    
    print("""
Mettre à jour le fichier .env dans c:\\ctba_project\\backend\\.env:

DATABASE_URL=postgresql://ctba_user:ctba_password123@localhost:5432/ctba_platform

OU variables séparées:

DB_TYPE=postgresql
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ctba_platform
DB_USER=ctba_user
DB_PASSWORD=ctba_password123

Voir le fichier .env.example pour tous les paramètres disponibles.
""")
    
    # ÉTAPE 4: Exporter les données SQLite
    print_section("ÉTAPE 4: Exporter les Données SQLite")
    
    print("""
Exécuter le script d'export:

cd c:\\ctba_project\\backend
python migrate_sqlite_to_postgres.py

Cela va créer: migration_to_postgres.sql
Contenant: 
  ✓ CREATE TABLE statements (adaptés pour PostgreSQL)
  ✓ INSERT statements (toutes vos données)
""")
    
    # ÉTAPE 5: Importer dans PostgreSQL
    print_section("ÉTAPE 5: Importer les Données dans PostgreSQL")
    
    print("""
Importer le fichier SQL:

psql -U ctba_user -d ctba_platform -h localhost < migration_to_postgres.sql

Ou sur Windows avec pgAdmin4:
  1. Query Tool
  2. Open file... → migration_to_postgres.sql
  3. Execute (F5)
""")
    
    # ÉTAPE 6: Tester la connexion
    print_section("ÉTAPE 6: Tester la Connexion")
    
    print("""
Vérifier que tout fonctionne:

cd c:\\ctba_project\\backend
python test_postgres_connection.py

Devrait afficher:
  ✅ Connexion réussie
  ✅ Tables trouvées
  ✅ Données importées
  ✅ CVEs, Products, Users, etc.
""")
    
    # ÉTAPE 7: Mettre à jour le code
    print_section("ÉTAPE 7: Mettre à Jour le Code (si nécessaire)")
    
    print("""
Le code main.py utilise déjà get_db_connection() qui supporte:
  ✓ SQLite (par défaut)
  ✓ PostgreSQL (si DB_TYPE=postgresql)

Aucun changement de code nécessaire!
Le switch est automatique selon la configuration .env
""")
    
    # ÉTAPE 8: Lancer l'application
    print_section("ÉTAPE 8: Lancer l'Application")
    
    print("""
cd c:\\ctba_project\\backend
pip install -r requirements.txt
python main.py

L'API démarrera avec PostgreSQL!
Vous devriez voir dans les logs:
  🐘 Connexion PostgreSQL: ctba_user@localhost:5432/ctba_platform
  ✅ Database initialized successfully
""")
    
    # ÉTAPE 9: Facultatif - Backup SQLite ancien
    print_section("ÉTAPE 9: Sauvegarder SQLite (Optionnel)")
    
    print("""
Garder une copie de sauvegarde de votre SQLite:

1. Copier ctba_platform.db vers ctba_platform.db.backup
2. Ou: Archiver en ZIP

C'est au cas où quelque chose irait mal et que vous voudriez revenir!
""")
    
    # ÉTAPE 10: Cloud Deployment
    print_section("ÉTAPE 10: Déploiement Cloud (Optionnel)")
    
    print("""
Maintenant que vous avez PostgreSQL, le cloud est facile!

AWS RDS:
  1. Créer RDS PostgreSQL instance
  2. Noter endpoint: ctba.xxxxx.eu-west-1.rds.amazonaws.com
  3. Mettre à jour .env:
     DATABASE_URL=postgresql://admin:password@ctba.xxxxx.rds.amazonaws.com:5432/ctba_platform
  4. Relancer l'app!

Google Cloud SQL:
  1. Créer PostgreSQL instance
  2. Récupérer connection string
  3. Même processus que RDS

Azure Database:
  1. Créer Azure Database for PostgreSQL
  2. Récupérer connection string
  3. Même processus
""")
    
    # Résumé
    print_section("RÉSUMÉ DES COMMANDES PRINCIPALES")
    
    print("""
┌─ Installation PostgreSQL ──────────────────────────────────────────┐
│  choco install postgresql --params '/Password:password' /Y         │
└────────────────────────────────────────────────────────────────────┘

┌─ Créer la base de données ────────────────────────────────────────┐
│  psql -U postgres -h localhost                                    │
│  CREATE DATABASE ctba_platform;                                   │
│  CREATE USER ctba_user WITH PASSWORD 'ctba_password123';          │
│  GRANT ALL PRIVILEGES ON DATABASE ctba_platform TO ctba_user;    │
└────────────────────────────────────────────────────────────────────┘

┌─ Export SQLite → SQL ─────────────────────────────────────────────┐
│  cd c:\\ctba_project\\backend                                      │
│  python migrate_sqlite_to_postgres.py                             │
└────────────────────────────────────────────────────────────────────┘

┌─ Import SQL → PostgreSQL ─────────────────────────────────────────┐
│  psql -U ctba_user -d ctba_platform -h localhost < migration_to_postgres.sql │
└────────────────────────────────────────────────────────────────────┘

┌─ Tester la connexion ─────────────────────────────────────────────┐
│  python test_postgres_connection.py                               │
└────────────────────────────────────────────────────────────────────┘

┌─ Lancer l'app avec PostgreSQL ────────────────────────────────────┐
│  python main.py                                                    │
└────────────────────────────────────────────────────────────────────┘
""")
    
    # Troubleshooting
    print_section("TROUBLESHOOTING")
    
    print("""
❌ "Connection refused"
   → PostgreSQL n'est pas lancé
   → Vérifier: psql -U postgres (si ça marche, PostgreSQL est ok)
   → Docker: docker start postgres-ctba

❌ "FATAL: password authentication failed"
   → Mauvais mot de passe
   → Vérifier le mot de passe dans .env
   → Réinitialiser: ALTER USER ctba_user WITH PASSWORD 'new_password';

❌ "database ctba_platform does not exist"
   → La base de données n'a pas été créée
   → Créer: psql -U postgres -c "CREATE DATABASE ctba_platform;"

❌ "psycopg2 not found"
   → Installer: pip install psycopg2-binary

❌ Les données ne sont pas importées
   → Vérifier le fichier migration_to_postgres.sql a bien été créé
   → Vérifier: psql -U ctba_user -d ctba_platform -c "SELECT COUNT(*) FROM cves;"
   → Devrait retourner le nombre de CVEs
""")
    
    # Notes finales
    print_section("NOTES FINALES")
    
    print("""
✅ PostgreSQL est production-ready
   - Scalabilité jusqu'à des millions de lignes
   - Backups automatisés facilement
   - Haute disponibilité (replicas, failover)
   - Prêt pour le cloud (AWS, GCP, Azure)

✅ Aucun changement de code nécessaire
   - get_db_connection() gère SQLite et PostgreSQL
   - Configurez simplement .env

✅ Gardez SQLite en backup
   - Au cas où vous voudriez revenir
   - ctba_platform.db.backup

✅ Après la migration:
   - Vous pouvez supprimer ctba_platform.db (ancien SQLite)
   - PostgreSQL est votre nouvelle source de vérité

✅ Prêt pour DevOps/Cloud?
   - PostgreSQL cloud (RDS, Cloud SQL, Azure Database)
   - Docker + Kubernetes
   - Consultez: CLOUD_DEVOPS_STRATEGY.md
""")
    
    print("\n" + "="*70)
    print("✨ Bonne chance avec votre migration!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
