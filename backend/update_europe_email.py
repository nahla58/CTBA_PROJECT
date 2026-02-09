import sqlite3

# Connexion à la base de données
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()

# Afficher l'email actuel
cursor.execute("SELECT name, recipients FROM regions WHERE name='EUROPE'")
result = cursor.fetchone()
print(f"Region EUROPE actuelle: {result}")

# Mettre à jour l'email
cursor.execute("UPDATE regions SET recipients='nahla.messaoudi@esprit.tn' WHERE name='EUROPE'")
affected = cursor.rowcount
conn.commit()
print(f"✓ Email mis a jour ({affected} ligne(s) affectee(s))")

# Vérifier la mise à jour
cursor.execute("SELECT name, recipients FROM regions WHERE name='EUROPE'")
result = cursor.fetchone()
print(f"Region EUROPE apres MAJ: {result}")

conn.close()
