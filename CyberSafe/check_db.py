import sqlite3
conn = sqlite3.connect('cybersafe.sqlite3')
cursor = conn.cursor()
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name")
for row in cursor.fetchall():
    print(row[0])
    print('---')
conn.close()