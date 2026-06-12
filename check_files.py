import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM files")
data = cursor.fetchall()

conn.close()

print(data)