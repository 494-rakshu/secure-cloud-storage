import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# delete old logs table
cursor.execute("DROP TABLE IF EXISTS logs")

# create correct logs table
cursor.execute("""
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    time TEXT
)
""")

conn.commit()
conn.close()

print("Logs table fixed successfully")