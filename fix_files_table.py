import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# delete old table
cursor.execute("DROP TABLE IF EXISTS files")

# create correct new table
cursor.execute("""
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    stored_name TEXT,
    username TEXT
)
""")

conn.commit()
conn.close()

print("Files table fixed successfully")