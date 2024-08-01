import sqlite3

conn = sqlite3.connect('authorized_devices.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY,
        mac TEXT UNIQUE NOT NULL,
        device_id TEXT NOT NULL,
        expected_network TEXT NOT NULL,
        authorized INTEGER NOT NULL
    )
''')
conn.commit()
conn.close()