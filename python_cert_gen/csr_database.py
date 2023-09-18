import sqlite3
from datetime import datetime

# Initialize the database or connect to an existing one
conn = sqlite3.connect('csr_database.db')
cursor = conn.cursor()

# Create a table to store CSR and key information
cursor.execute('''
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY,
        common_name TEXT,
        env TEXT,
        csr_data TEXT,
        key_data TEXT,
        generated_date DATETIME
    )
''')
conn.commit()

def insert_certificate(common_name, env, csr_data, key_data):
    # Insert a new certificate into the database
    generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO certificates (common_name, env, csr_data, key_data, generated_date) VALUES (?, ?, ?, ?, ?)', (common_name, env, csr_data, key_data, generated_date))
    conn.commit()

def fetch_all_certificates():
    # Retrieve all certificates from the database
    cursor.execute('SELECT common_name, generated_date FROM certificates')
    return cursor.fetchall()

def close_database():
    # Close the database connection
    conn.close()
    
def get_certificates(page_number, page_size):
    # Retrieve a specific page of certificates from the database
    offset = (page_number - 1) * page_size
    cursor.execute('SELECT common_name, env, csr_data, key_data, generated_date FROM certificates ORDER BY id DESC LIMIT ? OFFSET ?', (page_size, offset))
    return cursor.fetchall()

def get_total_certificate_count():
    # Count the total number of certificates in the database
    cursor.execute('SELECT COUNT(id) FROM certificates')
    return cursor.fetchone()[0]