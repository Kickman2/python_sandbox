import sqlite3
import threading
from datetime import datetime

# Create a thread-local storage for database connections
local = threading.local()


def get_db_connection():
    # Get a database connection for the current thread
    if not hasattr(local, "conn"):
        local.conn = sqlite3.connect('csr_database.db')
    return local.conn

def create_table():
    # Create a table to store CSR and key information
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            uid TEXT,
            common_name TEXT,
            env TEXT,
            csr_data TEXT,
            key_data TEXT,
            cnf_data TEXT,
            generated_date DATETIME
        )
    ''')
    conn.commit()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY,
            common_name TEXT,
            token TEXT,
            data TEXT,
            password TEXT,
            expiration_time INTEGER,
            generated_date DATETIME
        )
    ''')
    conn.commit()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT,
            generated_date DATETIME
        )
    ''')
    conn.commit()

def insert_certificate(uid,common_name, env, csr_data, key_data, cnf_data):
    # Insert a new certificate into the database
    conn = get_db_connection()
    cursor = conn.cursor()
    generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO certificates (uid, common_name, env, csr_data, key_data, cnf_data, generated_date) VALUES (?, ?, ?, ?, ?, ?, ?)', (uid, common_name, env, csr_data, key_data, cnf_data, generated_date))
    conn.commit()

def insert_tokens(common_name, token, data, password, expiration_time):
    # Insert a new certificate into the database
    conn = get_db_connection()
    cursor = conn.cursor()
    generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO tokens (common_name, token, data, password, expiration_time,generated_date) VALUES (?, ?, ?, ?, ?, ?)', (common_name, token, data, password, expiration_time, generated_date))
    conn.commit()

def insert_user(username, password):
    # Insert a new certificate into the database
    conn = get_db_connection()
    cursor = conn.cursor()
    generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO admin_users (username, password, generated_date) VALUES (?, ?, ?)', (username, password, generated_date))
    conn.commit()

def fetch_all_certificates():
    # Retrieve all certificates from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT common_name, generated_date FROM certificates')
    return cursor.fetchall()

def close_database():
    # Close the database connection for the current thread
    conn = get_db_connection()
    conn.close()
    del local.conn  # Remove the connection from thread-local storage

def get_certificates(page_number, page_size):
    # Retrieve a specific page of certificates from the database
    offset = (page_number - 1) * page_size
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, uid, common_name, env, generated_date FROM certificates ORDER BY id DESC LIMIT ? OFFSET ?', (page_size, offset))
    return cursor.fetchall()

def get_users(page_number, page_size):
    # Retrieve a specific page of certificates from the database
    offset = (page_number - 1) * page_size
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, generated_date FROM admin_users ORDER BY id DESC LIMIT ? OFFSET ?', (page_size, offset))
    return cursor.fetchall()

def get_total_certificate_count():
    # Count the total number of certificates in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(id) FROM certificates')
    return cursor.fetchone()[0]

def get_total_users_count():
    # Count the total number of certificates in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(id) FROM admin_users')
    return cursor.fetchone()[0]

# def execute_query(connection, query, params=None):
#     cursor = connection.cursor()
#     if params:
#         cursor.execute(query, params)
#     else:
#         cursor.execute(query)
#     return cursor.fetchall()

# def search_records(connection, search_term):
#     query = f"SELECT * FROM your_table_name WHERE column_name LIKE ?"
#     params = (f'%{search_term}%',)
#     results = execute_query(connection, query, params)
#     return results

# def sort_by_date(connection):
#     query = f"SELECT * FROM your_table_name ORDER BY date_column_name"
#     results = execute_query(connection, query)
#     return results

def delete_certificate_by_id(id):
    # Retrieve a specific certificates from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM certificates WHERE id = ?',(str(id)))
    return conn.commit()

def delete_user_by_id(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM admin_users WHERE id = ?',(str(id)))
    return conn.commit()

def get_certificate_by_id(id):
    # Retrieve a specific certificates from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT common_name, env, csr_data, key_data, cnf_data, generated_date FROM certificates WHERE id = ?',(str(id)))
    return cursor.fetchone()

def get_token_data(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT common_name, token, data, expiration_time, generated_date FROM tokens WHERE token = ?',[token])
    return cursor.fetchone()

def get_guest_otp(otp):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id,expiration_time FROM tokens WHERE password = ?',[otp])
    return cursor.fetchone()

def get_user_pass(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM admin_users WHERE username = ?',[username])
    return cursor.fetchone()

create_table()