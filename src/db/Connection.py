import sys
from utils.logger import logger
import mysql.connector
import os

class Connection:
    def _init_db(self):
        conn = self.connect_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                user VARCHAR(255) PRIMARY KEY,
                last_password_change DATE,
                password_encrypted TEXT
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()
    
    def connect_db(self):
        try:
            return mysql.connector.connect(
                host=os.getenv("DB_HOST"),
                port=int(os.getenv("DB_PORT", 3306)),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                database=os.getenv("DB_NAME")
            )
        except mysql.connector.Error as err:
            logger.error(f"Error connecting to database: {err}")
            sys.exit(1)