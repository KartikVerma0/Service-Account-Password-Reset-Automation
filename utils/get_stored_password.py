from pathlib import Path
import sys
import os
from dotenv import load_dotenv
import mysql.connector
from cryptography.fernet import Fernet
from logger import logger


class GetStoredPassword:
    def __init__(self):
        self.crypto_key = self._get_or_create_crypto_key()
        self.cipher = Fernet(self.crypto_key)

    def _get_or_create_crypto_key(self):
        """Get or create a key for password encryption"""
        key_file = Path(os.getenv("CRYPTO_KEY_FILE", ".crypto.key")).resolve()
        
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            # Generate a new key
            key = Fernet.generate_key()
            # Save it to file with restricted permissions
            with open(key_file, "wb") as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Only owner can read/write
            logger.info(f"Created new encryption key in {key_file}")
            return key

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

    def get_stored_password(self, user_id):
            """
            Retrieve and decrypt stored password for user
            
            Args:
                user_id (str): User ID or principal name
                
            Returns:
                str: Decrypted password if available, None otherwise
            """
            try:
                conn = self.connect_db()
                cursor = conn.cursor(dictionary=True)
                
                cursor.execute("SELECT password_encrypted FROM accounts WHERE user = %s", (user_id,))
                result = cursor.fetchone()
                
                cursor.close()
                conn.close()
                
                if result and result.get('password_encrypted'):
                    return self.decrypt_password(result['password_encrypted'])
                return None
            except Exception as e:
                logger.error(f"Error retrieving password for user {user_id}: {str(e)}")
                return None
            
    def decrypt_password(self, encrypted):
        """Decrypt a password"""
        return self.cipher.decrypt(encrypted.encode()).decode()
    def export_all_passwords(self, output_file):
        """
        Retrieve all passwords from the database, decrypt them, and store them in an output file.
        
        Args:
            output_file (str): Path to the output file where passwords will be saved.
        """
        try:
            conn = self.connect_db()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT user, password_encrypted FROM accounts")
            results = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            with open(output_file, "w") as f:
                for row in results:
                    user = row['user']
                    encrypted_password = row['password_encrypted']
                    if encrypted_password:
                        decrypted_password = self.decrypt_password(encrypted_password)
                        f.write(f"{user}: {decrypted_password}\n")
            
            logger.info(f"All passwords have been exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting passwords: {str(e)}")
            
def main():
    load_dotenv()
    # username = input("Enter username: ")
    # logger.info(GetStoredPassword().get_stored_password(username))
    
    # Uncomment the following line to export all passwords to a file
    output_file = Path(os.getenv("PWD_OUTPUT_FILE_PATH","output/passwords_output.txt")).resolve()
    GetStoredPassword().export_all_passwords(output_file)
            
if __name__ == "__main__":
    main()