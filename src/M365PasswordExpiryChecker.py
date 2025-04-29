from utils.logger import logger
import requests
import sys
import os
from cryptography.fernet import Fernet
import mysql.connector
from datetime import datetime, timedelta

class M365PasswordExpiryChecker:
    def __init__(self, tenant_id, client_id, client_secret, expiry_days, warn_days):
        """
        Initialize the Microsoft 365 Password Expiry Checker and Resetter.
        
        Args:
            tenant_id (str): Your Microsoft 365 tenant ID
            client_id (str): Application (client) ID from Azure AD app registration
            client_secret (str): Client secret from Azure AD app registration
            expiry_days (int): Number of days after which passwords expire
            warn_days (int): Number of days before expiry to reset password
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        self.expiry_days = expiry_days
        self.warn_days = warn_days
        self.crypto_key = self._get_or_create_crypto_key()
        self.cipher = Fernet(self.crypto_key)
        self._init_db()
    
    def _get_or_create_crypto_key(self):
        """Get or create a key for password encryption"""
        key_file = os.getenv("CRYPTO_KEY_FILE", ".crypto.key")
        
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
    
    def encrypt_password(self, password):
        """Encrypt a password"""
        return self.cipher.encrypt(password.encode()).decode()
    
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
    
    def authenticate(self):
        """Get OAuth access token for Microsoft Graph API"""
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        try:
            response = requests.post(self.token_endpoint, data=payload)
            response.raise_for_status()
            self.access_token = response.json().get('access_token')
            logger.info("Authentication successful")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {str(e)}")
            if hasattr(e, 'response') and e.response and e.response.text:
                logger.error(f"Error details: {e.response.text}")
            return False
    
    def get_headers(self):
        """Returns the headers needed for API requests"""
        return {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
    
    
    def get_user(self, identifier):
        """
        Get user by email or user principal name
        
        Args:
            identifier (str): Email address or UPN of the user
        
        Returns:
            dict: User object if found, None otherwise
        """
        try:
            response = requests.get(
                f"{self.graph_endpoint}/users/{identifier}",
                headers=self.get_headers()
            )
            
            if response.status_code == 200:
                logger.info(f"Found user: {identifier}")
                return response.json()
            else:
                logger.error(f"User not found: {identifier}. Status code: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting user: {str(e)}")
            return None
    
    
    
    def check_accounts_for_expiry(self):
        """
        Check user accounts in the MySQL DB for password expiry and reset if needed.

        Returns:
            dict: Results of password resets
        """
        today = datetime.now().date()
        expiry_threshold = today + timedelta(days=self.warn_days)
        results = {}

        try:
            conn = self.connect_db()
            cursor = conn.cursor(dictionary=True)

            # Fetch all accounts
            cursor.execute("SELECT user, last_password_change, password_encrypted FROM accounts")
            accounts = cursor.fetchall()

            for account in accounts:
                user = account["user"]
                last_change = account["last_password_change"]

                if not last_change:
                    logger.warning(f"No password change date for user {user}. Skipping.")
                    continue

                expiry_date = last_change + timedelta(days=self.expiry_days)

                if expiry_date <= expiry_threshold:
                    logger.info(f"User {user} password expires on {expiry_date} (threshold: {expiry_threshold})")
                    
                    # Reset password
                    success, new_password = self.reset_password(user, force_change=self.force_change)

                    if success:
                        # Update password change date in DB
                        cursor.execute(
                            "UPDATE accounts SET last_password_change = %s WHERE user = %s",
                            (today.strftime('%Y-%m-%d'), user)
                        )

                        results[user] = {
                            "success": True,
                            "new_password": new_password,
                            "old_expiry": expiry_date,
                            "new_expiry": today + timedelta(days=self.expiry_days)
                        }
                    else:
                        results[user] = {
                            "success": False,
                            "error": "Password reset failed",
                            "expiry": expiry_date
                        }
                else:
                    days_left = (expiry_date - today).days
                    logger.info(f"User {user} password is valid for {days_left} more days")

            conn.commit()
            cursor.close()
            conn.close()
        except mysql.connector.Error as err:
            logger.error(f"MySQL Error: {err}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")

        return results