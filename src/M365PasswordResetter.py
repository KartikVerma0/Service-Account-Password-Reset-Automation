from utils.logger import logger
import requests
import json
import random
import string
from datetime import datetime

class M365PasswordResetter:
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

    def generate_password(self, length=16):
        """Generate a strong random password"""
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        # Ensure at least one character from each category
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill the rest of the password length with random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend(random.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password characters
        random.shuffle(password)
        return ''.join(password)
    
    def store_password(self, user_id, password):
        """
        Store encrypted password in database
        
        Args:
            user_id (str): User ID or principal name
            password (str): Plain-text password to encrypt and store
        """
        try:
            encrypted_password = self.encrypt_password(password)
            conn = self.connect_db()
            cursor = conn.cursor()
            
            # Check if user exists in database
            cursor.execute("SELECT COUNT(*) FROM accounts WHERE user = %s", (user_id,))
            count = cursor.fetchone()[0]
            
            if count > 0:
                # Update existing record
                cursor.execute(
                    "UPDATE accounts SET password_encrypted = %s WHERE user = %s",
                    (encrypted_password, user_id)
                )
            else:
                # Insert new record
                today = datetime.now().date().strftime('%Y-%m-%d')
                cursor.execute(
                    "INSERT INTO accounts (user, last_password_change, password_encrypted) VALUES (%s, %s, %s)",
                    (user_id, today, encrypted_password)
                )
            
            conn.commit()
            cursor.close()
            conn.close()
            logger.info(f"Encrypted password stored for user: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Error storing password for user {user_id}: {str(e)}")
            return False

    def reset_password(self, user_id, temp_password=None, force_change=True):
        """
        Reset a user's password
        
        Args:
            user_id (str): User ID or principal name
            temp_password (str, optional): Password to set. If None, generates random password
            force_change (bool): Whether to force password change on next login
        
        Returns:
            tuple: (success (bool), new_password (str))
        """
        if not temp_password:
            temp_password = self.generate_password()
        
        payload = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": force_change,
                "password": temp_password
            }
        }
        
        try:
            response = requests.patch(
                f"{self.graph_endpoint}/users/{user_id}",
                headers=self.get_headers(),
                data=json.dumps(payload)
            )
            
            if response.status_code in (200, 204):
                logger.info(f"Password reset successful for user: {user_id}")
                # Store encrypted password in database
                self.store_password(user_id, temp_password)
                return True, temp_password
            else:
                logger.error(f"Password reset failed for user: {user_id}. Status code: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False, None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error resetting password: {str(e)}")
            return False, None