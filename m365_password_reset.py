import requests
import json
import random
import string
import sys
import logging
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

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
                return True, temp_password
            else:
                logger.error(f"Password reset failed for user: {user_id}. Status code: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False, None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error resetting password: {str(e)}")
            return False, None
    
    def check_accounts_for_expiry(self, accounts_file, output_file):
        """
        Check accounts in the file for password expiry and reset if needed
        
        Args:
            accounts_file (str): Path to file containing account data
            output_file (str): Path to file where updated account data will be saved
        
        Returns:
            dict: Results of password resets
        """
        today = datetime.now().date()
        expiry_threshold = today + timedelta(days=self.warn_days)
        results = {}
        
        updated_accounts = []
        
        try:
            # Read accounts file
            with open(accounts_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        updated_accounts.append(line)
                        continue
                    
                    parts = line.split(',')
                    if len(parts) < 2:
                        logger.warning(f"Invalid line in accounts file: {line}")
                        updated_accounts.append(line)
                        continue
                    
                    user = parts[0].strip()
                    try:
                        last_password_change = datetime.strptime(parts[1].strip(), '%Y-%m-%d').date()
                    except ValueError:
                        logger.error(f"Invalid date format for user {user}: {parts[1]}")
                        updated_accounts.append(line)
                        continue
                    
                    # Calculate password expiry date
                    expiry_date = last_password_change + timedelta(days=self.expiry_days)
                    
                    # Check if password is about to expire
                    if expiry_date <= expiry_threshold:
                        logger.info(f"User {user} password expires on {expiry_date} (threshold: {expiry_threshold})")
                        
                        # Reset password
                        success, new_password = self.reset_password(user, force_change=self.force_change)
                        
                        if success:
                            # Update the last password change date
                            results[user] = {
                                "success": True, 
                                "new_password": new_password,
                                "old_expiry": expiry_date,
                                "new_expiry": today + timedelta(days=self.expiry_days)
                            }
                            # Update the line with new date
                            updated_accounts.append(f"{user},{today.strftime('%Y-%m-%d')}")
                        else:
                            results[user] = {
                                "success": False, 
                                "error": "Password reset failed",
                                "expiry": expiry_date
                            }
                            updated_accounts.append(line)
                    else:
                        # No need to update, password not expiring soon
                        days_to_expiry = (expiry_date - today).days
                        logger.info(f"User {user} password is valid for {days_to_expiry} more days")
                        updated_accounts.append(line)
                
            # Write updated accounts back to file
            with open(output_file, 'w') as f:
                for line in updated_accounts:
                    f.write(f"{line}\n")
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing accounts file: {str(e)}")
            return {}

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Required settings
    tenant_id = os.getenv('TENANT_ID')
    client_id = os.getenv('CLIENT_ID')
    client_secret = os.getenv('CLIENT_SECRET')
    accounts_file = os.getenv('ACCOUNTS_FILE')
    
    # Optional settings with defaults
    output_file = os.getenv('OUTPUT_FILE', accounts_file)  # Default to same as accounts file
    expiry_days = int(os.getenv('EXPIRY_DAYS', '1'))
    warn_days = int(os.getenv('WARN_DAYS', '1'))
    force_change = os.getenv('FORCE_CHANGE', 'false').lower() == 'true'
    results_file = os.getenv('RESULTS_FILE')
    
    # Validate required settings
    if not all([tenant_id, client_id, client_secret, accounts_file]):
        logger.error("Missing required environment variables. Please check your .env file.")
        logger.error("Required variables: TENANT_ID, CLIENT_ID, CLIENT_SECRET, ACCOUNTS_FILE")
        sys.exit(1)
    
    # Initialize password checker
    checker = M365PasswordExpiryChecker(
        tenant_id, 
        client_id, 
        client_secret,
        expiry_days,
        warn_days
    )
    
    # Set force change attribute
    checker.force_change = force_change
    
    # Authenticate
    if not checker.authenticate():
        logger.error("Authentication failed. Check your credentials.")
        sys.exit(1)
    
    # Check accounts and reset passwords as needed
    logger.info(f"Checking password expiry for accounts in {accounts_file}")
    results = checker.check_accounts_for_expiry(accounts_file, output_file)
    
    # Output results
    reset_count = sum(1 for r in results.values() if r.get("success"))
    if reset_count > 0:
        logger.info(f"Password reset completed. {reset_count} passwords updated.")
        
        # Print passwords to console and log file
        password_summary = "\nPassword Reset Results:\n-----------------------\n"
        for user, result in results.items():
            if result.get("success"):
                password_summary += f"{user}: {result.get('new_password')}\n"
                password_summary += f"  Old expiry: {result.get('old_expiry')}\n"
                password_summary += f"  New expiry: {result.get('new_expiry')}\n"
            else:
                password_summary += f"{user}: FAILED - {result.get('error')}\n"
        
        logger.info(password_summary)
    else:
        logger.info("No passwords needed to be reset.")
    
    # Save results to file if requested
    if results_file and results:
        try:
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Results written to {results_file}")
        except Exception as e:
            logger.error(f"Error writing results file: {str(e)}")

if __name__ == "__main__":
    main()