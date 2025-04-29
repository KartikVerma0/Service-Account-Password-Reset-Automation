import json
import sys
from logger import logger
import os
from dotenv import load_dotenv
from M365PasswordExpiryChecker import M365PasswordExpiryChecker



def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Required settings
    tenant_id = os.getenv('TENANT_ID')
    client_id = os.getenv('CLIENT_ID')
    client_secret = os.getenv('CLIENT_SECRET')
    db_host = os.getenv('DB_HOST')
    db_port = os.getenv('DB_PORT')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_name = os.getenv('DB_NAME')
    
    # Optional settings with defaults
    expiry_days = int(os.getenv('EXPIRY_DAYS', '90'))
    warn_days = int(os.getenv('WARN_DAYS', '10'))
    force_change = os.getenv('FORCE_CHANGE', 'false').lower() == 'true'
    results_file = os.getenv('RESULTS_FILE')
    
    # Validate required settings
    if not all([tenant_id, client_id, client_secret, db_host, db_port, db_user, db_password, db_name]):
        logger.error("Missing required environment variables. Please check your .env file.")
        logger.error("Required variables: TENANT_ID, CLIENT_ID, CLIENT_SECRET, DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME")
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
    logger.info(f"Checking password expiry for accounts in Database: {db_name}...")
    results = checker.check_accounts_for_expiry()
    
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