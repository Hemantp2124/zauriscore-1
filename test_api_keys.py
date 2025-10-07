import os
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_api_keys():
    """Test if API keys are loaded correctly from .env file."""
    # Load environment variables
    load_dotenv()
    
    # List of required API keys
    required_keys = [
        'ETHERSCAN_API_KEY',
        'POLYGONSCAN_API_KEY',
        'ARBISCAN_API_KEY',
        'OPTIMISM_ETHERSCAN_API_KEY'
    ]
    
    # Check each key
    all_keys_valid = True
    for key in required_keys:
        value = os.getenv(key)
        if value:
            # Mask the key for security (show first and last 4 characters)
            masked = f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "[too short]"
            logger.info(f"✅ {key}: {masked}")
            
            # Basic validation
            if not value.strip() or len(value) < 32:
                logger.warning(f"⚠️  {key} appears to be invalid (too short or empty)")
                all_keys_valid = False
        else:
            logger.error(f"❌ {key}: Not found in environment")
            all_keys_valid = False
    
    return all_keys_valid

if __name__ == "__main__":
    print("Testing API key configuration...\n")
    if test_api_keys():
        print("\n✅ All API keys are present and appear to be valid")
    else:
        print("\n❌ Some API keys are missing or invalid. Please check your .env file.")
        print("Make sure to restart your IDE/terminal after updating the .env file.")
