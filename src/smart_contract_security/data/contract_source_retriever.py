import os
import json
import logging
import requests
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv

# Configure logging
logger = logging.getLogger(__name__)

# Project root is three levels up from this file
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Load environment variables
load_dotenv(PROJECT_ROOT / '.env')

# Configure paths
CACHE_DIR = PROJECT_ROOT / 'datasets' / 'contract_cache'
os.makedirs(CACHE_DIR, exist_ok=True)

class ContractSourceRetriever:
    """Unified contract source code retriever with caching capabilities"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize contract source retriever
        
        Args:
            api_key (Optional[str]): Etherscan API key. If not provided, 
                                   will use environment variable.
        """
        self.api_key = api_key or os.getenv('ETHERSCAN_API_KEY')
        if not self.api_key:
            raise ValueError("Etherscan API key is required")
            
        self.base_url = "https://api.etherscan.io/api"
        
        # Use global cache directory
        self.cache_dir = CACHE_DIR
    
    def _get_cache_path(self, contract_address: str) -> str:
        """Generate cache file path for a contract"""
        cache_filename = hashlib.md5(contract_address.encode()).hexdigest() + '.json'
        return os.path.join(self.cache_dir, cache_filename)
    
    def _save_to_cache(self, contract_address: str, data: Dict[str, Any]) -> None:
        """Save contract data to cache"""
        try:
            cache_path = self._get_cache_path(contract_address)
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Cached source code for {contract_address}")
        except Exception as e:
            logger.warning(f"Failed to cache source code: {e}")
    
    def _load_from_cache(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """Load contract data from cache if available"""
        try:
            cache_path = self._get_cache_path(contract_address)
            if os.path.exists(cache_path):
                with open(cache_path, 'r') as f:
                    data = json.load(f)
                logger.info(f"Loaded source code from cache for {contract_address}")
                return data
        except Exception as e:
            logger.warning(f"Failed to load cached source code: {e}")
        return None
    
    def get_contract_source(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve contract source code with caching
        
        Args:
            contract_address (str): Ethereum contract address
            
        Returns:
            Optional[Dict[str, Any]]: Contract source code and metadata
        """
        # Validate address format
        if not contract_address.startswith('0x') or len(contract_address) != 42:
            raise ValueError("Invalid Ethereum contract address format")
        
        # Try cache first
        cached_data = self._load_from_cache(contract_address)
        if cached_data:
            return cached_data
        
        # Fetch from Etherscan if not in cache
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": contract_address,
            "apikey": self.api_key
        }
        
        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if data['status'] == '1' and data['message'] == 'OK':
                result = data['result'][0]
                
                # Cache the successful response
                self._save_to_cache(contract_address, result)
                return result
            else:
                logger.error(f"Etherscan API error: {data.get('message', 'Unknown error')}")
                return None
                
        except Exception as e:
            logger.error(f"Error fetching contract source: {str(e)}")
            return None

def main():
    """Example usage"""
    try:
        retriever = ContractSourceRetriever()
        contract_address = "0x17150840c6002D60207dB95AB093Bd6998024a50"
        result = retriever.get_contract_source(contract_address)
        
        if result:
            print(f"Successfully retrieved contract source for {contract_address}")
            print(f"Contract name: {result.get('ContractName', 'Unknown')}")
            print(f"Compiler version: {result.get('CompilerVersion', 'Unknown')}")
        else:
            print(f"Failed to retrieve contract source for {contract_address}")
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
