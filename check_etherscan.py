"""Etherscan API client for fetching smart contract source code and metadata."""

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('etherscan_client.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class EtherscanConfig:
    """Configuration for Etherscan API client."""
    api_key: str
    base_url: str = "https://api.etherscan.io/v2/api"
    chain_id: int = 1  # Ethereum mainnet
    timeout: int = 15
    max_retries: int = 3
    backoff_factor: float = 0.5
    output_dir: Path = Path("contracts")

    def __post_init__(self) -> None:
        """Validate configuration on initialization."""
        if not self.api_key:
            raise ValueError("Etherscan API key is required")
        
        # Sanitize base URL to prevent SSRF attacks
        allowed_domains = ["api.etherscan.io", "api-goerli.etherscan.io", "api-sepolia.etherscan.io"]
        if not any(domain in self.base_url for domain in allowed_domains):
            raise ValueError(f"Invalid base URL: {self.base_url}. Must be an official Etherscan API domain.")
            
        self.output_dir.mkdir(parents=True, exist_ok=True)

class EtherscanClient:
    """Client for interacting with the Etherscan API."""
    
    def __init__(self, config: EtherscanConfig) -> None:
        """Initialize the Etherscan client.
        
        Args:
            config: Configuration for the Etherscan client
        """
        self.config = config
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

def validate_ethereum_address(address: str) -> bool:
    """Validate Ethereum address format.
    
    Args:
        address: Ethereum address to validate
        
    Returns:
        bool: True if address is valid, False otherwise
    """
    return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))

def get_contract_source_code(
    client: EtherscanClient,
    contract_address: str
) -> Dict[str, Any]:
    """Fetch contract source code from Etherscan API.
    
    Args:
        client: Configured Etherscan client
        contract_address: Ethereum contract address
        
    Returns:
        Dictionary containing contract source code and metadata
        
    Raises:
        ValueError: If the address is invalid or API returns an error
        requests.exceptions.RequestException: If there's a network error
    """
    if not validate_ethereum_address(contract_address):
        raise ValueError(f"Invalid Ethereum address: {contract_address}")

    # Sanitize input parameters
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": client.config.api_key
    }

    try:
        logger.info("Fetching contract data for address: %s", contract_address)
        
        # Use a timeout to prevent hanging requests
        response = client.session.get(
            client.config.base_url,
            params=params,
            timeout=client.config.timeout
        )
        response.raise_for_status()
        
        # Rate limiting protection
        if 'rate limit' in response.text.lower():
            logger.warning("Rate limit warning detected, sleeping for 1 second")
            time.sleep(1)
            
        data = response.json()
        
        if data.get('status') != '1':
            error_message = data.get('message', 'Unknown error')
            logger.error("API error: %s", error_message)
            raise ValueError(f"API error: {error_message}")
            
        result = data.get('result', [{}])[0]
        if not result:
            raise ValueError("No contract data found")
            
        return result
    
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logger.exception("Failed to fetch contract data")
        raise EtherscanError(f"Failed to fetch contract data: {str(e)}") from e

def save_contract_source(
    contract_data: Dict[str, Any],
    output_dir: Path,
    contract_address: str
) -> Path:
    """Save contract source code to a file.
    
    Args:
        contract_data: Contract data from Etherscan
        output_dir: Directory to save the contract
        contract_address: Contract address for the filename
        
    Returns:
        Path: Path to the saved contract file
    """
    source_code = contract_data.get('SourceCode', '')
    if not source_code:
        raise ValueError("No source code found in contract data")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{contract_address}.sol"
    
    try:
        output_file.write_text(source_code, encoding='utf-8')
        return output_file
    except IOError as e:
        raise IOError(f"Failed to save contract to {output_file}: {str(e)}") from e

class EtherscanError(Exception):
    """Base exception for Etherscan client errors."""
    pass

def display_contract_info(contract_data: Dict[str, Any]) -> None:
    """Display contract information in a formatted way."""
    logger.info("=" * 50)
    logger.info("Contract Information")
    logger.info("=" * 50)
    
    info_fields = [
        ("Name", contract_data.get('ContractName')),
        ("Compiler", contract_data.get('CompilerVersion')),
        ("Optimization", contract_data.get('OptimizationUsed')),
        ("License", contract_data.get('LicenseType')),
        ("ABI", "Yes" if contract_data.get('ABI') else "No"),
        ("Proxy", contract_data.get('Proxy', '0') == '1'),
        ("Implementation", contract_data.get('Implementation')),
        ("Source Code Length", f"{len(contract_data.get('SourceCode', ''))} bytes")
    ]
    
    for field, value in info_fields:
        if value is not None and value != '':
            logger.info(f"{field}: {value}")

def main() -> None:
    """Main function to fetch and display contract information."""
    try:
        # Load environment variables
        load_dotenv()
        
        # Initialize configuration
        config = EtherscanConfig(
            api_key=os.getenv('ETHERSCAN_API_KEY', ''),
            output_dir=Path("contracts")
        )
        
        # Initialize client
        client = EtherscanClient(config)
        
        # Parse command line arguments
        if len(sys.argv) != 2:
            logger.error("Usage: python check_etherscan.py <contract_address>")
            sys.exit(1)
            
        contract_address = sys.argv[1].strip()
        
        # Fetch contract data
        contract_data = get_contract_source_code(client, contract_address)
        
        # Display contract information
        display_contract_info(contract_data)
        
        # Save source code if available
        if contract_data.get('SourceCode'):
            output_file = save_contract_source(
                contract_data,
                config.output_dir,
                contract_address
            )
            logger.info("Source code saved to: %s", output_file)
            
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(130)
    except EtherscanError as e:
        logger.error("Etherscan error: %s", str(e))
        sys.exit(1)
    except Exception as e:
        logger.exception("An unexpected error occurred")
        sys.exit(1)

if __name__ == "__main__":
    main()
