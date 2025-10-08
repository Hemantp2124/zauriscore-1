"""HTTP client with retry and timeout support."""
import hashlib
import ipaddress
import json
import re
import socket
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional, Union, Tuple, Callable, List, Set

import requests
from requests.adapters import HTTPAdapter, Retry

from ..config import config
from ..utils.logger import setup_logger

# Security constants
DEFAULT_TIMEOUT = 30
DEFAULT_USER_AGENT = 'ZauriScore'
ALLOWED_SCHEMES = {'http', 'https'}
BLACKLISTED_IPS = {
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32'
}

class SecurityError(Exception):
    """Base class for security-related errors."""
    pass

class SSRFError(SecurityError):
    """Raised when a potential SSRF attack is detected."""
    pass

class APIClient:
    """HTTP client with retry and timeout support."""
    
    def __init__(
        self,
        base_url: str = "",
        api_key: Optional[str] = None,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        timeout: int = DEFAULT_TIMEOUT,
        cache_dir: Optional[Union[str, Path]] = None,
        allowed_domains: Optional[Set[str]] = None,
        allowed_ips: Optional[Set[str]] = None
    ):
        """Initialize the API client with security controls.
        
        Args:
            base_url: Base URL for all requests
            api_key: API key for authentication
            max_retries: Maximum number of retries for failed requests (0-5)
            backoff_factor: Backoff factor for retries (0.1-5.0)
            timeout: Request timeout in seconds (5-300)
            cache_dir: Directory to cache responses (if None, caching is disabled)
            allowed_domains: Set of allowed domains (if None, domain validation is skipped)
            allowed_ips: Set of allowed IPs/CIDRs (in addition to default blacklist)
            
        Raises:
            ValueError: If input parameters are invalid
        """
        # Validate inputs
        if not isinstance(max_retries, int) or not 0 <= max_retries <= 5:
            raise ValueError("max_retries must be between 0 and 5")
        if not isinstance(backoff_factor, (int, float)) or not 0.1 <= backoff_factor <= 5.0:
            raise ValueError("backoff_factor must be between 0.1 and 5.0")
        if not isinstance(timeout, (int, float)) or not 5 <= timeout <= 300:
            raise ValueError("timeout must be between 5 and 300 seconds")
            
        self.base_url = base_url.rstrip('/') if base_url else ""
        self.api_key = api_key
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.allowed_domains = set(allowed_domains) if allowed_domains else None
        self.allowed_ips = self._parse_allowed_ips(allowed_ips) if allowed_ips else set()
        self.logger = setup_logger("api.client")
        
        # Set up session with retry strategy
        self.session = self._create_session(max_retries, backoff_factor)
    
    def _create_session(self, max_retries: int, backoff_factor: float) -> requests.Session:
        """Create a requests session with retry strategy."""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )
        
        # Mount the retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set secure default headers
        session.headers.update({
            'User-Agent': DEFAULT_USER_AGENT,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        })
        
        # Add API key if provided
        if self.api_key:
            session.headers['Authorization'] = f'Bearer {self.api_key}'
        
        return session
    
    def _parse_allowed_ips(self, ip_ranges: Set[str]) -> Set[ipaddress.IPv4Network]:
        """Parse and validate allowed IP ranges."""
        allowed = set()
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                if network.is_private or network.is_loopback or network.is_link_local:
                    self.logger.warning(f"Potentially unsafe IP range allowed: {ip_range}")
                allowed.add(network)
            except ValueError as e:
                self.logger.warning(f"Invalid IP range {ip_range}: {e}")
        return allowed
        
    def _is_ip_allowed(self, ip: str) -> bool:
        """Check if an IP is allowed based on the whitelist and blacklist."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            
            # Check against blacklist first
            for network in BLACKLISTED_IPS:
                if ip_addr in ipaddress.ip_network(network, strict=False):
                    return False
                    
            # Check against whitelist if specified
            if self.allowed_ips:
                for network in self.allowed_ips:
                    if ip_addr in network:
                        return True
                return False
                
            return True
        except ValueError:
            return False
            
    def _validate_url(self, url: str) -> None:
        """Validate a URL to prevent SSRF attacks."""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ALLOWED_SCHEMES:
                raise SSRFError(f"URL scheme '{parsed.scheme}' is not allowed")
                
            # Check for IP addresses in hostname
            hostname = parsed.hostname or ""
            try:
                ip_addr = socket.gethostbyname(hostname)
                if not self._is_ip_allowed(ip_addr):
                    raise SSRFError(f"Access to IP {ip_addr} is not allowed")
            except socket.gaierror:
                # Could not resolve hostname
                pass
                
            # Check domain whitelist if specified
            if self.allowed_domains and hostname not in self.allowed_domains:
                # Check subdomains
                if not any(hostname.endswith(f".{domain}") for domain in self.allowed_domains):
                    raise SSRFError(f"Access to domain '{hostname}' is not allowed")
                    
            # Check for sensitive URL patterns
            sensitive_patterns = [
                r'@',  # Username in URL
                r'//',  # Multiple slashes
                r':\d+',  # Port specification
                r'[\x00-\x1f\x7f-\xff]'  # Control characters
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, url):
                    raise SSRFError(f"URL contains potentially dangerous pattern: {pattern}")
                    
        except ValueError as e:
            raise SSRFError(f"Invalid URL: {e}") from e
            
    def _get_cache_path(self, url: str, params: Optional[Dict] = None) -> Optional[Path]:
        """Get the cache path for a request.
        
        Args:
            url: The URL being requested
            params: Optional query parameters
            
        Returns:
            Path to the cache file or None if caching is disabled
            
        Raises:
            ValueError: If the URL is invalid
        """
        if not self.cache_dir:
            return None
            
        # Create a secure cache key
        cache_key = f"{url}_{json.dumps(params, sort_keys=True) if params else ''}"
        # Use SHA-256 instead of MD5 for better security
        cache_key = hashlib.sha256(cache_key.encode()).hexdigest()
        
        # Sanitize the filename to prevent directory traversal
        safe_key = "".join(c for c in cache_key if c.isalnum() or c in '._-')
        return self.cache_dir / f"{safe_key}.json"
    
    def _get_cached_response(self, cache_path: Path) -> Optional[Dict]:
        """Get a cached response if it exists and is fresh."""
        if not cache_path.exists():
            return None
            
        # Check if cache is fresh (24 hours)
        cache_age = time.time() - cache_path.stat().st_mtime
        if cache_age > 24 * 3600:  # 24 hours
            return None
            
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.warning(f"Failed to read cache file {cache_path}: {e}")
            return None
    
    def _cache_response(self, cache_path: Path, data: Dict) -> None:
        """Cache a response."""
        if not self.cache_dir:
            return
            
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except (IOError, TypeError) as e:
            self.logger.warning(f"Failed to cache response to {cache_path}: {e}")
    
    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        use_cache: bool = True,
        validate_url: bool = True
    ) -> Dict:
        """Send an HTTP request with security controls.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (will be appended to base_url)
            params: Query parameters
            json_data: JSON request body
            headers: Additional headers
            use_cache: Whether to use cached responses if available
            validate_url: Whether to validate the URL for SSRF protection
            
        Returns:
            Parsed JSON response as a dictionary
            
        Raises:
            SSRFError: If URL validation fails
            requests.exceptions.RequestException: If the request fails
            ValueError: If the request is invalid
        """
        if method.upper() not in {'GET', 'POST', 'PUT', 'DELETE'}:
            raise ValueError(f"Unsupported HTTP method: {method}")
            
        # Construct and validate URL
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        if validate_url:
            self._validate_url(url)
            
        # Sanitize headers
        headers = self._sanitize_headers(headers or {})
        
        # Get cache path (after validation)
        cache_path = None
        if use_cache:
            cache_path = self._get_cache_path(url, params)
            if cache_path:
                cached = self._get_cached_response(cache_path)
                if cached is not None:
                    self.logger.debug(f"Using cached response for {url}")
                    return cached
        
        # Prepare request
        req_headers = self.session.headers.copy()
        req_headers.update(headers)
        
        self.logger.debug("Sending %s request to %s", method, url)
        
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                json=json_data,
                headers=req_headers,
                timeout=self.timeout,
                allow_redirects=False  # Handle redirects manually for security
            )
            
            # Handle redirects securely
            if 300 <= response.status_code < 400:
                if 'Location' in response.headers:
                    redirect_url = response.headers['Location']
                    if validate_url:
                        self._validate_url(redirect_url)
                    return self.request(
                        method=method,
                        endpoint=redirect_url,
                        params=params,
                        json_data=json_data,
                        headers=headers,
                        use_cache=use_cache,
                        validate_url=validate_url  # Don't re-validate if we already did
                    )
                
                raise requests.exceptions.TooManyRedirects(
                    f"Redirected but no Location header in response"
                )
            
            # Raise an exception for 4XX/5XX responses
            response.raise_for_status()
            
            # Parse JSON response
            try:
                result = response.json()
            except ValueError:
                result = {'data': response.text}
            
            # Cache the response if successful
            if cache_path and response.status_code == 200:
                self._cache_response(cache_path, result)
            
            return result
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize request headers to prevent header injection."""
        sanitized = {}
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                self.logger.warning("Skipping non-string header: %s", key)
                continue
                
            # Remove newlines and other control characters
            clean_key = re.sub(r'[\r\n]', '', key).strip()
            clean_value = re.sub(r'[\r\n]', '', value).strip()
            
            # Skip sensitive headers that should be set internally
            if clean_key.lower() in {'host', 'user-agent', 'authorization'}:
                self.logger.warning("Skipping restricted header: %s", clean_key)
                continue
                
            sanitized[clean_key] = clean_value
            
        return sanitized
    
    def get(self, endpoint: str, params: Optional[Dict] = None, **kwargs) -> Dict:
        """Send a GET request.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            **kwargs: Additional arguments to pass to request()
            
        Returns:
            Response data as a dictionary
            
        Raises:
            SSRFError: If URL validation fails
            requests.exceptions.RequestException: If the request fails
        """
        return self.request('GET', endpoint, params=params, **kwargs)
    
    def post(self, endpoint: str, json_data: Optional[Dict] = None, **kwargs) -> Dict:
        """Send a POST request.
        
        Args:
            endpoint: API endpoint
            json_data: JSON request body
            **kwargs: Additional arguments to pass to request()
            
        Returns:
            Response data as a dictionary
            
        Raises:
            SSRFError: If URL validation fails
            requests.exceptions.RequestException: If the request fails
        """
        return self.request('POST', endpoint, json_data=json_data, **kwargs)
    
    def put(self, endpoint: str, json_data: Optional[Dict] = None, **kwargs) -> Dict:
        """Send a PUT request.
        
        Args:
            endpoint: API endpoint
            json_data: JSON request body
            **kwargs: Additional arguments to pass to request()
            
        Returns:
            Response data as a dictionary
            
        Raises:
            SSRFError: If URL validation fails
            requests.exceptions.RequestException: If the request fails
        """
        return self.request('PUT', endpoint, json_data=json_data, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> Dict:
        """Send a DELETE request.
        
        Args:
            endpoint: API endpoint
            **kwargs: Additional arguments to pass to request()
            
        Returns:
            Response data as a dictionary
            
        Raises:
            SSRFError: If URL validation fails
            requests.exceptions.RequestException: If the request fails
        """
        return self.request('DELETE', endpoint, **kwargs)
    
    def close(self) -> None:
        """Close the underlying session."""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
