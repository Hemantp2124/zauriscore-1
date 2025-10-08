"""
Configuration management for ZauriScore.

This module provides a centralized configuration system using environment variables
with validation, type conversion, and support for different environments.
"""

import os
import logging
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, Type, TypeVar

from pydantic import BaseSettings, Field, validator, root_validator
from pydantic.types import DirectoryPath, FilePath

# Load environment variables from .env file if it exists
env_path = Path(__file__).parent.parent.parent.parent / ".env"
if env_path.exists():
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=env_path)

class Environment(str, Enum):
    """Application environment types."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"

T = TypeVar('T', bound='Settings')

class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Environment and Mode
    ENVIRONMENT: Environment = Field(
        default=Environment.DEVELOPMENT,
        env="ENVIRONMENT",
        description="Application environment (development, testing, production)",
    )
    
    # API Keys
    ETHERSCAN_API_KEY: str = Field(
        ...,  # Required
        env="ETHERSCAN_API_KEY",
        description="API key for Etherscan API",
        min_length=32,
    )
    
    # Timeouts (in seconds)
    SLITHER_TIMEOUT: int = Field(
        default=300,
        env="SLITHER_TIMEOUT",
        description="Timeout for Slither analysis in seconds",
        gt=0,
    )
    
    REQUEST_TIMEOUT: int = Field(
        default=30,
        env="REQUEST_TIMEOUT",
        description="Default timeout for HTTP requests in seconds",
        gt=0,
    )
    
    # Paths
    REPORTS_DIR: DirectoryPath = Field(
        default=Path("reports"),
        env="REPORTS_DIR",
        description="Directory to store analysis reports",
    )
    
    CACHE_DIR: DirectoryPath = Field(
        default=Path(".cache"),
        env="CACHE_DIR",
        description="Directory for caching data",
    )
    
    # Analysis
    MAX_CONTRACT_SIZE: int = Field(
        default=24576,  # 24KB
        env="MAX_CONTRACT_SIZE",
        description="Maximum allowed contract size in bytes",
        gt=0,
    )
    
    MAX_RETRIES: int = Field(
        default=3,
        env="MAX_RETRIES",
        description="Maximum number of retries for failed operations",
        ge=0,
    )
    
    # Logging
    LOG_LEVEL: str = Field(
        default="INFO",
        env="LOG_LEVEL",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
        regex=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
    )
    
    LOG_FILE: Optional[FilePath] = Field(
        default=None,
        env="LOG_FILE",
        description="Optional file path for logging",
    )
    
    # Model Configuration
    MODEL_PATH: DirectoryPath = Field(
        default=Path("models"),
        env="MODEL_PATH",
        description="Directory containing ML models",
    )
    
    # Performance
    WORKERS: int = Field(
        default=os.cpu_count() or 1,
        env="WORKERS",
        description="Number of worker processes",
        gt=0,
    )
    
    class Config:
        """Pydantic configuration."""
        env_file = env_path if env_path.exists() else None
        env_file_encoding = 'utf-8'
        case_sensitive = True
        extra = 'ignore'  # Ignore extra environment variables
    
    @validator('REPORTS_DIR', 'CACHE_DIR', 'MODEL_PATH', pre=True)
    def create_directories(cls, v: Path) -> Path:
        """Ensure directories exist."""
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    @root_validator(pre=True)
    def validate_environment(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Validate environment-specific settings."""
        if values.get('ENVIRONMENT') == Environment.PRODUCTION:
            if values.get('LOG_LEVEL') == 'DEBUG':
                logging.warning(
                    "Debug mode is not recommended in production. "
                    "Setting log level to INFO."
                )
                values['LOG_LEVEL'] = 'INFO'
        return values
    
    @classmethod
    def from_env(cls: Type[T]) -> T:
        """Create settings from environment variables."""
        return cls()

# Global settings instance
settings = Settings.from_env()

# Backward compatibility
def get_config() -> Dict[str, Any]:
    """Get configuration as a dictionary (for backward compatibility)."""
    return settings.dict(exclude_unset=True)

# Initialize logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=settings.LOG_FILE if settings.LOG_FILE else None,
)

# Log configuration on startup
logging.info("Initializing ZauriScore with configuration: %s", 
    {k: '***' if 'KEY' in k or 'SECRET' in k else v 
     for k, v in settings.dict().items()}
)
