"""
Centralized error handling utilities for ZauriScore.

This module provides standardized error handling, logging, and exception classes
for use throughout the ZauriScore codebase.
"""

import functools
import logging
import sys
import traceback
from enum import Enum
from typing import Any, Callable, Dict, Optional, Type, TypeVar, Union, cast

from fastapi import HTTPException, status

# Configure logger
logger = logging.getLogger(__name__)

# Type variable for function return types
T = TypeVar("T")


class ErrorSeverity(Enum):
    """Enum for error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ZauriScoreError(Exception):
    """Base exception class for ZauriScore-specific errors."""
    
    def __init__(
        self, 
        message: str, 
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize ZauriScoreError.
        
        Args:
            message: Error message
            severity: Error severity level
            details: Additional error details
        """
        self.message = message
        self.severity = severity
        self.details = details or {}
        super().__init__(message)


class ModelError(ZauriScoreError):
    """Exception for ML model-related errors."""
    pass


class EtherscanError(ZauriScoreError):
    """Exception for Etherscan API-related errors."""
    pass


class ContractAnalysisError(ZauriScoreError):
    """Exception for smart contract analysis errors."""
    pass


class ValidationError(ZauriScoreError):
    """Exception for data validation errors."""
    
    def __init__(self, message: str, field: str, value: Any):
        """
        Initialize ValidationError.
        
        Args:
            message: Error message
            field: Field that failed validation
            value: Invalid value
        """
        super().__init__(
            message, 
            severity=ErrorSeverity.MEDIUM,
            details={"field": field, "value": str(value)}
        )
        self.field = field
        self.value = value


def error_to_http_exception(error: Exception) -> HTTPException:
    """
    Convert an exception to an appropriate HTTPException.
    
    Args:
        error: The exception to convert
        
    Returns:
        HTTPException with appropriate status code and details
    """
    # Map of exception types to HTTP status codes
    status_code_map = {
        ValidationError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        ModelError: status.HTTP_500_INTERNAL_SERVER_ERROR,
        EtherscanError: status.HTTP_503_SERVICE_UNAVAILABLE,
        ContractAnalysisError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        ValueError: status.HTTP_400_BAD_REQUEST,
        KeyError: status.HTTP_400_BAD_REQUEST,
        ZauriScoreError: status.HTTP_500_INTERNAL_SERVER_ERROR
    }
    
    # Determine status code based on error type
    for error_type, code in status_code_map.items():
        if isinstance(error, error_type):
            status_code = code
            break
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    
    # Format error details based on error type
    if isinstance(error, ValidationError):
        detail = {
            "message": error.message,
            "field": error.field,
            "value": str(error.value),
            "type": "validation_error"
        }
    elif isinstance(error, ZauriScoreError):
        error_type = error.__class__.__name__.lower()
        detail = {
            "message": str(error),
            "type": error_type,
            "severity": error.severity.value if hasattr(error, 'severity') else "medium"
        }
        # Add any additional details if available
        if hasattr(error, 'details') and error.details:
            detail["details"] = error.details
    else:
        # Generic error handling
        detail = {
            "message": str(error) or "An unexpected error occurred",
            "type": "unknown"
        }
    
    return HTTPException(status_code=status_code, detail=detail)


def handle_exceptions(
    error_types: Optional[Union[Type[Exception], tuple[Type[Exception], ...]]] = None,
    log_traceback: bool = True,
    default_return: Any = None,
    raise_http_exception: bool = False
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for handling exceptions in functions.
    
    Args:
        error_types: Exception type(s) to catch
        log_traceback: Whether to log the traceback
        default_return: Default value to return on error
        raise_http_exception: Whether to convert exceptions to HTTPExceptions
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if error_types and not isinstance(e, error_types):
                    raise
                
                # Log the error
                if log_traceback:
                    logger.error(
                        f"Error in {func.__name__}: {str(e)}\n"
                        f"{traceback.format_exc()}"
                    )
                else:
                    logger.error(f"Error in {func.__name__}: {str(e)}")
                
                # Convert to HTTP exception if requested
                if raise_http_exception:
                    http_exc = error_to_http_exception(e)
                    raise http_exc
                
                # Return default value
                return cast(T, default_return)
        
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if error_types and not isinstance(e, error_types):
                    raise
                
                # Log the error
                if log_traceback:
                    logger.error(
                        f"Error in {func.__name__}: {str(e)}\n"
                        f"{traceback.format_exc()}"
                    )
                else:
                    logger.error(f"Error in {func.__name__}: {str(e)}")
                
                # Convert to HTTP exception if requested
                if raise_http_exception:
                    http_exc = error_to_http_exception(e)
                    raise http_exc
                
                # Return default value
                return cast(T, default_return)
        
        import inspect
        if inspect.iscoroutinefunction(func):
            return cast(Callable[..., T], async_wrapper)
        return cast(Callable[..., T], sync_wrapper)
    
    return decorator


def setup_global_exception_handler() -> None:
    """
    Set up a global exception handler for uncaught exceptions.
    """
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            # Let KeyboardInterrupt pass through
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logger.critical("Uncaught exception", 
                       exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = handle_exception


async def fastapi_exception_handler(request: "Request", exc: Exception) -> "JSONResponse":
    """
    Global exception handler for FastAPI applications.
    
    Args:
        request: The request that caused the exception
        exc: The exception that was raised
        
    Returns:
        JSONResponse with appropriate status code and error details
    """
    from fastapi.responses import JSONResponse
    
    # Log the exception
    logger.exception(f"Unhandled exception in request to {request.url.path}: {str(exc)}")
    
    # Convert to HTTPException if it's not already
    if not isinstance(exc, HTTPException):
        http_exc = error_to_http_exception(exc)
    else:
        http_exc = exc
    
    # Return JSON response
    return JSONResponse(
        status_code=http_exc.status_code,
        content={
            "error": True,
            "detail": http_exc.detail,
            "status_code": http_exc.status_code,
            "path": request.url.path
        }
    )