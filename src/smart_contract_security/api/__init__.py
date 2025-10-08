"""
ZauriScore API Package

This package contains web API implementations.

Note:
- We keep this __init__ import-light so importing `zauriscore.api` does NOT
  pull in Flask or FastAPI servers implicitly. This avoids import side-effects
  when tools like Uvicorn import submodules (e.g., `zauriscore.api.fastapi_app`).
"""

__all__ = []
