"""
ZauriScore Models Package

This package contains all ML model-related functionality:
- Model Trainer: Train ML models
- Vulnerability Predictor: Predict vulnerabilities
- Training Scripts: Classifier and regression model training
"""
import importlib
from typing import Any, Dict, Optional, Type, TypeVar

# Type variable for generic model types
T = TypeVar('T')

def _lazy_import(module_name: str, class_name: Optional[str] = None) -> Any:
    """Lazily import a module or class.
    
    Args:
        module_name: The module to import
        class_name: Optional class name to import from the module
        
    Returns:
        The imported module or class
    """
    try:
        module = importlib.import_module(module_name)
        return getattr(module, class_name) if class_name else module
    except (ImportError, AttributeError) as e:
        raise ImportError(f"Failed to import {class_name or module_name}: {str(e)}")

# Lazy imports for models
CodeBERTRegressor = lambda: _lazy_import('.codebert', 'CodeBERTRegressor')
predict_vulnerabilities = lambda: _lazy_import('.predict_vulnerability', 'predict_vulnerabilities')
train_classifier = lambda: _lazy_import('.train_classifier', 'train_classifier')
create_advanced_ensemble = lambda: _lazy_import('.train_classifier', 'create_advanced_ensemble')
train_regression_model = lambda: _lazy_import('.train_regression', 'train_regression_model')

# Export the public API
__all__ = [
    'CodeBERTRegressor', 
    'predict_vulnerabilities',
    'train_classifier',
    'train_regression_model',
    'create_advanced_ensemble'
]
