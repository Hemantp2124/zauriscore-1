"""
ZauriScore - AI-powered smart contract vulnerability analysis platform.

This package provides comprehensive smart contract security analysis including:
- Static analysis with Slither
- ML-powered vulnerability detection with CodeBERT
- Comprehensive risk scoring and reporting
- REST API for integration
"""

from .analyzers import ComprehensiveContractAnalyzer
from .models import CodeBERTRegressor, predict_vulnerabilities
from .utils import create_report_generator

__version__ = "1.0.0"
__all__ = [
    'ComprehensiveContractAnalyzer',
    'CodeBERTRegressor',
    'predict_vulnerabilities',
    'create_report_generator'
]
