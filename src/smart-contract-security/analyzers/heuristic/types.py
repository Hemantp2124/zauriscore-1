"""
Type definitions for the heuristic analyzer.

This module contains type hints and data structures used throughout the heuristic analyzer.
"""

from typing import Dict, Literal, TypedDict, Any, Optional, Union
from pathlib import Path

# Type aliases
EconomicRisk = Literal['economic_risk_low', 'economic_risk_medium', 'economic_risk_high']

class HeuristicWeights(TypedDict):
    """Type definition for heuristic scoring weights."""
    reentrancy_guard_present: int
    reentrancy_guard_absent: int
    unguarded_call: int
    owner_selfdestruct: int
    access_control_present: int
    access_control_absent: int
    natspec_present: int
    etherscan_verified: int
    no_external_calls: int
    economic_risk_low: int
    economic_risk_medium: int
    economic_risk_high: int
    compiler_vulnerability: int

# Default heuristic weights
DEFAULT_HEURISTIC_WEIGHTS: HeuristicWeights = {
    'reentrancy_guard_present': 5,
    'reentrancy_guard_absent': -15,
    'unguarded_call': -20,
    'owner_selfdestruct': -20,
    'access_control_present': 5,
    'access_control_absent': -10,
    'natspec_present': 10,
    'etherscan_verified': 10,
    'no_external_calls': 10,
    'economic_risk_low': 10,
    'economic_risk_medium': -5,
    'economic_risk_high': -15,
    'compiler_vulnerability': -25
}

class AnalysisResult(TypedDict):
    """Type definition for analysis results."""
    success: bool
    score: float
    findings: Dict[str, Any]
    warnings: list[str]
    error: Optional[str]
    metadata: Dict[str, Any]
