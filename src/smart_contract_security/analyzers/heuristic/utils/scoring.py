"""
Scoring Utilities

This module provides scoring and normalization functions for the heuristic analyzer.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

def normalize_score(
    score: float, 
    min_score: float = -100.0, 
    max_score: float = 50.0
) -> float:
    """Normalize a score to a 0-100 scale.
    
    Args:
        score: Raw score to normalize
        min_score: Minimum possible score
        max_score: Maximum possible score
        
    Returns:
        float: Normalized score between 0 and 100
    """
    try:
        if min_score >= max_score:
            raise ValueError("min_score must be less than max_score")
            
        # Clip the score to the specified range
        clipped = max(min(score, max_score), min_score)
        
        # Normalize to 0-100 range
        normalized = ((clipped - min_score) / (max_score - min_score)) * 100
        
        # Ensure the result is between 0 and 100
        return max(0.0, min(100.0, normalized))
        
    except (ValueError, ZeroDivisionError) as e:
        logger.warning(f"Error normalizing score: {e}. Using default score of 50.0")
        return 50.0  # Return a neutral score on error
