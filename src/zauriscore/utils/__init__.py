"""
ZauriScore Utils Package

This package contains utility functions and helper modules:
- Report Generator: Generate analysis reports
- Environment Checker: Verify tool dependencies
"""

from .report_generator import JSONExporter, ZauriScoreReportGenerator
from .check_slither_env import check_slither_installation

# Create a simple report generator function for compatibility
def create_report_generator():
    """Create a report generator instance."""
    return JSONExporter()

def generate_report(data, output_path=None):
    """Generate a report from analysis data."""
    exporter = JSONExporter()
    return exporter.export(data, output_path)

__all__ = ['create_report_generator', 'generate_report', 'check_slither_installation']
