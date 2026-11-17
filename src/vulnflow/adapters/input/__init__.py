"""
src/vulnflow/adapters/input/__init__.py
Input adapters translating external security scanner reports to normalized Findings.
"""

from vulnflow.adapters.input.sarif import SARIFAdapter
from vulnflow.adapters.input.trivy import ScannerParseError, TrivyAdapter

__all__ = ["SARIFAdapter", "ScannerParseError", "TrivyAdapter"]
