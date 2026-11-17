"""
src/vulnflow/adapters/input/__init__.py
Input adapters translating external security scanner reports to normalized Findings.
"""

from vulnflow.adapters.input.gitleaks import GitleaksAdapter
from vulnflow.adapters.input.grype import GrypeAdapter
from vulnflow.adapters.input.osv import OSVAdapter
from vulnflow.adapters.input.sarif import SARIFAdapter
from vulnflow.adapters.input.trivy import ScannerParseError, TrivyAdapter

__all__ = [
    "GitleaksAdapter",
    "GrypeAdapter",
    "OSVAdapter",
    "SARIFAdapter",
    "ScannerParseError",
    "TrivyAdapter",
]
