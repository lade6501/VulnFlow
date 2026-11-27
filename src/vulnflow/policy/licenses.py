"""
src/vulnflow/policy/licenses.py
Checks proposed dependency package licenses against organizational policy allowlists.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Set

from vulnflow.contracts.policy import PolicyStatus
from vulnflow.policy.loaders.yaml_loader import parse_simple_yaml

logger = logging.getLogger("vulnflow.policy.licenses")


class LicenseChecker:
    """Evaluates software package licenses against permitted, restricted, and denied policies."""

    def __init__(self, policy_file: Optional[str] = None) -> None:
        self.policy_path = Path(policy_file or "policies/licenses.yaml")
        self.allowed: Set[str] = set()
        self.restricted: Set[str] = set()
        self.denied: Set[str] = set()
        self.load_policy()

    def load_policy(self) -> None:
        """Load license policy definitions from YAML file."""
        if not self.policy_path.exists():
            # Default fallbacks if file not on disk
            self.allowed = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "CC0-1.0", "Unlicense"}
            self.restricted = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0"}
            self.denied = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0", "Commons-Clause"}
            return

        try:
            content = self.policy_path.read_text(encoding="utf-8")
            data = parse_simple_yaml(content)
            self.allowed = {str(x).strip() for x in data.get("allowed", [])}
            self.restricted = {str(x).strip() for x in data.get("restricted", [])}
            self.denied = {str(x).strip() for x in data.get("denied", [])}
        except Exception as exc:
            logger.warning("Failed loading license policy from %s: %s", self.policy_path, exc)
            self.allowed = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"}
            self.denied = {"GPL-2.0", "GPL-3.0", "AGPL-3.0"}

    def check_license(self, license_name: str, package: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluate a single license against policy.

        Returns a dictionary with status, allowed flag, and reason.
        """
        lic_clean = (license_name or "UNKNOWN").strip()

        # Check denied list (case-insensitive)
        for d in self.denied:
            if d.lower() == lic_clean.lower():
                return {
                    "license": lic_clean,
                    "package": package,
                    "status": PolicyStatus.LICENSE_DENIED,
                    "allowed": False,
                    "reason": f"License {lic_clean} is explicitly denied by corporate policy.",
                }

        # Check allowed list
        for a in self.allowed:
            if a.lower() == lic_clean.lower():
                return {
                    "license": lic_clean,
                    "package": package,
                    "status": PolicyStatus.APPROVED,
                    "allowed": True,
                    "reason": f"License {lic_clean} is approved for production use.",
                }

        # Check restricted list
        for r in self.restricted:
            if r.lower() == lic_clean.lower():
                return {
                    "license": lic_clean,
                    "package": package,
                    "status": PolicyStatus.UNKNOWN,
                    "allowed": False,
                    "requires_approval": True,
                    "reason": f"License {lic_clean} is restricted; requires human legal approval.",
                }

        return {
            "license": lic_clean,
            "package": package,
            "status": PolicyStatus.UNKNOWN,
            "allowed": False,
            "requires_approval": True,
            "reason": f"License {lic_clean} is unclassified; requires legal review.",
        }


default_license_checker = LicenseChecker()
