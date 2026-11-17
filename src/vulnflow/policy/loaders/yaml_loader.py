"""
src/vulnflow/policy/loaders/yaml_loader.py
Loads organizational policy definitions from local YAML configuration files.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from vulnflow.contracts.policy import (
    ApprovedPackagesPolicy,
    PackagePolicyEntry,
    PolicyRules,
    PolicyStatus,
)

logger = logging.getLogger("vulnflow.policy.loaders.yaml")


def parse_simple_yaml(content: str) -> Dict[str, Any]:
    """
    Lightweight zero-dependency YAML parser for policy configuration.
    Falls back to pyyaml if available.
    """
    try:
        import yaml
        return yaml.safe_load(content) or {}
    except ImportError:
        pass

    # Simple dictionary and list parser for policy YAML files
    result: Dict[str, Any] = {"packages": [], "rules": {}}
    current_section: Optional[str] = None
    current_pkg: Optional[Dict[str, Any]] = None

    for line in content.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue

        if line_stripped.startswith("packages:"):
            current_section = "packages"
            continue
        elif line_stripped.startswith("rules:"):
            current_section = "rules"
            current_pkg = None
            continue
        elif line_stripped.startswith("tiers:") or line_stripped.startswith("allowed:") or line_stripped.startswith("denied:"):
            current_section = line_stripped.rstrip(":")
            continue

        if current_section == "packages":
            if line_stripped.startswith("- "):
                # New package entry
                current_pkg = {}
                result["packages"].append(current_pkg)
                pair = line_stripped[2:].strip()
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    current_pkg[k.strip()] = v.strip().strip("'\"")
            elif current_pkg is not None and ":" in line_stripped:
                k, v = line_stripped.split(":", 1)
                current_pkg[k.strip()] = v.strip().strip("'\"")

        elif current_section == "rules":
            if ":" in line_stripped:
                k, v = line_stripped.split(":", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if v.startswith("[") and v.endswith("]"):
                    items = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
                    result["rules"][k] = items
                elif v.lower() in ("true", "yes", "1"):
                    result["rules"][k] = True
                elif v.lower() in ("false", "no", "0"):
                    result["rules"][k] = False
                else:
                    result["rules"][k] = v

    return result


class YAMLPolicyLoader:
    """Loads and validates ApprovedPackagesPolicy from a YAML file."""

    def __init__(self, policy_path: Optional[Union[str, Path]] = None) -> None:
        self.policy_path = Path(policy_path or "policies/approved_packages.yaml")

    def load(self) -> ApprovedPackagesPolicy:
        """Parse policy file into ApprovedPackagesPolicy instance."""
        if not self.policy_path.exists():
            logger.warning("Policy file not found at %s; returning empty policy", self.policy_path)
            return ApprovedPackagesPolicy()

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                content = f.read()
            data = parse_simple_yaml(content)
            return ApprovedPackagesPolicy.from_dict(data)
        except Exception as exc:
            logger.error("Failed to load policy from %s: %s", self.policy_path, exc)
            return ApprovedPackagesPolicy()
