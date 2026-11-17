"""
src/vulnflow/adapters/ecosystem/npm.py
Handles npm dependency tree parsing, package updates, and build verification.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("vulnflow.adapters.ecosystem.npm")


class NPMAdapter:
    """Manages Node.js / npm package.json modifications and dependency version bumps."""

    @staticmethod
    def load_manifest(manifest_path: Path) -> Dict[str, Any]:
        """Read and parse package.json from disk."""
        if not manifest_path.exists():
            raise FileNotFoundError(f"package.json not found at {manifest_path}")
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def bump_dependency(
        manifest_path: Path,
        package_name: str,
        new_version: str,
        preserve_prefix: bool = True,
    ) -> Tuple[bool, str]:
        """
        Update the specified dependency to new_version in package.json.

        Returns:
            (changed: bool, diff_description: str)
        """
        # Strip ecosystem prefix if present
        clean_name = package_name.replace("npm:", "")
        data = NPMAdapter.load_manifest(manifest_path)

        old_version: Optional[str] = None
        target_section: Optional[str] = None

        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if section in data and clean_name in data[section]:
                old_version = data[section][clean_name]
                target_section = section
                break

        if not target_section or not old_version:
            # Add to dependencies if not found
            if "dependencies" not in data:
                data["dependencies"] = {}
            data["dependencies"][clean_name] = f"^{new_version}"
            target_section = "dependencies"
            old_version = "none"

        # Determine version prefix to retain (e.g. ^, ~, or bare)
        prefix = ""
        if preserve_prefix and old_version.startswith("^"):
            prefix = "^"
        elif preserve_prefix and old_version.startswith("~"):
            prefix = "~"

        formatted_target = f"{prefix}{new_version}"
        data[target_section][clean_name] = formatted_target

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

        diff = (
            f"--- package.json\n"
            f"+++ package.json\n"
            f"-   \"{clean_name}\": \"{old_version}\"\n"
            f"+   \"{clean_name}\": \"{formatted_target}\""
        )
        logger.info("Bumped %s from %s to %s in %s", clean_name, old_version, formatted_target, manifest_path)
        return True, diff

    @staticmethod
    def replace_dependency(
        manifest_path: Path,
        old_package: str,
        new_package: str,
        new_version: str = "latest",
    ) -> Tuple[bool, str]:
        """Replace a deprecated/banned package with its approved replacement in package.json."""
        clean_old = old_package.replace("npm:", "")
        clean_new = new_package.replace("npm:", "")
        data = NPMAdapter.load_manifest(manifest_path)
        found_section = None
        old_ver = "none"

        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if section in data and clean_old in data[section]:
                old_ver = data[section].pop(clean_old)
                found_section = section
                break

        target_section = found_section or "dependencies"
        if target_section not in data:
            data[target_section] = {}
        formatted_target = f"^{new_version}" if new_version not in ("latest", "*") else "*"
        data[target_section][clean_new] = formatted_target

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

        diff = (
            f"--- package.json\n"
            f"+++ package.json\n"
            f"-   \"{clean_old}\": \"{old_ver}\"\n"
            f"+   \"{clean_new}\": \"{formatted_target}\""
        )
        logger.info("Replaced %s with %s (%s) in %s", clean_old, clean_new, formatted_target, manifest_path)
        return True, diff
