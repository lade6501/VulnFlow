"""
src/vulnflow/adapters/ecosystem/pip.py
Handles Python pip requirements.txt parsing, package updates, and version bumps.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("vulnflow.adapters.ecosystem.pip")


class PipAdapter:
    """Manages Python requirements.txt dependency modifications and version bumps."""

    @staticmethod
    def bump_dependency(
        manifest_path: Path,
        package_name: str,
        new_version: str,
    ) -> Tuple[bool, str]:
        """
        Update the specified package in requirements.txt to new_version.
        Preserves formatting and operator style (e.g. ==, >=).
        """
        clean_name = package_name.replace("pip:", "").replace("python:", "")
        if not manifest_path.exists():
            raise FileNotFoundError(f"requirements.txt not found at {manifest_path}")

        with open(manifest_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        pkg_regex = re.escape(clean_name).replace(r"\-", "[-_]").replace("_", "[-_]")
        pattern = re.compile(rf"^\s*({pkg_regex})\s*([=><~^!]+)?\s*([^\s#]+)?(\s*#.*)?$", re.IGNORECASE)
        changed = False
        old_line = ""
        new_line = ""
        new_lines = []

        for line in lines:
            stripped = line.strip()
            match = pattern.match(stripped)
            if match and not changed:
                pkg_match = match.group(1)
                op = match.group(2) or ">="
                comment = match.group(4) or ""
                old_line = stripped
                new_line = f"{pkg_match}{op}{new_version}{comment}"
                new_lines.append(new_line + "\n")
                changed = True
            else:
                new_lines.append(line)

        if not changed:
            old_line = "none"
            new_line = f"{clean_name}>={new_version}"
            new_lines.append(new_line + "\n")
            changed = True

        with open(manifest_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        diff = (
            f"--- requirements.txt\n"
            f"+++ requirements.txt\n"
            f"- {old_line}\n"
            f"+ {new_line}"
        )
        logger.info("Bumped %s to %s in %s", clean_name, new_version, manifest_path)
        return True, diff
