"""
src/vulnflow/adapters/ecosystem/maven.py
Handles Maven pom.xml parsing, dependency version bumps, and XML patch generation.
"""

from __future__ import annotations

import difflib
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("vulnflow.adapters.ecosystem.maven")


class MavenAdapter:
    """Adapter for Java Maven projects managing pom.xml dependencies."""

    @classmethod
    def parse_dependencies(cls, pom_path: Path) -> Dict[str, str]:
        """Extract direct dependencies and their versions from pom.xml."""
        if not pom_path.exists():
            return {}

        deps: Dict[str, str] = {}
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            # Strip XML namespaces if present
            ns = ""
            if "}" in root.tag:
                ns = root.tag.split("}")[0] + "}"

            for dep in root.findall(f".//{ns}dependency"):
                grp = dep.find(f"{ns}groupId")
                art = dep.find(f"{ns}artifactId")
                ver = dep.find(f"{ns}version")
                if art is not None and art.text:
                    art_name = art.text.strip()
                    pkg_key = f"{grp.text.strip()}:{art_name}" if grp is not None and grp.text else art_name
                    ver_text = ver.text.strip() if ver is not None and ver.text else "unknown"
                    deps[pkg_key] = ver_text
                    deps[art_name] = ver_text
        except Exception as exc:
            logger.warning("Failed parsing pom.xml dependencies with xml parser: %s", exc)

        return deps

    @classmethod
    def bump_dependency(
        cls,
        pom_path: Path,
        package: str,
        target_version: str,
    ) -> Tuple[bool, str]:
        """Update dependency version in pom.xml and return (success, unified_diff)."""
        if not pom_path.exists():
            return False, ""

        original_content = pom_path.read_text(encoding="utf-8")
        clean_target = package.split(":")[-1]

        # Use regex to replace version while preserving formatting and XML structure
        # Matches <artifactId>clean_target</artifactId> ... <version>old</version>
        pattern = re.compile(
            rf"(<artifactId>\s*{re.escape(clean_target)}\s*</artifactId>[\s\S]*?<version>)([^<]+)(</version>)",
            re.IGNORECASE,
        )

        match = pattern.search(original_content)
        if not match:
            # Try alternate ordering: <version> before <artifactId>
            pattern_rev = re.compile(
                rf"(<version>)([^<]+)(</version>[\s\S]*?<artifactId>\s*{re.escape(clean_target)}\s*</artifactId>)",
                re.IGNORECASE,
            )
            match_rev = pattern_rev.search(original_content)
            if not match_rev:
                logger.warning("Could not locate dependency %s in %s", package, pom_path)
                return False, ""
            new_content = pattern_rev.sub(rf"\g<1>{target_version}\g<3>", original_content, count=1)
        else:
            new_content = pattern.sub(rf"\g<1>{target_version}\g<3>", original_content, count=1)

        if new_content == original_content:
            return False, ""

        pom_path.write_text(new_content, encoding="utf-8")

        # Generate standard unified diff
        orig_lines = original_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                orig_lines,
                new_lines,
                fromfile=f"a/{pom_path.name}",
                tofile=f"b/{pom_path.name}",
            )
        )
        return True, "".join(diff_lines)
