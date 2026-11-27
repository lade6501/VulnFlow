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
from typing import Dict, Tuple

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
        coordinate = package.removeprefix("maven:").split(":")
        if len(coordinate) not in (1, 2) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", target_version):
            return False, ""
        group = coordinate[0] if len(coordinate) == 2 else None
        artifact = coordinate[-1]

        # Preserve formatting by editing the version inside one matching dependency block.
        block_pattern = re.compile(r"<!--.*?-->|<dependency\s*>.*?</dependency\s*>", re.DOTALL)
        versions = []
        for block in block_pattern.finditer(original_content):
            if block.group().startswith("<!--"):
                continue
            try:
                entry = ET.fromstring(block.group())
            except ET.ParseError:
                continue
            if (entry.findtext("artifactId") or "").strip() != artifact:
                continue
            if group is not None and (entry.findtext("groupId") or "").strip() != group:
                continue
            version = re.search(r"<version>\s*([^<>\s]+)\s*</version>", block.group())
            if version and version.group(1) == (entry.findtext("version") or "").strip():
                versions.append((block.start() + version.start(1), block.start() + version.end(1)))
        if len(versions) != 1:
            return False, ""
        start, end = versions[0]
        new_content = original_content[:start] + target_version + original_content[end:]

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
