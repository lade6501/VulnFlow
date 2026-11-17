"""
src/vulnflow/knowledge/sources/osv.py
Fetches open vulnerability data from the Open Source Vulnerabilities (OSV) API.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vulnflow.knowledge.sources.osv")

# Seeded fallback cache for air-gapped / offline testing
BUILTIN_ADVISORIES: Dict[str, List[Dict[str, Any]]] = {
    "lodash": [
        {
            "id": "GHSA-p6mc-m468-83gw",
            "aliases": ["CVE-2020-8203"],
            "summary": "Prototype Pollution in lodash",
            "details": "Prototype pollution vulnerability in lodash before 4.17.21 allows attackers to cause denial of service or code execution via zipObjectDeep.",
            "cvss_score": 7.4,
            "fixed_versions": ["4.17.21"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"],
        },
        {
            "id": "GHSA-35jh-r3h4-6jhm",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection in lodash",
            "details": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via template function.",
            "cvss_score": 7.2,
            "fixed_versions": ["4.17.21"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
        },
    ],
    "moment": [
        {
            "id": "GHSA-8hfj-j24r-96c4",
            "aliases": ["CVE-2022-24785"],
            "summary": "Path Traversal in moment",
            "details": "Moment.js before 2.29.2 is vulnerable to path traversal through user-supplied locale names.",
            "cvss_score": 7.5,
            "fixed_versions": ["2.29.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-24785"],
        }
    ],
    "axios": [
        {
            "id": "GHSA-8hc4-vh64-cxmj",
            "aliases": ["CVE-2023-45857"],
            "summary": "Cross-Site Request Forgery in axios",
            "details": "Axios versions before 1.6.0 leak XSRF-TOKEN in cross-site redirects.",
            "cvss_score": 6.5,
            "fixed_versions": ["1.6.0", "1.7.4"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45857"],
        }
    ],
}


class OSVClient:
    """Client for querying open vulnerability data from Google OSV API (api.osv.dev)."""

    def __init__(self, base_url: str = "https://api.osv.dev/v1", timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def query_package(
        self,
        package_name: str,
        ecosystem: str = "npm",
        version: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query OSV for all known vulnerabilities affecting a given package.
        Returns normalized advisory chunk dictionaries.
        """
        # Infer ecosystem from prefix if present
        clean_name = package_name.replace("PKG-", "")
        if ":" in clean_name and ecosystem == "npm":
            prefix = clean_name.split(":", 1)[0].lower()
            if prefix in ("pip", "pypi", "python"):
                ecosystem = "PyPI"
            elif prefix in ("npm", "node"):
                ecosystem = "npm"

        bare_name = clean_name.split(":", 1)[1] if ":" in clean_name else clean_name

        # Try live network query first
        chunks = self._query_live_api(bare_name, ecosystem, version)
        if chunks:
            return chunks

        # Fallback to local cached advisories
        return self._query_local_cache(bare_name, ecosystem)

    def _query_live_api(
        self,
        bare_name: str,
        ecosystem: str,
        version: Optional[str],
    ) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/query"
        osv_eco = "npm"
        if ecosystem.lower() in ("pip", "pypi", "python"):
            osv_eco = "PyPI"
        elif ecosystem.lower() in ("npm", "node"):
            osv_eco = "npm"
        else:
            osv_eco = ecosystem

        query_payload: Dict[str, Any] = {
            "package": {"name": bare_name, "ecosystem": osv_eco}
        }
        if version and version != "0.0.0":
            query_payload["version"] = version

        req_data = json.dumps(query_payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            chunks = []
            for item in vulns:
                chunk = self._format_osv_item(item, bare_name, ecosystem)
                if chunk:
                    chunks.append(chunk)
            return chunks
        except Exception as exc:
            logger.debug("OSV live query unavailable for %s (%s); using local cache", bare_name, exc)
            return []

    def _query_local_cache(self, bare_name: str, ecosystem: str) -> List[Dict[str, Any]]:
        cached_items = BUILTIN_ADVISORIES.get(bare_name, [])
        chunks = []
        for item in cached_items:
            chunk = self._format_osv_item(item, bare_name, ecosystem)
            if chunk:
                chunks.append(chunk)
        return chunks

    def _format_osv_item(
        self,
        item: Dict[str, Any],
        bare_name: str,
        ecosystem: str,
    ) -> Optional[Dict[str, Any]]:
        vid = item.get("id", "UNKNOWN-ADV")
        aliases = item.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), vid)
        chunk_id = f"ADV-{bare_name}-{cve_alias.replace('CVE-', '')}"

        details = item.get("details") or item.get("summary") or ""
        fixes: List[str] = list(item.get("fixed_versions", []))

        # Extract fixed versions from OSV affected ranges if present
        if not fixes and "affected" in item:
            for aff in item.get("affected", []):
                for rng in aff.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixes.append(event["fixed"])

        # Deduplicate fixed versions while preserving order
        fixes = list(dict.fromkeys(fixes))

        return {
            "chunk_id": chunk_id,
            "id": vid,
            "title": item.get("summary") or vid,
            "cve": cve_alias,
            "aliases": aliases,
            "package": f"{ecosystem}:{bare_name}",
            "ecosystem": ecosystem,
            "cvss_score": item.get("cvss_score") or 7.0,
            "description": details,
            "fixed_versions": fixes,
            "references": item.get("references", []),
        }


# Global default client
default_osv_client = OSVClient()
