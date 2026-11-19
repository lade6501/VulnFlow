"""
src/vulnflow/core/dotenv.py
Zero-dependency .env loader ensuring environment variables are injected into os.environ.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def load_dotenv(custom_path: Optional[str] = None) -> bool:
    """Find and load key-value pairs from .env into os.environ."""
    candidates = []
    if custom_path:
        candidates.append(Path(custom_path))

    cwd = Path.cwd()
    here = Path(__file__).resolve().parent

    candidates.extend([
        cwd / ".env",
        cwd / "vulnflow" / ".env",
        here.parent.parent.parent / ".env",  # repo root (vulnflow/)
        here.parent.parent.parent.parent / ".env",  # workspace root (VulnFlow/)
    ])

    for p in candidates:
        if p and p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
                return True
            except Exception:
                pass
    return False


# Automatically load on import
load_dotenv()
