"""
src/vulnflow/core/console.py
Terminal styling, ANSI colors, and enterprise CLI layout utilities.
Supports NO_COLOR environment variable and non-interactive stdout piping.
"""

from __future__ import annotations

import os
import sys
from typing import Any


def _supports_color() -> bool:
    """Return True if stdout supports ANSI color codes."""
    if os.getenv("NO_COLOR") or os.getenv("VULNFLOW_NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR") or os.getenv("CLICOLOR_FORCE"):
        return True
    if sys.platform == "win32":
        # Enable ANSI virtual terminal processing on Windows cmd.exe / PowerShell
        try:
            os.system("")
        except Exception:
            pass
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOR = _supports_color()

# ANSI Color & Style Codes
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
DIM = "\033[2m" if USE_COLOR else ""
ITALIC = "\033[3m" if USE_COLOR else ""
UNDERLINE = "\033[4m" if USE_COLOR else ""

# Foreground colors
RED = "\033[91m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
BLUE = "\033[94m" if USE_COLOR else ""
MAGENTA = "\033[95m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
WHITE = "\033[97m" if USE_COLOR else ""
GRAY = "\033[90m" if USE_COLOR else ""

# Background tags
BG_DARK = "\033[48;5;236m" if USE_COLOR else ""
BG_GREEN = "\033[42;30m" if USE_COLOR else ""
BG_YELLOW = "\033[43;30m" if USE_COLOR else ""
BG_RED = "\033[41;37m" if USE_COLOR else ""
BG_BLUE = "\033[44;37m" if USE_COLOR else ""


def style(text: Any, *codes: str) -> str:
    """Wrap text with specified ANSI codes if color is enabled."""
    if not USE_COLOR:
        return str(text)
    prefix = "".join(codes)
    return f"{prefix}{text}{RESET}"


def bold(text: Any) -> str:
    return style(text, BOLD)


def dim(text: Any) -> str:
    return style(text, DIM)


def cyan(text: Any) -> str:
    return style(text, CYAN)


def green(text: Any) -> str:
    return style(text, GREEN)


def yellow(text: Any) -> str:
    return style(text, YELLOW)


def red(text: Any) -> str:
    return style(text, RED)


def magenta(text: Any) -> str:
    return style(text, MAGENTA)


def blue(text: Any) -> str:
    return style(text, BLUE)


def gray(text: Any) -> str:
    return style(text, GRAY)


def white(text: Any) -> str:
    return style(text, WHITE)


def underline(text: Any) -> str:
    return style(text, UNDERLINE)


def italic(text: Any) -> str:
    return style(text, ITALIC)


def status_badge(status: str, exit_code: int) -> str:
    """Return a stylized, colored status badge."""
    clean = status.upper().strip()
    if exit_code == 0 or clean in ("COMPLETED", "APPROVED", "CLEAN"):
        return style(f" ✔ {clean} ", BOLD, GREEN)
    elif exit_code == 10 or "PENDING" in clean or "REVIEW" in clean:
        return style(f" ⚡ {clean} (EXIT {exit_code}) ", BOLD, YELLOW)
    elif exit_code == 20 or "BLOCKED" in clean or "REJECTED" in clean:
        return style(f" ✖ {clean} (EXIT {exit_code}) ", BOLD, RED)
    elif clean in ("ERROR", "FAILED"):
        return style(f" ✖ {clean} ", BOLD, RED)
    return style(f" ● {clean} ", BOLD, CYAN)


def severity_badge(severity: Any) -> str:
    """Return a colored severity pill."""
    sev = str(severity).upper()
    if "CRITICAL" in sev:
        return style(" CRITICAL ", BOLD, RED)
    elif "HIGH" in sev:
        return style(" HIGH ", BOLD, YELLOW)
    elif "MEDIUM" in sev:
        return style(" MEDIUM ", BOLD, CYAN)
    elif "LOW" in sev:
        return style(" LOW ", BOLD, GRAY)
    return style(f" {sev} ", BOLD, WHITE)


def action_badge(action: str) -> str:
    """Return colored action badge (e.g. [BUMP], [ROTATE])."""
    act = action.upper().strip()
    if act == "ROTATE":
        return style(" ROTATE ", BOLD, YELLOW)
    elif act == "BUMP":
        return style(" BUMP ", BOLD, GREEN)
    elif act == "PIN":
        return style(" PIN ", BOLD, BLUE)
    elif act == "REMOVE":
        return style(" REMOVE ", BOLD, RED)
    return style(f" {act} ", BOLD, CYAN)


def box_header(title: str, width: int = 70) -> str:
    """Render a rounded Unicode boxed header."""
    inner_width = width - 4
    title_visible = title
    pad = inner_width - len(title_visible)
    left_pad = " " * (pad // 2)
    right_pad = " " * (pad - len(left_pad))

    top = f"{CYAN}╭{'─' * (width - 2)}╮{RESET}"
    mid = f"{CYAN}│{RESET} {left_pad}{BOLD}{WHITE}{title}{RESET}{right_pad} {CYAN}│{RESET}"
    bot = f"{CYAN}╰{'─' * (width - 2)}╯{RESET}"
    return f"{top}\n{mid}\n{bot}"


def section_divider(title: str, width: int = 70, color_fn: Any = cyan) -> str:
    """Render a styled section divider."""
    prefix = f"{title} "
    remaining = max(0, width - len(prefix) - 2)
    fill = "─" * remaining
    return f"\n{color_fn(f'── {prefix}{fill}')}"


def stat_card(label: str, value: Any, color_fn: Any = cyan) -> str:
    """Format an inline stat card."""
    return f"{gray(label + ':')} {color_fn(bold(str(value)))}"
