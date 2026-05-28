"""
ScanAI Design System — ScanAI-inspired clean, minimal TUI.

Professional terminal UI: bordered tables, minimal color, clean layout.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from rich import box
from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# ══════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE — Minimal, professional
# ══════════════════════════════════════════════════════════════════════

C = {
    # Core (ScanAI Theme)
    "primary":    "bright_cyan",
    "secondary":  "bright_blue",
    "accent":     "bright_green",
    "orange":     "bold orange1",
    "red":        "bold red",
    "cyan":       "bright_cyan",
    "magenta":    "bright_magenta",

    "text":       "white",
    "muted":      "dim white",
    "dim":        "dim white",
    "bg":         "black",

    # Semantic
    "success":    "bright_green",
    "warning":    "bright_yellow",
    "danger":     "bright_red",
    "info":       "bright_cyan",

    # Severity
    "critical":   "bold bright_red",
    "high":       "bold bright_red",
    "medium":     "bold bright_yellow",
    "low":        "bold bright_green",
    "none":       "dim white",
}

# ══════════════════════════════════════════════════════════════════════
#  SEVERITY HELPERS
# ══════════════════════════════════════════════════════════════════════

SEVERITY_MAP = {
    "CRITICAL": {"color": C["critical"], "icon": "👾", "bar": "bright_red"},
    "HIGH":     {"color": C["high"],     "icon": "👾", "bar": "bright_red"},
    "MEDIUM":   {"color": C["medium"],   "icon": "●", "bar": "bright_yellow"},
    "LOW":      {"color": C["low"],      "icon": "●", "bar": "bright_green"},
    "INFO":     {"color": C["none"],     "icon": "○", "bar": "dim"},
}


def severity_badge(level: str) -> str:
    level_upper = level.upper()
    meta = SEVERITY_MAP.get(level_upper, SEVERITY_MAP["INFO"])
    return f"[{meta['color']}]{meta['icon']} {level_upper}[/{meta['color']}]"


def severity_color(level: str) -> str:
    return SEVERITY_MAP.get(level.upper(), SEVERITY_MAP["INFO"])["bar"]


# ══════════════════════════════════════════════════════════════════════
#  RISK GAUGE — Clean bar
# ══════════════════════════════════════════════════════════════════════

def risk_gauge(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    if score < 25:
        color, label = "bright_green", "LOW"
    elif score < 50:
        color, label = "bright_yellow", "MEDIUM"
    elif score < 75:
        color, label = "bright_red", "HIGH"
    else:
        color, label = "bold bright_red", "CRITICAL"

    bar = f"[{color}]{'█' * filled}[/{color}][dim white]{'░' * (width - filled)}[/dim white]"
    return f"{bar} [{color}]{score}% {label}[/{color}]"


# ══════════════════════════════════════════════════════════════════════
#  PANEL — ScanAI style (ROUNDED box, dim border)
# ══════════════════════════════════════════════════════════════════════

class ThemePanel(Panel):
    """ScanAI panel — ScanAI style with ROUNDED borders."""

    def __init__(
        self,
        renderable: Any,
        title: str = "",
        subtitle: str = "",
        border_style: str = "dim",
        padding: Tuple = (0, 1),
        expand: bool = True,
        **kwargs
    ):
        super().__init__(
            renderable,
            title=f" {title} " if title else None,
            subtitle=f" {subtitle} " if subtitle else None,
            border_style=border_style,
            box=box.ROUNDED,
            padding=padding,
            expand=expand,
            **kwargs
        )


def make_panel(
    content: Any,
    title: str = "",
    subtitle: str = "",
    border: str = None,
    border_style: str = None,
    padding: Any = (0, 1),
    expand: bool = True,
    **kwargs
) -> Panel:
    """Create a clean ScanAI-style panel."""
    return ThemePanel(
        content,
        title=title,
        subtitle=subtitle,
        border_style=border or border_style or "dim",
        padding=padding,
        expand=expand,
        **kwargs,
    )


def make_header(text: str, icon: str = "›") -> str:
    """Section header — minimal."""
    return f"\n[bold]{icon} {text}[/bold]"


def make_divider(width: int = 60) -> str:
    return f"[dim]{'─' * width}[/dim]"


# ══════════════════════════════════════════════════════════════════════
#  TABLE — Clean ROUNDED box
# ══════════════════════════════════════════════════════════════════════

def make_table(
    title: str,
    columns: List[Tuple[str, str]],
    border: str = "dim",
    show_lines: bool = False,
    expand: bool = True,
) -> Table:
    table = Table(
        title=f"[bold]{title}[/bold]" if title else None,
        box=box.ROUNDED,
        border_style=border,
        show_lines=show_lines,
        expand=expand,
        header_style="bold",
        padding=(0, 1),
    )
    for header, justify in columns:
        table.add_column(header, justify=justify)
    return table


# ══════════════════════════════════════════════════════════════════════
#  STATUS INDICATORS
# ══════════════════════════════════════════════════════════════════════

def status_dot(active: bool = True) -> str:
    return "[green]●[/green]" if active else "[red]○[/red]"


def flash_badge(label: str, color: str = "cyan") -> str:
    return f"[bold {color}]{label.upper()}[/bold {color}]"


# ══════════════════════════════════════════════════════════════════════
#  SYSTEM STATS (kept for compatibility)
# ══════════════════════════════════════════════════════════════════════

def get_cpu_percent() -> float:
    try:
        with open("/proc/stat") as f:
            fields = f.readline().split()
        idle = int(fields[4])
        total = sum(int(x) for x in fields[1:])
        prev_idle = getattr(get_cpu_percent, "_prev_idle", idle)
        prev_total = getattr(get_cpu_percent, "_prev_total", total)
        diff_idle = idle - prev_idle
        diff_total = total - prev_total
        get_cpu_percent._prev_idle = idle
        get_cpu_percent._prev_total = total
        if diff_total == 0:
            return 0.0
        return round((1.0 - diff_idle / diff_total) * 100, 1)
    except Exception:
        return 0.0


def get_mem_percent() -> Tuple[float, str, str]:
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        info: Dict[str, int] = {}
        for line in lines:
            parts = line.split()
            key = parts[0].rstrip(":")
            info[key] = int(parts[1])
        total = info.get("MemTotal", 1)
        available = info.get("MemAvailable", total)
        used = total - available
        pct = round(used / total * 100, 1)
        return pct, f"{used // 1024}M", f"{total // 1024}M"
    except Exception:
        return 0.0, "?", "?"


from collections import deque
_cpu_history = deque([0.0] * 10, maxlen=10)
_mem_history = deque([0.0] * 10, maxlen=10)

def _get_tower_bar(history: deque, width: int = 10) -> str:
    bars = "  ▂▃▄▅▆▇█"
    out = []
    items = list(history)[-width:]
    for val in items:
        idx = min(8, max(0, int((val / 100.0) * 8)))
        color = "green" if val < 50 else "yellow" if val < 80 else "red"
        out.append(f"[{color}]{bars[idx]}[/{color}]")
    return "".join(out)

def get_cpu_tower(cpu_val: float, width: int = 10) -> str:
    _cpu_history.append(cpu_val)
    return _get_tower_bar(_cpu_history, width)

def get_mem_tower(mem_val: float, width: int = 10) -> str:
    _mem_history.append(mem_val)
    return _get_tower_bar(_mem_history, width)


def system_stats_block() -> str:
    now = datetime.now()
    cpu = get_cpu_percent()
    mem_pct, mem_used, mem_total = get_mem_percent()
    return (
        f"CPU {cpu:.1f}% · MEM {mem_used}/{mem_total} ({mem_pct:.1f}%)\n"
        f"{now.strftime('%a %d %b %Y %H:%M:%S')}"
    )
