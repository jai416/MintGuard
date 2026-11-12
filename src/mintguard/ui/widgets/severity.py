"""Severity visual helpers: colored chips, risk gauge and CSS hooks.

One place for the palette so screens and widgets stay consistent.
Colors follow the tokyo-night accent family (the app's theme).
"""

from __future__ import annotations

from rich.text import Text

from mintguard.core.prioritizer import Finding, Severidad, resumen

# Shared palette constants (keep hex here, not scattered across screens).
MUTED = "#565f89"
SOFT = "#a9b1d6"
TEXT = "#c0caf5"
GOOD = "#9ece6a"
BORDER = "#414868"

_ACCENT: dict[str, str] = {
    "INFO": "#565f89",
    "BAJA": "#7aa2f7",
    "MEDIA": "#e0af68",
    "ALTA": "#ff9e64",
    "CRITICA": "#f7768e",
}

_CHIP_STYLES: dict[str, str] = {
    "INFO": f"#1a1b26 on {_ACCENT['INFO']}",
    "BAJA": f"#1a1b26 on {_ACCENT['BAJA']}",
    "MEDIA": f"#1a1b26 on {_ACCENT['MEDIA']}",
    "ALTA": f"#1a1b26 on {_ACCENT['ALTA']}",
    "CRITICA": f"#1a1b26 on {_ACCENT['CRITICA']}",
}

_CSS_CLASS: dict[str, str] = {
    "INFO": "sev-info",
    "BAJA": "sev-baja",
    "MEDIA": "sev-media",
    "ALTA": "sev-alta",
    "CRITICA": "sev-critica",
}


def label(name: str) -> str:
    """Spanish display label (enum names carry no accents on purpose)."""
    return "CRÍTICA" if name == "CRITICA" else name


def accent_color(name: str) -> str:
    return _ACCENT.get(name, MUTED)


def chip(name: str) -> Text:
    """A small colored badge like ` MEDIA `."""
    return Text(f" {label(name)} ", style=_CHIP_STYLES.get(name, f"italic {MUTED}"))


def css_class(name: str) -> str:
    return _CSS_CLASS.get(name, "sev-info")


def worst_severity_name(findings: list[Finding]) -> str | None:
    """Name of the highest severity present, or None when there is nothing."""
    if not findings:
        return None
    return max(findings, key=lambda f: f.severity).severity.name


def risk_gauge(findings: list[Finding]) -> Text:
    """`▰▰▰▱▱ MEDIA` gauge for the global risk, colored by severity."""
    worst = worst_severity_name(findings)
    color = accent_color(worst) if worst else MUTED
    filled = (int(Severidad[worst]) + 1) if worst else 0
    gauge = Text()
    gauge.append("▰" * filled, style=color)
    gauge.append("▱" * (5 - filled), style=MUTED)
    if worst:
        gauge.append(f"  {label(worst)}", style=f"bold {color}")
    else:
        gauge.append("  SIN DATOS", style=MUTED)
    return gauge


def count_line(findings: list[Finding]) -> Text:
    """`● 2 MEDIA  ● 3 BAJA …` compact per-severity counts."""
    counts = resumen(findings)
    line = Text()
    parts: list[tuple[str, str]] = []
    for name in ("CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"):
        count = counts.get(name, 0)
        if count:
            parts.append((f"● {count} {label(name)}", _ACCENT[name]))
    if not parts:
        return Text("—", style=MUTED)
    for index, (chunk, color) in enumerate(parts):
        if index:
            line.append("  ", style=MUTED)
        line.append(chunk, style=color)
    return line
