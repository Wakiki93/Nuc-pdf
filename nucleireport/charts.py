"""Matplotlib chart generation for PDF embedding."""

from __future__ import annotations

import io
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

from .styles import SEVERITY_COLORS


# Matplotlib-compatible hex strings
_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "info": "#6B7280",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def severity_bar_chart(
    severity_counts: dict[str, int],
    width: float = 5.5,
    height: float = 2.5,
) -> bytes:
    """Generate a horizontal bar chart of findings by severity.

    Returns PNG image bytes ready for embedding in a PDF.
    """
    labels = []
    counts = []
    colors = []

    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        labels.append(sev.upper())
        counts.append(count)
        colors.append(_COLORS[sev])

    fig, ax = plt.subplots(figsize=(width, height))
    fig.patch.set_facecolor("white")

    bars = ax.barh(labels, counts, color=colors, height=0.6, edgecolor="white", linewidth=0.5)

    # Value labels on each bar
    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(
                bar.get_width() + 0.3,
                bar.get_y() + bar.get_height() / 2,
                str(count),
                va="center",
                ha="left",
                fontsize=10,
                fontweight="bold",
                color="#334155",
            )

    # Styling
    ax.set_xlim(0, max(counts) * 1.25 if max(counts) > 0 else 1)
    ax.invert_yaxis()  # Critical on top
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.set_xlabel("Number of Findings", fontsize=9, color="#64748B")
    ax.tick_params(axis="y", labelsize=10, colors="#334155")
    ax.tick_params(axis="x", labelsize=8, colors="#94A3B8")

    # Clean up spines
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#E2E8F0")
    ax.spines["left"].set_visible(False)
    ax.grid(axis="x", linestyle="--", alpha=0.3, color="#CBD5E1")

    plt.tight_layout(pad=0.5)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def severity_donut_chart(
    severity_counts: dict[str, int],
    width: float = 3.0,
    height: float = 3.0,
) -> bytes:
    """Generate a donut chart of findings by severity.

    Returns PNG image bytes ready for embedding in a PDF.
    """
    labels = []
    sizes = []
    colors = []

    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count > 0:
            labels.append(f"{sev.upper()}\n({count})")
            sizes.append(count)
            colors.append(_COLORS[sev])

    if not sizes:
        sizes = [1]
        colors = ["#E2E8F0"]
        labels = ["NO FINDINGS"]

    fig, ax = plt.subplots(figsize=(width, height))
    fig.patch.set_facecolor("white")

    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct=lambda pct: f"{pct:.0f}%" if pct > 5 else "",
        startangle=90,
        pctdistance=0.75,
        wedgeprops=dict(width=0.4, edgecolor="white", linewidth=2),
    )

    for text in texts:
        text.set_fontsize(7)
        text.set_color("#334155")
    for autotext in autotexts:
        autotext.set_fontsize(7)
        autotext.set_color("white")
        autotext.set_fontweight("bold")

    # Center label
    total = sum(sizes)
    ax.text(0, 0, f"{total}\nTotal", ha="center", va="center",
            fontsize=14, fontweight="bold", color="#0F172A")

    plt.tight_layout(pad=0.2)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf.read()
