"""
Charts over EMB3D threat data (see main.get_emb3d_threats).

Palette and mark specs follow the dataviz skill's validated defaults
(references/palette.md, marks-and-anatomy.md): a single-series bar chart gets
one color for every bar (color encodes identity, not decoration); a
multi-series breakdown gets the fixed categorical hue order with a legend.
"""

from __future__ import annotations
from collections import Counter
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from glitched.paths import data_home
from glitched.queries import get_emb3d_threats
from glitched.queries import (
    get_known_exploitable_by_category,
    get_known_exploitable_mitigation_depth,
    get_mitigation_depth_by_category,
)

OUT_DIR = data_home() / "charts"

# Validated default palette (dataviz skill, references/palette.md), light mode.
BLUE = "#2a78d6"  # sequential / single-series default
CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # slots 1-4, fixed order
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#d9d8d3"  # one-step-off-surface gray, hairline

# EMB3D's four maturity values, ordered by strength of evidence rather than
# alphabetically (proof-of-concept -> observed-in-the-wild technique).
MATURITY_ORDER = [
    "proof of concept",
    "known exploitable weakness",
    "observed adversarial behavior",
    "observed adversarial technique",
]


def _style_axes(ax: plt.Axes) -> None:
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.yaxis.grid(True, color=GRID, linewidth=1)
    ax.set_axisbelow(True)
    ax.tick_params(colors=TEXT_SECONDARY, length=0)
    for label in ax.get_xticklabels() + ax.get_yticklabels():
        label.set_color(TEXT_SECONDARY)


def _rounded_bar(ax: plt.Axes, x: float, height: float, width: float, color: str) -> None:
    """Thin bar, rounded data-end, square at the baseline."""
    ax.add_patch(
        FancyBboxPatch(
            (x - width / 2, 0),
            width,
            height,
            boxstyle=f"round,pad=0,rounding_size={min(0.05, width / 2)}",
            linewidth=0,
            facecolor=color,
        )
    )


def _ranked_bar_chart(counts: dict[str, int], title: str, path: Path, order: list[str] | None) -> Path:
    """Single-series bar chart: one color for every bar, value labeled at the tip."""
    labels = order or [k for k, _ in sorted(counts.items(), key=lambda kv: -kv[1])]
    values = [counts.get(label, 0) for label in labels]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    width = 0.5
    for i, value in enumerate(values):
        _rounded_bar(ax, i, value, width, BLUE)
        ax.text(i, value + max(values) * 0.02, str(value), ha="center", va="bottom",
                 color=TEXT_PRIMARY, fontsize=10)

    ax.set_xlim(-0.6, len(labels) - 0.4)
    ax.set_ylim(0, max(values) * 1.15)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_title(title, color=TEXT_PRIMARY, fontsize=13, loc="left", pad=12)
    _style_axes(ax)

    OUT_DIR.mkdir(exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor="white")
    plt.close(fig)
    return path


def threats_by_category(path: Path = OUT_DIR / "threats_by_category.png") -> Path:
    """EMB3D threat count by category (application/system software, hardware, networking)."""
    threats = get_emb3d_threats()
    counts = Counter(t["category"] for t in threats)
    return _ranked_bar_chart(counts, "EMB3D threats by category", path, order=None)


def threats_by_maturity(path: Path = OUT_DIR / "threats_by_maturity.png") -> Path:
    """EMB3D threat count by maturity, ordered by strength of evidence."""
    threats = get_emb3d_threats()
    counts = Counter(t["maturity"] for t in threats)
    return _ranked_bar_chart(counts, "EMB3D threats by maturity", path, order=MATURITY_ORDER)


def threats_by_category_and_maturity(
    path: Path = OUT_DIR / "threats_by_category_and_maturity.png",
) -> Path:
    """EMB3D threat count by category, broken down by maturity (stacked, one hue per maturity)."""
    threats = get_emb3d_threats()
    categories = sorted(
        {t["category"] for t in threats},
        key=lambda c: -sum(1 for t in threats if t["category"] == c),
    )
    by_category = {c: Counter(t["maturity"] for t in threats if t["category"] == c) for c in categories}

    fig, ax = plt.subplots(figsize=(8, 5))
    width = 0.5
    gap = 0.3  # surface-gap equivalent between stacked segments, in data units
    true_totals = [sum(by_category[c].values()) for c in categories]
    bottoms = [0.0] * len(categories)
    for series_idx, maturity in enumerate(MATURITY_ORDER):
        heights = [by_category[c].get(maturity, 0) for c in categories]
        is_last_segment = [bottoms[i] + heights[i] >= true_totals[i] for i in range(len(categories))]
        color = CATEGORICAL[series_idx]
        for i, (height, bottom) in enumerate(zip(heights, bottoms, strict=True)):
            if height == 0:
                continue
            # Shave the gap off every segment's own top except the topmost one
            # in its stack, so the visible seam never changes the true total.
            drawn_height = height if is_last_segment[i] else max(height - gap, 0)
            ax.bar(i, drawn_height, width=width, bottom=bottom, color=color, linewidth=0)
        bottoms = [b + h for b, h in zip(bottoms, heights, strict=True)]

    ax.set_xlim(-0.6, len(categories) - 0.4)
    ax.set_ylim(0, max(bottoms) * 1.15)
    ax.set_xticks(range(len(categories)))
    ax.set_xticklabels(categories, rotation=15, ha="right")
    ax.set_title("EMB3D threats by category and maturity", color=TEXT_PRIMARY, fontsize=13, loc="left", pad=12)
    _style_axes(ax)

    handles = [plt.Rectangle((0, 0), 1, 1, color=CATEGORICAL[i]) for i in range(len(MATURITY_ORDER))]
    legend = ax.legend(handles, MATURITY_ORDER, frameon=False, loc="upper right")
    for text in legend.get_texts():
        text.set_color(TEXT_SECONDARY)

    OUT_DIR.mkdir(exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor="white")
    plt.close(fig)
    return path


def mitigation_depth_by_category(
    path: Path = OUT_DIR / "mitigation_depth_by_category.png",
) -> Path:
    """
    Average documented mitigations per threat, by category, across all 81
    EMB3D threats. Every threat has >=1 mitigation on record catalogue-wide,
    same as the known-exploitable subset - this chart is about relative
    defense-in-depth between categories, not coverage gaps.
    """
    rows = get_mitigation_depth_by_category()
    values = {row["category"]: round(float(row["avg_mitigations"]), 1) for row in rows}
    order = [row["category"] for row in rows]  # already sorted lowest-depth first
    return _ranked_bar_chart(
        values, "Avg. mitigations per threat (all vulnerabilities)", path, order=order
    )


def known_exploitable_by_category(
    path: Path = OUT_DIR / "known_exploitable_by_category.png",
) -> Path:
    """Known-exploitable-weakness threat count by device category."""
    rows = get_known_exploitable_by_category()
    counts = {row["category"]: row["threat_count"] for row in rows}
    return _ranked_bar_chart(counts, "Known-exploitable threats by category", path, order=None)


def known_exploitable_mitigation_depth(
    path: Path = OUT_DIR / "known_exploitable_mitigation_depth.png",
) -> Path:
    """
    Average documented mitigations per known-exploitable-weakness threat, by
    category. Every one of these threats has >=1 mitigation on record - this
    chart is about how much defense-in-depth exists, not whether any does.
    """
    rows = get_known_exploitable_mitigation_depth()
    values = {row["category"]: round(float(row["avg_mitigations"]), 1) for row in rows}
    order = [row["category"] for row in rows]  # already sorted lowest-depth first
    return _ranked_bar_chart(
        values, "Avg. mitigations per known-exploitable threat", path, order=order
    )


def main() -> None:
    chart_fns = (
        threats_by_category,
        threats_by_maturity,
        threats_by_category_and_maturity,
        mitigation_depth_by_category,
        known_exploitable_by_category,
        known_exploitable_mitigation_depth,
    )
    for chart_fn in chart_fns:
        path = chart_fn()
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
