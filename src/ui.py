"""Presentation layer for the SignalTrail dashboard.

Everything about how the dashboard *looks* lives here, and nothing about what
it means. The dashboard module composes pages out of these helpers; it does
not write colours, CSS or markup of its own.

The reason for the split is drift. A console that grows a hex code here and a
``<span style=...>`` there ends up with four shades of "high severity" and no
way to change any of them. So there is exactly one palette, one stylesheet,
one chart theme, and one function per repeated piece of markup.

Three rules hold throughout:

* **Severity is never colour alone.** Every badge carries its label as text,
  every chart axis names the level, and tables keep the severity word.
* **Every value rendered into HTML is escaped.** The markup here is built from
  database contents; ``_esc`` is not optional decoration.
* **Nothing here queries anything.** These functions take data and return or
  write markup, which keeps them testable without a browser or a database.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence

import pandas as pd
import streamlit as st

from . import schemas

# --------------------------------------------------------------------------
# Design tokens
# --------------------------------------------------------------------------
#
# The single source of truth for colour in SignalTrail. These values are
# mirrored into .streamlit/config.toml so that Streamlit's own widgets
# (dataframes, selects, buttons) sit on the same palette as the custom markup
# below; tests/test_dashboard.py asserts that the two stay in step.

PALETTE: dict[str, str] = {
    # Surfaces, darkest first.
    "bg": "#0e1116",
    "panel": "#151a21",
    "panel_alt": "#1b212b",
    "border": "#262d38",
    "border_strong": "#333c4a",
    # Text, in descending prominence. All three clear 4.5:1 on `panel`.
    "text": "#e6e9ee",
    "text_muted": "#9aa4b2",
    "text_faint": "#7d8796",
    # The one non-severity accent, used for selection and the activity chart.
    "accent": "#5b8fc9",
    "accent_text": "#8fb7e2",
    "ok": "#4f9d69",
    # Severity. The only colours in the console that carry meaning.
    "info": "#7f8c9b",
    "low": "#5b8fc9",
    "medium": "#d9a441",
    "high": "#d1663a",
    "critical": "#b23b3b",
}

#: Severity fill colours, used for chart marks and badge accents.
SEVERITY_COLORS: dict[str, str] = {
    schemas.SEVERITY_INFO: PALETTE["info"],
    schemas.SEVERITY_LOW: PALETTE["low"],
    schemas.SEVERITY_MEDIUM: PALETTE["medium"],
    schemas.SEVERITY_HIGH: PALETTE["high"],
    schemas.SEVERITY_CRITICAL: PALETTE["critical"],
}

#: Lightened severity colours for text on a dark panel. The fill colours above
#: are chosen to read as marks against the background; as small text they fall
#: under 4.5:1 contrast, so badges and labels use these instead.
SEVERITY_TEXT_COLORS: dict[str, str] = {
    schemas.SEVERITY_INFO: "#aeb7c2",
    schemas.SEVERITY_LOW: "#8fb7e2",
    schemas.SEVERITY_MEDIUM: "#e6c07a",
    schemas.SEVERITY_HIGH: "#ea8f63",
    schemas.SEVERITY_CRITICAL: "#e77373",
}

#: One timestamp format everywhere, plus a short form for dense rows.
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
TIMESTAMP_COMPACT = "%m-%d %H:%M:%S"
#: The same format in the token syntax Streamlit's column config expects.
TIMESTAMP_COLUMN_FORMAT = "YYYY-MM-DD HH:mm:ss"

FONT_STACK = (
    'ui-sans-serif, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", '
    "Arial, sans-serif"
)
MONO_STACK = 'ui-monospace, "Cascadia Mono", Consolas, "SF Mono", Menlo, monospace'


def severity_color(severity: str) -> str:
    """Fill colour for a severity, falling back to the INFO grey."""
    return SEVERITY_COLORS.get(severity, PALETTE["info"])


def severity_text_color(severity: str) -> str:
    """Readable text colour for a severity on a dark panel."""
    return SEVERITY_TEXT_COLORS.get(severity, PALETTE["text_muted"])


def rgba(hex_color: str, alpha: float) -> str:
    """Convert ``#rrggbb`` to an ``rgba()`` string."""
    value = hex_color.lstrip("#")
    red, green, blue = (int(value[index : index + 2], 16) for index in (0, 2, 4))
    return f"rgba({red},{green},{blue},{alpha})"


def severity_tint(severity: str, alpha: float = 0.14) -> str:
    """A translucent wash of a severity colour, for badge backgrounds."""
    return rgba(severity_color(severity), alpha)


def _slug(value: str) -> str:
    """CSS-safe form of a label."""
    return re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-") or "info"


# --------------------------------------------------------------------------
# Escaping and formatting
# --------------------------------------------------------------------------


def _esc(value) -> str:
    """Escape a value for inclusion in HTML.

    Every helper below builds markup out of database contents - hostnames,
    account names, file paths, rule text. Escaping here rather than at each
    call site is what keeps that safe by default.
    """
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):  # arrays and other non-scalars
        pass
    return html.escape(str(value), quote=True)


def fmt_int(value) -> str:
    """Thousands-separated integer, tolerant of nulls and non-numbers."""
    try:
        if value is None or pd.isna(value):
            return "0"
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return _esc(value)


def fmt_time(value, compact: bool = False) -> str:
    """A timestamp in the project's one format."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    try:
        return pd.Timestamp(value).strftime(
            TIMESTAMP_COMPACT if compact else TIMESTAMP_FORMAT
        )
    except (TypeError, ValueError):
        return str(value)


def fmt_duration(start, end) -> str:
    """Whole-minute duration between two moments, as a short label."""
    try:
        minutes = int((pd.Timestamp(end) - pd.Timestamp(start)).total_seconds() // 60)
    except (TypeError, ValueError):
        return "unknown"
    if minutes < 1:
        return "< 1 min"
    if minutes < 60:
        return f"{minutes} min"
    hours, remainder = divmod(minutes, 60)
    return f"{hours} h {remainder:02d} m"


def _write(markup: str) -> None:
    """Emit a fragment of the console's own markup.

    Two details of Streamlit's renderer are worked around here, once, rather
    than at three dozen call sites.

    Fragments are built on one line because Streamlit runs this through a
    Markdown renderer first, and indented or blank-line-separated HTML comes
    back as a code block.

    The wrapper exists because Streamlit lays a markdown element out one root
    font size shorter than its contents - visible in its own markdown too,
    where paragraph margins absorb it. These fragments are compact and have no
    such slack, so without the wrapper each one is overlapped by whatever
    follows it. The padding restores the missing measure; `.sgt-frag` is the
    only place that number appears.
    """
    st.markdown(
        f'<div class="sgt-frag">{markup}</div>', unsafe_allow_html=True
    )


# --------------------------------------------------------------------------
# Stylesheet
# --------------------------------------------------------------------------


def _css_variables() -> str:
    """Expose the Python palette to CSS, so both sides share one definition."""
    declarations = "".join(
        f"--sgt-{name.replace('_', '-')}:{value};" for name, value in PALETTE.items()
    )
    declarations += f"--sgt-font:{FONT_STACK};--sgt-mono:{MONO_STACK};"
    for severity, color in SEVERITY_COLORS.items():
        declarations += f"--sgt-sev-{_slug(severity)}:{color};"
    for severity, color in SEVERITY_TEXT_COLORS.items():
        declarations += f"--sgt-sev-{_slug(severity)}-text:{color};"
    return ":root{" + declarations + "}"


#: The whole stylesheet, in one place. Streamlit's own class names change
#: between releases, so every rule that touches them is written to degrade
#: into a plain-but-working control rather than an invisible one.
_STYLESHEET = """
/* ---- density: the default page padding costs half a screen height ---- */
[data-testid="stMainBlockContainer"], .block-container{padding-top:3.0rem;padding-bottom:3rem;max-width:1640px;}
[data-testid="stHeader"]{background:transparent;}
[data-testid="stMain"] [data-testid="stVerticalBlock"]{gap:0.3rem;}
hr{margin:0.9rem 0;border-color:var(--sgt-border);}
h1,h2,h3,h4,h5,h6{font-family:var(--sgt-font);letter-spacing:-0.01em;}
code,kbd,pre,.sgt-mono{font-family:var(--sgt-mono);}
/* Streamlit measures a markdown element one root font size short of its
   content; see _write(). This is that measure, given back. */
.sgt-frag{padding-bottom:1rem;}
/* ---- top bar ---- */
.sgt-topbar{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:0 0 10px;border-bottom:1px solid var(--sgt-border);margin:0;}
.sgt-topbar__id{display:flex;flex-direction:column;gap:2px;min-width:0;}
.sgt-topbar__line{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;}
.sgt-topbar__name{font-size:1.08rem;font-weight:650;letter-spacing:0.01em;color:var(--sgt-text);}
.sgt-topbar__sep{color:var(--sgt-border-strong);}
.sgt-topbar__page{font-size:0.8rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:var(--sgt-accent-text);}
.sgt-topbar__sub{font-size:0.78rem;color:var(--sgt-text-faint);}
.sgt-topbar__meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap;}
/* ---- chips ---- */
.sgt-chip{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border:1px solid var(--sgt-border);border-radius:3px;background:var(--sgt-panel);color:var(--sgt-text-muted);font-size:0.72rem;letter-spacing:0.04em;white-space:nowrap;}
.sgt-chip b{color:var(--sgt-text);font-weight:600;}
/* A toned chip keeps its tone for the emphasised part too. */
.sgt-chip--ok b,.sgt-chip--warn b{color:inherit;}
.sgt-chip--mono{font-family:var(--sgt-mono);letter-spacing:0;}
.sgt-chip--ok{color:var(--sgt-ok);border-color:rgba(79,157,105,0.35);}
.sgt-chip--warn{color:var(--sgt-sev-medium-text);border-color:rgba(217,164,65,0.35);}
.sgt-dot{width:7px;height:7px;border-radius:50%;background:var(--sgt-text-faint);flex:0 0 auto;}
.sgt-dot--ok{background:var(--sgt-ok);}
.sgt-dot--warn{background:var(--sgt-sev-medium);}
.sgt-dot--off{background:var(--sgt-text-faint);}
/* ---- section headers ---- */
.sgt-section{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:0;padding:10px 0 5px;border-bottom:1px solid var(--sgt-border);}
.sgt-section__title{font-size:0.76rem;font-weight:650;letter-spacing:0.1em;text-transform:uppercase;color:var(--sgt-text);}
.sgt-section__meta{font-size:0.74rem;color:var(--sgt-text-faint);}
.sgt-note{font-size:0.76rem;color:var(--sgt-text-faint);line-height:1.5;margin:0;padding:1px 0 2px;max-width:120ch;}
/* ---- severity badge: colour plus the word, never colour alone ---- */
.sgt-sev{display:inline-flex;align-items:center;gap:6px;padding:2px 7px 2px 6px;border-radius:2px;font-size:0.68rem;font-weight:650;letter-spacing:0.07em;white-space:nowrap;border:1px solid transparent;}
.sgt-sev::before{content:"";width:3px;height:0.72rem;border-radius:1px;background:currentColor;flex:0 0 auto;}
.sgt-sev--info{color:var(--sgt-sev-info-text);background:rgba(127,140,155,0.14);border-color:rgba(127,140,155,0.30);}
.sgt-sev--low{color:var(--sgt-sev-low-text);background:rgba(91,143,201,0.14);border-color:rgba(91,143,201,0.30);}
.sgt-sev--medium{color:var(--sgt-sev-medium-text);background:rgba(217,164,65,0.14);border-color:rgba(217,164,65,0.30);}
.sgt-sev--high{color:var(--sgt-sev-high-text);background:rgba(209,102,58,0.16);border-color:rgba(209,102,58,0.34);}
.sgt-sev--critical{color:var(--sgt-sev-critical-text);background:rgba(178,59,59,0.18);border-color:rgba(178,59,59,0.40);}
/* ---- KPI cards ---- */
.sgt-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:8px;margin:0;padding:2px 0;}
.sgt-kpi{position:relative;background:var(--sgt-panel);border:1px solid var(--sgt-border);border-radius:3px;padding:9px 11px 10px;min-width:0;overflow:hidden;}
.sgt-kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--sgt-border-strong);}
.sgt-kpi[data-tone="accent"]::before{background:var(--sgt-accent);}
.sgt-kpi[data-tone="ok"]::before{background:var(--sgt-ok);}
.sgt-kpi[data-tone="INFO"]::before{background:var(--sgt-sev-info);}
.sgt-kpi[data-tone="LOW"]::before{background:var(--sgt-sev-low);}
.sgt-kpi[data-tone="MEDIUM"]::before{background:var(--sgt-sev-medium);}
.sgt-kpi[data-tone="HIGH"]::before{background:var(--sgt-sev-high);}
.sgt-kpi[data-tone="CRITICAL"]::before{background:var(--sgt-sev-critical);}
.sgt-kpi__label{font-size:0.68rem;font-weight:600;letter-spacing:0.09em;text-transform:uppercase;color:var(--sgt-text-faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sgt-kpi__value{font-size:1.6rem;font-weight:600;line-height:1.2;color:var(--sgt-text);font-variant-numeric:tabular-nums;overflow:hidden;text-overflow:ellipsis;}
.sgt-kpi__note{font-size:0.71rem;color:var(--sgt-text-faint);line-height:1.35;min-height:0.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
/* ---- fact strip ---- */
.sgt-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:1px;background:var(--sgt-border);border:1px solid var(--sgt-border);border-radius:3px;overflow:hidden;margin:0;}
.sgt-fact{background:var(--sgt-panel);padding:7px 11px;min-width:0;}
.sgt-fact__label{font-size:0.66rem;font-weight:600;letter-spacing:0.09em;text-transform:uppercase;color:var(--sgt-text-faint);}
.sgt-fact__value{font-size:0.92rem;color:var(--sgt-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-variant-numeric:tabular-nums;}
/* ---- scannable rows (recent alerts, related alerts) ---- */
.sgt-rows{border:1px solid var(--sgt-border);border-radius:3px;overflow:hidden;background:var(--sgt-panel);}
.sgt-row{display:grid;grid-template-columns:92px minmax(0,1fr) minmax(0,auto) auto;align-items:center;gap:10px;padding:6px 11px;border-bottom:1px solid var(--sgt-border);font-size:0.8rem;}
.sgt-row:last-child{border-bottom:none;}
.sgt-row:hover{background:var(--sgt-panel-alt);}
.sgt-row__main{color:var(--sgt-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.sgt-row__meta{color:var(--sgt-text-muted);font-family:var(--sgt-mono);font-size:0.73rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.sgt-row__time{color:var(--sgt-text-faint);font-family:var(--sgt-mono);font-size:0.72rem;white-space:nowrap;}
@media (max-width:900px){.sgt-row{grid-template-columns:92px minmax(0,1fr);row-gap:2px;}.sgt-row__meta,.sgt-row__time{grid-column:2;}}
/* ---- indicator cards ---- */
.sgt-inds{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;}
.sgt-ind{background:var(--sgt-panel);border:1px solid var(--sgt-border);border-radius:3px;padding:8px 10px;min-width:0;}
.sgt-ind__title{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:0.67rem;font-weight:650;letter-spacing:0.09em;text-transform:uppercase;color:var(--sgt-text-faint);margin-bottom:5px;}
.sgt-ind__count{color:var(--sgt-text-muted);font-weight:600;letter-spacing:0;}
.sgt-ind__list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:3px;}
.sgt-ind__list li{font-family:var(--sgt-mono);font-size:0.76rem;color:var(--sgt-text);background:var(--sgt-panel-alt);border:1px solid var(--sgt-border);border-radius:2px;padding:2px 6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.sgt-ind__empty{font-size:0.75rem;color:var(--sgt-text-faint);font-style:italic;}
/* ---- incident header and snapshot cards ---- */
.sgt-inchead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0;padding:2px 0 4px;}
.sgt-inchead__id{font-family:var(--sgt-mono);font-size:0.82rem;color:var(--sgt-text-muted);border:1px solid var(--sgt-border);border-radius:2px;padding:2px 7px;background:var(--sgt-panel);}
.sgt-inchead__title{font-size:1.1rem;font-weight:600;color:var(--sgt-text);min-width:0;}
.sgt-inc{background:var(--sgt-panel);border:1px solid var(--sgt-border);border-left:2px solid var(--sgt-border-strong);border-radius:3px;padding:9px 12px;min-width:0;height:100%;}
.sgt-inc[data-sev="LOW"]{border-left-color:var(--sgt-sev-low);}
.sgt-inc[data-sev="MEDIUM"]{border-left-color:var(--sgt-sev-medium);}
.sgt-inc[data-sev="HIGH"]{border-left-color:var(--sgt-sev-high);}
.sgt-inc[data-sev="CRITICAL"]{border-left-color:var(--sgt-sev-critical);}
.sgt-inc__top{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;}
.sgt-inc__id{font-family:var(--sgt-mono);font-size:0.74rem;color:var(--sgt-text-muted);}
.sgt-inc__status{font-size:0.68rem;letter-spacing:0.08em;text-transform:uppercase;color:var(--sgt-text-faint);border:1px solid var(--sgt-border);border-radius:2px;padding:1px 6px;}
.sgt-inc__title{font-size:0.92rem;color:var(--sgt-text);margin-bottom:5px;overflow:hidden;text-overflow:ellipsis;}
.sgt-inc__facts{display:flex;flex-wrap:wrap;gap:3px 14px;font-size:0.75rem;color:var(--sgt-text-muted);}
.sgt-inc__facts b{color:var(--sgt-text-faint);font-weight:600;letter-spacing:0.06em;text-transform:uppercase;font-size:0.66rem;margin-right:5px;}
/* ---- attack sequence ---- */
.sgt-seq{display:flex;align-items:stretch;flex-wrap:wrap;gap:6px;margin:0;}
.sgt-seq__stage{flex:1 1 148px;min-width:0;background:var(--sgt-panel);border:1px solid var(--sgt-border);border-top:2px solid var(--sgt-border-strong);border-radius:3px;padding:7px 10px 8px;}
.sgt-seq__stage[data-sev="LOW"]{border-top-color:var(--sgt-sev-low);}
.sgt-seq__stage[data-sev="MEDIUM"]{border-top-color:var(--sgt-sev-medium);}
.sgt-seq__stage[data-sev="HIGH"]{border-top-color:var(--sgt-sev-high);}
.sgt-seq__stage[data-sev="CRITICAL"]{border-top-color:var(--sgt-sev-critical);}
.sgt-seq__kind{font-size:0.62rem;font-weight:650;letter-spacing:0.11em;text-transform:uppercase;color:var(--sgt-text-faint);}
.sgt-seq__name{font-size:0.85rem;color:var(--sgt-text);line-height:1.3;margin:1px 0 3px;}
.sgt-seq__meta{font-size:0.71rem;color:var(--sgt-text-faint);font-family:var(--sgt-mono);}
.sgt-seq__link{display:flex;align-items:stretch;gap:6px;flex:1 1 168px;min-width:0;}
.sgt-seq__link .sgt-seq__stage{flex:1 1 auto;}
.sgt-seq__arrow{align-self:center;color:var(--sgt-border-strong);font-size:0.95rem;flex:0 0 auto;}
/* ---- timeline ---- */
.sgt-tl{list-style:none;margin:0;padding:0;border:1px solid var(--sgt-border);border-radius:3px;background:var(--sgt-panel);overflow:hidden;}
.sgt-tl__item{display:grid;grid-template-columns:78px 16px minmax(0,1fr);align-items:start;gap:8px;padding:6px 11px;border-bottom:1px solid var(--sgt-border);}
.sgt-tl__item:last-child{border-bottom:none;}
.sgt-tl__item:hover{background:var(--sgt-panel-alt);}
.sgt-tl__time{font-family:var(--sgt-mono);font-size:0.74rem;color:var(--sgt-text-muted);padding-top:1px;white-space:nowrap;}
.sgt-tl__rail{position:relative;align-self:stretch;display:flex;justify-content:center;}
.sgt-tl__rail::before{content:"";position:absolute;top:-7px;bottom:-7px;width:1px;background:var(--sgt-border);}
.sgt-tl__item:first-child .sgt-tl__rail::before{top:9px;}
.sgt-tl__item:last-child .sgt-tl__rail::before{bottom:calc(100% - 9px);}
.sgt-tl__dot{position:relative;margin-top:5px;width:7px;height:7px;border-radius:50%;border:1px solid var(--sgt-border-strong);background:var(--sgt-panel);flex:0 0 auto;}
.sgt-tl__item[data-role="evidence"] .sgt-tl__dot{background:var(--sgt-accent);border-color:var(--sgt-accent);}
.sgt-tl__body{min-width:0;}
.sgt-tl__head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.sgt-tl__type{font-size:0.7rem;font-weight:650;letter-spacing:0.07em;text-transform:uppercase;color:var(--sgt-text-muted);}
.sgt-tl__role{font-size:0.63rem;letter-spacing:0.07em;text-transform:uppercase;color:var(--sgt-text-faint);border:1px solid var(--sgt-border);border-radius:2px;padding:0 5px;}
.sgt-tl__item[data-role="evidence"] .sgt-tl__role{color:var(--sgt-accent-text);border-color:rgba(91,143,201,0.35);}
.sgt-tl__detail{display:block;font-size:0.8rem;color:var(--sgt-text);line-height:1.4;overflow-wrap:anywhere;}
.sgt-tl__host{font-family:var(--sgt-mono);font-size:0.71rem;color:var(--sgt-text-faint);}
/* ---- empty, status and note panels ---- */
.sgt-empty{border:1px dashed var(--sgt-border-strong);border-radius:3px;background:var(--sgt-panel);padding:13px 15px;margin:0;max-width:120ch;}
.sgt-empty__title{font-size:0.9rem;font-weight:600;color:var(--sgt-text);margin-bottom:3px;}
.sgt-empty__body{font-size:0.79rem;color:var(--sgt-text-muted);line-height:1.55;}
.sgt-empty__hints{margin:6px 0 0;padding-left:18px;color:var(--sgt-text-muted);font-size:0.79rem;line-height:1.6;}
.sgt-status{display:flex;align-items:center;gap:12px;flex-wrap:wrap;border:1px solid var(--sgt-border);border-left:2px solid var(--sgt-border-strong);border-radius:3px;background:var(--sgt-panel);padding:9px 13px;}
.sgt-status[data-state="ok"]{border-left-color:var(--sgt-ok);}
.sgt-status[data-state="off"]{border-left-color:var(--sgt-text-faint);}
.sgt-status[data-state="warn"]{border-left-color:var(--sgt-sev-medium);}
.sgt-status__block{display:flex;flex-direction:column;min-width:0;}
.sgt-status__label{font-size:0.65rem;font-weight:650;letter-spacing:0.1em;text-transform:uppercase;color:var(--sgt-text-faint);}
.sgt-status__value{font-size:0.92rem;font-weight:600;color:var(--sgt-text);}
.sgt-status__detail{font-size:0.77rem;color:var(--sgt-text-muted);line-height:1.5;flex:1 1 260px;max-width:105ch;}
/* ---- sidebar ---- */
[data-testid="stSidebar"]{border-right:1px solid var(--sgt-border);}
[data-testid="stSidebar"] [data-testid="stVerticalBlock"]{gap:0.2rem;}
.sgt-brand{display:flex;align-items:center;gap:9px;padding:2px 0 10px;border-bottom:1px solid var(--sgt-border);margin:0;}
.sgt-brand__mark{width:22px;height:22px;border:1px solid var(--sgt-accent);border-radius:3px;display:flex;align-items:center;justify-content:center;font-family:var(--sgt-mono);font-size:0.72rem;font-weight:700;color:var(--sgt-accent-text);background:rgba(91,143,201,0.12);flex:0 0 auto;}
.sgt-brand__text{display:flex;flex-direction:column;line-height:1.25;min-width:0;}
.sgt-brand__name{font-size:0.95rem;font-weight:650;color:var(--sgt-text);letter-spacing:0.01em;}
.sgt-brand__state{display:flex;align-items:center;gap:5px;font-size:0.65rem;letter-spacing:0.08em;text-transform:uppercase;color:var(--sgt-text-faint);}
.sgt-navlabel{font-size:0.62rem;font-weight:650;letter-spacing:0.13em;text-transform:uppercase;color:var(--sgt-text-faint);margin:0;padding:5px 0 1px;}
/* Navigation is a column of buttons, scoped by the st-key- class Streamlit
   puts on any keyed element, so ordinary sidebar buttons keep their own look.
   The current page is the primary button, which is a server-side fact rather
   than a CSS state - if these rules stop matching, the nav still works. */
[class*="st-key-sgtnav-"] button{justify-content:flex-start;text-align:left;font-size:0.84rem;font-weight:500;padding:5px 10px;min-height:0;border-radius:3px;width:100%;}
/* The label sits in a nested flex box of its own, so left-aligning the
   nav row means changing that box rather than the button's text-align. */
[class*="st-key-sgtnav-"] button > div{justify-content:flex-start;text-align:left;width:100%;}
[class*="st-key-sgtnav-"] button p{text-align:left;}
[class*="st-key-sgtnav-"] button[kind="secondary"]{background:transparent;border-color:transparent;color:var(--sgt-text-muted);}
[class*="st-key-sgtnav-"] button[kind="secondary"]:hover{background:var(--sgt-panel-alt);border-color:var(--sgt-border);color:var(--sgt-text);}
[class*="st-key-sgtnav-"] button[kind="primary"]{background:rgba(91,143,201,0.14);border-color:rgba(91,143,201,0.34);color:var(--sgt-text);box-shadow:inset 2px 0 0 var(--sgt-accent);font-weight:600;}
[class*="st-key-sgtnav-"] button[kind="primary"]:hover{background:rgba(91,143,201,0.2);color:var(--sgt-text);}
.sgt-sb{display:flex;flex-direction:column;gap:1px;background:var(--sgt-border);border:1px solid var(--sgt-border);border-radius:3px;overflow:hidden;}
.sgt-sb__row{display:flex;align-items:center;justify-content:space-between;gap:8px;background:var(--sgt-panel);padding:5px 9px;font-size:0.76rem;}
.sgt-sb__key{color:var(--sgt-text-faint);letter-spacing:0.03em;white-space:nowrap;}
.sgt-sb__val{color:var(--sgt-text);font-family:var(--sgt-mono);font-size:0.75rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sgt-sb__foot{font-size:0.7rem;color:var(--sgt-text-faint);line-height:1.5;}
/* ---- Streamlit widget polish ---- */
[data-testid="stMain"] .stButton button[kind="primary"]{background:rgba(91,143,201,0.16);border-color:rgba(91,143,201,0.45);color:var(--sgt-accent-text);font-weight:600;}
[data-testid="stMain"] .stButton button[kind="primary"]:hover{background:rgba(91,143,201,0.26);color:var(--sgt-text);border-color:var(--sgt-accent);}
[data-testid="stMetricValue"]{font-variant-numeric:tabular-nums;}
[data-testid="stDataFrame"]{border-radius:3px;}
[data-testid="stExpander"] summary{font-size:0.82rem;}
[data-testid="stExpander"] details{border-radius:3px;}
[data-testid="stMain"] label p{font-size:0.78rem;color:var(--sgt-text-muted);}
"""


def inject_theme() -> None:
    """Install the stylesheet. Called once per rerun, before anything renders."""
    _write("<style>" + _css_variables() + _STYLESHEET + "</style>")


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------


def severity_badge(severity: str) -> str:
    """Severity as a label chip: a colour *and* the word, never colour alone."""
    label = _esc(severity or schemas.SEVERITY_INFO)
    return f'<span class="sgt-sev sgt-sev--{_slug(severity)}">{label}</span>'


def render_severity_badge(severity: str) -> None:
    """Write a severity badge as its own element."""
    _write(severity_badge(severity))


def chip(text: str, *, tone: str = "", mono: bool = False, title: str = "") -> str:
    """A small bordered label for status and counts."""
    classes = "sgt-chip"
    if tone:
        classes += f" sgt-chip--{_slug(tone)}"
    if mono:
        classes += " sgt-chip--mono"
    attrs = f' title="{_esc(title)}"' if title else ""
    return f'<span class="{classes}"{attrs}>{text}</span>'


def status_dot(state: str = "off") -> str:
    """A small state light: ``ok``, ``warn`` or ``off``."""
    return f'<span class="sgt-dot sgt-dot--{_slug(state)}"></span>'


def render_top_header(
    page: str,
    *,
    subtitle: str = "Security telemetry and investigation",
    meta: Sequence[str] = (),
) -> None:
    """The compact header strip above the main content area."""
    meta_html = "".join(meta)
    _write(
        '<div class="sgt-topbar"><div class="sgt-topbar__id">'
        '<div class="sgt-topbar__line">'
        '<span class="sgt-topbar__name">SignalTrail</span>'
        '<span class="sgt-topbar__sep">/</span>'
        f'<span class="sgt-topbar__page">{_esc(page)}</span></div>'
        f'<div class="sgt-topbar__sub">{_esc(subtitle)}</div></div>'
        f'<div class="sgt-topbar__meta">{meta_html}</div></div>'
    )


def render_section_header(title: str, meta: str = "") -> None:
    """A titled rule that separates one block of the page from the next."""
    meta_html = f'<div class="sgt-section__meta">{_esc(meta)}</div>' if meta else ""
    _write(
        f'<div class="sgt-section"><div class="sgt-section__title">{_esc(title)}</div>'
        f"{meta_html}</div>"
    )


def render_note(text: str) -> None:
    """A quiet line of explanation under a heading or control."""
    _write(f'<div class="sgt-note">{_esc(text)}</div>')


def render_kpi_card(label: str, value, note: str = "", tone: str = "") -> str:
    """Markup for one KPI card: a number, what it counts, and its context."""
    tone_attr = f' data-tone="{_esc(tone)}"' if tone else ""
    note_html = f'<div class="sgt-kpi__note">{_esc(note)}</div>'
    return (
        f'<div class="sgt-kpi"{tone_attr}>'
        f'<div class="sgt-kpi__label">{_esc(label)}</div>'
        f'<div class="sgt-kpi__value" title="{_esc(value)}">{_esc(value)}</div>'
        f"{note_html}</div>"
    )


def render_kpi_row(cards: Sequence[Mapping[str, object]]) -> None:
    """A responsive row of KPI cards.

    A CSS grid rather than Streamlit columns: the cards then reflow to fewer
    per row on a narrow laptop instead of squeezing to unreadable widths.
    """
    if not cards:
        return
    body = "".join(
        render_kpi_card(
            str(card.get("label", "")),
            card.get("value", ""),
            str(card.get("note", "") or ""),
            str(card.get("tone", "") or ""),
        )
        for card in cards
    )
    _write(f'<div class="sgt-kpis">{body}</div>')


def render_fact_strip(facts: Sequence[tuple[str, object]]) -> None:
    """A single-line strip of labelled facts, denser than st.metric."""
    if not facts:
        return
    body = "".join(
        '<div class="sgt-fact">'
        f'<div class="sgt-fact__label">{_esc(label)}</div>'
        f'<div class="sgt-fact__value" title="{_esc(value)}">{_esc(value)}</div>'
        "</div>"
        for label, value in facts
    )
    _write(f'<div class="sgt-facts">{body}</div>')


def render_empty_state(title: str, body: str = "", hints: Sequence[str] = ()) -> None:
    """Say what is not there, and what to try next.

    An empty result is usually a filter that was too narrow, not a fault, so
    the panel names the likely cause rather than reporting a failure.
    """
    parts = [f'<div class="sgt-empty"><div class="sgt-empty__title">{_esc(title)}</div>']
    if body:
        parts.append(f'<div class="sgt-empty__body">{_esc(body)}</div>')
    if hints:
        items = "".join(f"<li>{_esc(hint)}</li>" for hint in hints)
        parts.append(f'<ul class="sgt-empty__hints">{items}</ul>')
    parts.append("</div>")
    _write("".join(parts))


def render_status_panel(
    label: str, value: str, detail: str = "", state: str = "off"
) -> None:
    """A labelled state panel, used for the local model and the database."""
    detail_html = (
        f'<div class="sgt-status__detail">{_esc(detail)}</div>' if detail else ""
    )
    _write(
        f'<div class="sgt-status" data-state="{_slug(state)}">'
        f'{status_dot(state)}<div class="sgt-status__block">'
        f'<span class="sgt-status__label">{_esc(label)}</span>'
        f'<span class="sgt-status__value">{_esc(value)}</span></div>'
        f"{detail_html}</div>"
    )


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------


def render_brand(state: str = "ok", state_text: str = "Local session") -> None:
    """The sidebar wordmark and its status light."""
    _write(
        '<div class="sgt-brand"><div class="sgt-brand__mark">ST</div>'
        '<div class="sgt-brand__text">'
        '<span class="sgt-brand__name">SignalTrail</span>'
        f'<span class="sgt-brand__state">{status_dot(state)}{_esc(state_text)}</span>'
        "</div></div>"
    )


def render_sidebar_stats(rows: Sequence[tuple[str, object]]) -> None:
    """The sidebar's data panel: what is loaded, and over what period."""
    body = "".join(
        '<div class="sgt-sb__row">'
        f'<span class="sgt-sb__key">{_esc(key)}</span>'
        f'<span class="sgt-sb__val" title="{_esc(value)}">{_esc(value)}</span>'
        "</div>"
        for key, value in rows
    )
    _write(f'<div class="sgt-sb">{body}</div>')


def render_sidebar_footer(lines: Sequence[str]) -> None:
    """Quiet closing lines under the sidebar controls."""
    body = "<br>".join(_esc(line) for line in lines)
    _write(f'<div class="sgt-sb__foot">{body}</div>')


def render_nav_label(text: str) -> None:
    _write(f'<div class="sgt-navlabel">{_esc(text)}</div>')


# --------------------------------------------------------------------------
# Lists and records
# --------------------------------------------------------------------------


def render_alert_rows(alerts: pd.DataFrame, limit: int = 8) -> None:
    """Recent alerts as scannable rows: severity, rule, where, when."""
    if alerts.empty:
        render_empty_state(
            "No alerts raised",
            "Nothing in the loaded telemetry matched a detection rule.",
        )
        return

    frame = alerts.sort_values("created_at", ascending=False).head(limit)
    rows = []
    for alert in frame.itertuples(index=False):
        where = f"{alert.host} / {alert.user}"
        rows.append(
            '<div class="sgt-row">'
            f"{severity_badge(alert.severity)}"
            f'<span class="sgt-row__main" title="{_esc(alert.rule_name)}">'
            f"{_esc(alert.rule_name)}</span>"
            f'<span class="sgt-row__meta" title="{_esc(where)}">{_esc(where)}</span>'
            f'<span class="sgt-row__time">{_esc(fmt_time(alert.created_at, compact=True))}'
            "</span></div>"
        )
    _write(f'<div class="sgt-rows">{"".join(rows)}</div>')


def render_indicator_card(title: str, values: Sequence[str], limit: int = 6) -> str:
    """Markup for one indicator group - addresses, domains, processes, files."""
    values = [value for value in values if value]
    count = len(values)
    shown = values[:limit]
    if shown:
        items = "".join(
            f'<li title="{_esc(value)}">{_esc(value)}</li>' for value in shown
        )
        if count > limit:
            items += f'<li class="sgt-ind__empty">+{count - limit} more</li>'
        body = f'<ul class="sgt-ind__list">{items}</ul>'
    else:
        body = '<div class="sgt-ind__empty">none recorded</div>'
    return (
        '<div class="sgt-ind"><div class="sgt-ind__title">'
        f"<span>{_esc(title)}</span><span class='sgt-ind__count'>{count}</span></div>"
        f"{body}</div>"
    )


def render_indicator_grid(
    groups: Mapping[str, Sequence[str]], limit: int = 6, columns: int | None = None
) -> None:
    """A responsive grid of indicator cards.

    The grid picks its own column count from the space available, which is
    right for a wide row of five. Four cards in a narrow column come out three
    and one, so a caller in that position can name the count instead.
    """
    body = "".join(
        render_indicator_card(title, values, limit=limit)
        for title, values in groups.items()
    )
    style = (
        f' style="grid-template-columns:repeat({int(columns)},minmax(0,1fr))"'
        if columns
        else ""
    )
    _write(f'<div class="sgt-inds"{style}>{body}</div>')


def render_record_header(severity: str, identifier: str, title: str) -> None:
    """Severity, identifier and title, in that reading order.

    The order is the one an analyst reads in: how bad, which record, what it
    is. Used for incidents and for the selected alert, which answer the same
    three questions.
    """
    _write(
        '<div class="sgt-inchead">'
        f"{severity_badge(severity)}"
        f'<span class="sgt-inchead__id">{_esc(identifier)}</span>'
        f'<span class="sgt-inchead__title">{_esc(title)}</span>'
        "</div>"
    )


def render_incident_header(incident: Mapping[str, object]) -> None:
    """The header for one incident record."""
    render_record_header(
        str(incident.get("severity", "")),
        str(incident.get("incident_id", "")),
        str(incident.get("title", "")),
    )


def render_incident_card(incident: Mapping[str, object], alert_count: int) -> None:
    """One incident as a compact snapshot card."""
    severity = str(incident.get("severity", ""))
    facts = [
        ("Host", incident.get("host")),
        ("User", incident.get("user")),
        ("Alerts", alert_count),
        ("Evidence", int(incident.get("evidence_count") or 0)),
        ("Duration", fmt_duration(incident.get("start_time"), incident.get("end_time"))),
        ("Started", fmt_time(incident.get("start_time"))),
    ]
    fact_html = "".join(
        f"<span><b>{_esc(label)}</b>{_esc(value)}</span>" for label, value in facts
    )
    _write(
        f'<div class="sgt-inc" data-sev="{_esc(severity)}">'
        f'<div class="sgt-inc__top">{severity_badge(severity)}'
        f'<span class="sgt-inc__id">{_esc(incident.get("incident_id"))}</span>'
        f'<span class="sgt-inc__status">{_esc(incident.get("status"))}</span></div>'
        f'<div class="sgt-inc__title">{_esc(incident.get("title"))}</div>'
        f'<div class="sgt-inc__facts">{fact_html}</div></div>'
    )


def render_timeline(timeline: pd.DataFrame, limit: int = 120) -> None:
    """The incident timeline as a marked sequence rather than a table.

    The ``role`` column is what the rail encodes: a filled marker is an event
    a rule actually fired on, a hollow one is context correlation attached
    because it shares the host, account and window. That distinction is the
    reason this is not simply a sorted dataframe.
    """
    if timeline.empty:
        render_empty_state(
            "No events in this timeline",
            "This incident has no evidence events attached to it.",
        )
        return

    items = []
    for event in timeline.head(limit).itertuples(index=False):
        role = "evidence" if event.role == "evidence" else "context"
        role_label = "rule evidence" if role == "evidence" else "context"
        where = f"{event.host} / {event.user}"
        items.append(
            f'<li class="sgt-tl__item" data-role="{role}">'
            f'<span class="sgt-tl__time">{_esc(fmt_time(event.timestamp)[11:])}</span>'
            '<span class="sgt-tl__rail"><span class="sgt-tl__dot"></span></span>'
            '<span class="sgt-tl__body"><span class="sgt-tl__head">'
            f'<span class="sgt-tl__type">{_esc(event.event_type)}</span>'
            f'<span class="sgt-tl__role">{_esc(role_label)}</span>'
            f'<span class="sgt-tl__host">{_esc(where)}</span></span>'
            f'<span class="sgt-tl__detail">{_esc(event.details)}</span>'
            "</span></li>"
        )
    _write(f'<ol class="sgt-tl">{"".join(items)}</ol>')
    if len(timeline) > limit:
        render_note(
            f"Showing the first {limit} of {len(timeline)} events. "
            "The complete timeline is in the table below."
        )


def render_attack_sequence(stages: Sequence[Mapping[str, object]]) -> None:
    """The observed stages of an incident, in the order they were recorded."""
    if not stages:
        render_empty_state(
            "No sequence to draw",
            "No rule evidence is attached to this incident, so there are no "
            "stages to order.",
        )
        return

    blocks = []
    for index, stage in enumerate(stages):
        card = (
            f'<div class="sgt-seq__stage" data-sev="{_esc(stage.get("severity", ""))}">'
            f'<div class="sgt-seq__kind">{_esc(stage.get("kind", "Observed"))}</div>'
            f'<div class="sgt-seq__name">{_esc(stage.get("name", ""))}</div>'
            f'<div class="sgt-seq__meta">{_esc(stage.get("meta", ""))}</div></div>'
        )
        if index:
            # The arrow travels with the stage it leads into, so a wrapped row
            # never ends with an arrow pointing at nothing.
            card = (
                '<div class="sgt-seq__link">'
                '<span class="sgt-seq__arrow">&rarr;</span>' + card + "</div>"
            )
        blocks.append(card)
    _write(f'<div class="sgt-seq">{"".join(blocks)}</div>')


def style_severity_column(frame: pd.DataFrame, column: str = "Severity"):
    """Tint a table's severity column so levels separate at a glance.

    The cell keeps its word - this adds emphasis to text that already says
    what it means, rather than replacing the label with a colour. Falls back
    to the plain frame if the Styler is unavailable for any reason, because a
    table that renders unstyled is better than one that does not render.
    """
    if frame.empty or column not in frame.columns:
        return frame

    def cell(value) -> str:
        severity = str(value)
        if severity not in SEVERITY_COLORS:
            return ""
        return (
            f"color:{severity_text_color(severity)};"
            f"background-color:{severity_tint(severity, 0.16)};"
            "font-weight:600;"
        )

    try:
        return frame.style.map(cell, subset=[column])
    except Exception:  # noqa: BLE001 - styling is never worth losing a table for
        return frame


# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------


def style_figure(figure, *, height: int = 260, legend: bool = False, ygrid: bool = True):
    """Apply the one chart theme every Plotly figure in the console uses.

    Charts are drawn on the panel colour with a single faint gridline family
    and no chart furniture beyond the axes. Series colours are always passed
    in by the caller from the palette above, so no chart ever invents its own.
    """
    figure.update_layout(
        height=height,
        # Small but not zero: automargin below grows these as labels need it,
        # which is what keeps axis text from being clipped at either end.
        margin=dict(l=6, r=10, t=10, b=6),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT_STACK, size=12, color=PALETTE["text_muted"]),
        showlegend=legend,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.0,
            x=0,
            font=dict(size=11),
            bgcolor="rgba(0,0,0,0)",
        ),
        hoverlabel=dict(
            bgcolor=PALETTE["panel_alt"],
            bordercolor=PALETTE["border_strong"],
            font=dict(family=FONT_STACK, size=12, color=PALETTE["text"]),
        ),
        hovermode="closest",
        bargap=0.28,
    )
    axis = dict(
        showgrid=False,
        zeroline=False,
        automargin=True,
        linecolor=PALETTE["border"],
        tickfont=dict(size=11, color=PALETTE["text_faint"]),
        title_font=dict(size=11, color=PALETTE["text_faint"]),
    )
    figure.update_xaxes(**axis)
    figure.update_yaxes(
        **axis, gridcolor=PALETTE["border"], griddash="dot" if ygrid else None
    )
    if ygrid:
        figure.update_yaxes(showgrid=True)
    return figure


def table_height(rows: int, cap: int = 400, minimum: int = 92) -> int:
    """Height for a table of ``rows`` rows.

    Tall enough that the data does not get its own scrollbar inside an
    already-scrolling page, short enough that a three-row result does not sit
    above a band of empty grid.
    """
    return max(minimum, min(50 + 35 * max(rows, 0), cap))


#: Plotly's modebar is chart furniture an analyst never uses here.
PLOTLY_CONFIG = {"displayModeBar": False, "displaylogo": False}


def plotly_panel(figure, *, key: str | None = None) -> None:
    """Render a figure with the console's chart configuration."""
    st.plotly_chart(
        figure, width="stretch", theme=None, config=PLOTLY_CONFIG, key=key
    )


# --------------------------------------------------------------------------
# Presentation models
# --------------------------------------------------------------------------

#: What each rule contributes to an incident's observed sequence. The wording
#: stays descriptive - these are stages that were *recorded*, not stages of a
#: confirmed attack.
STAGE_NAMES: dict[str, str] = {
    "RULE-001": "Authentication failures",
    "RULE-002": "Encoded PowerShell",
    "RULE-003": "Suspicious DNS lookup",
    "RULE-004": "Watchlisted destination",
    "RULE-005": "File creation after execution",
}


def attack_sequence(
    alerts: pd.DataFrame, evidence: pd.DataFrame
) -> list[dict[str, object]]:
    """Order an incident's observed stages by when their evidence starts.

    Every stage here is something the stored evidence contains: a rule that
    fired, or - called out separately because it changes what an analyst does
    next - a successful authentication inside the incident window. Nothing is
    inferred, and no stage is added because it would complete a familiar
    pattern.
    """
    stages: list[dict[str, object]] = []

    if not alerts.empty:
        for alert in alerts.itertuples(index=False):
            name = STAGE_NAMES.get(alert.rule_id, alert.rule_name)
            count = int(getattr(alert, "evidence_count", 0) or 0)
            stages.append(
                {
                    "name": name,
                    "kind": "Observed",
                    "severity": alert.severity,
                    "time": alert.created_at,
                    "meta": f"{count} event(s) - {fmt_time(alert.created_at)[11:]}",
                }
            )

    if not evidence.empty and "status" in evidence.columns:
        successes = evidence[
            (evidence["event_type"] == schemas.EVENT_TYPE_AUTHENTICATION)
            & (evidence["status"] == schemas.STATUS_SUCCESS)
        ]
        if not successes.empty:
            first = successes.iloc[0]
            stages.append(
                {
                    "name": "Successful login",
                    "kind": "Observed",
                    "severity": schemas.SEVERITY_MEDIUM,
                    "time": first["timestamp"],
                    "meta": (
                        f"{len(successes)} event(s) - "
                        f"{fmt_time(first['timestamp'])[11:]}"
                    ),
                }
            )

    return sorted(stages, key=lambda stage: pd.Timestamp(stage["time"]))


#: The headings the investigation notes are written under, in order. Used to
#: split both model output and the deterministic fallback into panels.
NOTE_HEADINGS = [
    "Incident summary",
    "Observed evidence",
    "Likely sequence",
    "Risk assessment",
    "Recommended investigation steps",
    "Evidence gaps",
]

_HEADING_PATTERN = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:\*\*)?\s*(\d)[.)]\s+([^\n*#]+?)\s*(?:\*\*)?\s*$"
)


def split_notes_sections(text: str) -> list[tuple[str, str]]:
    """Split investigation notes into ``(heading, body)`` pairs.

    Both the deterministic summary and a cooperative model write the same six
    numbered headings, so the notes can be shown as panels instead of one
    wall of text. A model that ignores the format still has to render, so
    anything unrecognised comes back as a single untitled section rather than
    being dropped.
    """
    text = (text or "").strip()
    if not text:
        return []

    sections: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        match = _HEADING_PATTERN.match(line)
        if match and (line.lstrip().startswith("#") or match.group(1) in "123456"):
            heading = match.group(2).strip().rstrip(":")
            # A numbered list item inside a body is not a heading. Only treat
            # it as one when it is marked up as a heading or names a section
            # the prompt asked for.
            is_markdown_heading = line.lstrip().startswith("#")
            is_known = heading.lower() in {h.lower() for h in NOTE_HEADINGS}
            if is_markdown_heading or is_known:
                sections.append((heading, []))
                continue
        if sections:
            sections[-1][1].append(line)
        else:
            sections.append(("", [line]))

    return [(heading, "\n".join(body).strip()) for heading, body in sections]
