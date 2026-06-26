"""
ForgeLens Theme
===============
Central color palette, fonts, and style constants for the desktop GUI.
"""

from __future__ import annotations


# ── Color Palette ─────────────────────────────────────────────────────────────

class Colors:
    """Dark forensic theme — deep navy + crimson accent."""

    # Backgrounds
    BG_DARKEST    = "#0d1117"   # Window / root background
    BG_DARK       = "#161b22"   # Sidebar background
    BG_PANEL      = "#1c2333"   # Card / panel background
    BG_SURFACE    = "#21283b"   # Elevated surface (inputs, rows)
    BG_HOVER      = "#2a3350"   # Hover state

    # Accent
    ACCENT        = "#e94560"   # Primary accent (crimson)
    ACCENT_HOVER  = "#ff6b81"   # Accent hover
    ACCENT_DIM    = "#8b2035"   # Accent muted

    # Semantic
    SUCCESS       = "#2ecc71"   # Green
    WARNING       = "#f39c12"   # Amber
    ERROR         = "#e74c3c"   # Red
    INFO          = "#00d2ff"   # Cyan

    # Text
    TEXT_PRIMARY   = "#e6edf3"  # Main text
    TEXT_SECONDARY = "#8b949e"  # Muted text
    TEXT_MUTED     = "#484f58"  # Very dim text
    TEXT_ON_ACCENT = "#ffffff"  # Text on accent backgrounds

    # Borders
    BORDER         = "#30363d"
    BORDER_FOCUS   = "#58a6ff"

    # Status badges
    STATUS_OPEN     = "#58a6ff"
    STATUS_ACTIVE   = "#2ecc71"
    STATUS_CLOSED   = "#8b949e"
    STATUS_CRITICAL = "#e74c3c"

    # Priority
    PRIORITY_LOW      = "#8b949e"
    PRIORITY_MEDIUM   = "#f39c12"
    PRIORITY_HIGH     = "#e94560"
    PRIORITY_CRITICAL = "#e74c3c"


# ── Typography ────────────────────────────────────────────────────────────────

class Fonts:
    """Font configurations (family, size, weight)."""

    FAMILY      = "Segoe UI"
    MONO_FAMILY = "Consolas"

    # Sizes
    TITLE       = (FAMILY, 22, "bold")
    HEADING     = (FAMILY, 16, "bold")
    SUBHEADING  = (FAMILY, 14, "bold")
    BODY        = (FAMILY, 13)
    BODY_BOLD   = (FAMILY, 13, "bold")
    SMALL       = (FAMILY, 11)
    SMALL_BOLD  = (FAMILY, 11, "bold")
    TINY        = (FAMILY, 10)
    MONO        = (MONO_FAMILY, 12)
    MONO_SMALL  = (MONO_FAMILY, 11)


# ── Layout Constants ──────────────────────────────────────────────────────────

class Layout:
    """Spacing, sizing, and layout constants."""

    # Padding
    PAD_XS   = 4
    PAD_SM   = 8
    PAD_MD   = 12
    PAD_LG   = 16
    PAD_XL   = 24
    PAD_XXL  = 32

    # Corner radius
    RADIUS_SM  = 4
    RADIUS_MD  = 8
    RADIUS_LG  = 12

    # Sidebar
    SIDEBAR_WIDTH        = 220
    SIDEBAR_COLLAPSED    = 60

    # Window
    WINDOW_MIN_WIDTH  = 1200
    WINDOW_MIN_HEIGHT = 750

    # Table row height
    ROW_HEIGHT = 36

    # Card
    CARD_PAD = 16

    # Progress bar
    PROGRESS_HEIGHT = 16

    # Border
    BORDER_WIDTH = 1


# ── Icon Map (Unicode symbols) ────────────────────────────────────────────────

class Icons:
    """Unicode symbols used as pseudo-icons in the sidebar and buttons."""

    DASHBOARD    = "⊞"
    DEVICES      = "⛁"
    CASES        = "🗂"
    EVIDENCE     = "🔒"
    ACQUISITION  = "⬇"
    HASHING      = "⧫"
    MEMORY       = "🧠"
    DFIR         = "🛡"
    SETTINGS     = "⚙"
    SEARCH       = "🔍"
    ADD          = "＋"
    REFRESH      = "↻"
    PLAY         = "▶"
    PAUSE        = "⏸"
    STOP         = "■"
    COPY         = "⧉"
    CHECK        = "✔"
    CROSS        = "✘"
    WARNING      = "⚠"
    FOLDER       = "📁"
    FILE         = "📄"
    SHIELD       = "🛡"
    CLOCK        = "⏱"
    USER         = "👤"
    LINK         = "🔗"
    TAG          = "🏷"
    CHART        = "📊"
