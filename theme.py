#!/usr/bin/env python3
"""
Vanguard Knight - Visual Theme
==================================
Color palette: dark-tech aesthetic using deep greens, olive, silver-grey,
black and white -- built to feel serious/tactical (like a defense-grade
tool) rather than playful. Every color below is used consistently across
all screens so the interface feels like one cohesive product.
"""

# ---- Core palette ----
BLACK = "#0A0D0A"              # near-black background (slight green tint, not pure black)
DARK_PANEL = "#12160F"         # panel/card background
DARK_GREEN = "#1B3A2B"         # secondary surfaces, borders
MID_GREEN = "#2E6B45"          # inactive elements, secondary buttons
BRIGHT_GREEN = "#4CD97B"       # primary accent -- active/success states, glow color
LIGHT_GREEN = "#9BE8B4"        # highlighted text, hover states
OLIVE = "#6B7A4F"              # tertiary accent, subtle warnings/neutral tags
SILVER_GREY = "#B8C2BA"        # secondary text
WHITE = "#F2F5F0"              # primary text
ALERT_RED = "#FF3B3B"          # threat/critical alerts only -- used sparingly, high contrast
ALERT_RED_GLOW = "#FF6B6B"     # lighter red for pulse/glow animation peaks
AMBER_WARN = "#E0B94C"         # medium-severity warnings

# ---- Fonts ----
FONT_FAMILY = "Consolas"       # monospace = tactical/technical feel, matches original design intent
FONT_TITLE = (FONT_FAMILY, 30, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 14)
FONT_HEADING = (FONT_FAMILY, 18, "bold")
FONT_BODY = (FONT_FAMILY, 12)
FONT_SMALL = (FONT_FAMILY, 10)
FONT_BUTTON = (FONT_FAMILY, 14, "bold")
FONT_MONO_LOG = ("Consolas", 11)

# ---- Semantic aliases (use these in code so a future re-theme is a one-line change) ----
COLOR_BG = BLACK
COLOR_PANEL = DARK_PANEL
COLOR_BORDER = DARK_GREEN
COLOR_PRIMARY = BRIGHT_GREEN
COLOR_PRIMARY_HOVER = LIGHT_GREEN
COLOR_SECONDARY = MID_GREEN
COLOR_ACCENT = OLIVE
COLOR_TEXT = WHITE
COLOR_TEXT_MUTED = SILVER_GREY
COLOR_DANGER = ALERT_RED
COLOR_DANGER_GLOW = ALERT_RED_GLOW
COLOR_WARNING = AMBER_WARN

# ---- Severity -> color mapping (used consistently everywhere severity is shown) ----
SEVERITY_COLORS = {
    "LOW": MID_GREEN,
    "MEDIUM": AMBER_WARN,
    "HIGH": "#FF8C42",
    "CRITICAL": ALERT_RED,
}

APP_TITLE = "Vanguard Knight"
APP_TAGLINE = "The Immortal Shield Of Your System"
AUTHOR_CREDIT = "Made by Uzan Khan"
SUPPORT_EMAIL = "uzankhan17@gmail.com"

# ---- Logo & Icon paths (place these files in the project root) ----
LOGO_PATH = "logo.png"      # Transparent PNG for UI display (recommended: 80x80 to 200x200)
ICON_PATH = "logo.ico"      # Windows .ico file for window icon and taskbar


def load_logo_ctk_image(size=(64, 64)):
    """
    Returns a CTkImage of the logo for use in labels/buttons, or None if
    the logo file isn't present (callers should fall back to the shield
    emoji in that case, so the UI never breaks just because logo.png is
    missing from a given machine).
    """
    try:
        from PIL import Image
        import customtkinter as ctk
        img = Image.open(LOGO_PATH)
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception:
        return None


def apply_window_icon(window):
    """
    Sets the .ico window/taskbar icon on any Tk/CTk window or Toplevel.
    Safe no-op if logo.ico is missing (e.g. during development) so this
    never crashes the app -- just call this once after creating any window.
    """
    try:
        window.iconbitmap(ICON_PATH)
    except Exception:
        pass
