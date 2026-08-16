#!/usr/bin/env python3
"""
Vanguard Knight - Visual Theme
==================================
Color palette: dark-tech aesthetic using deep greens, olive, silver-grey,
black and white -- built to feel serious/tactical (like a defense-grade
tool) rather than playful. Every color below is used consistently across
all screens so the interface feels like one cohesive product.
"""

# ---- Core palette (per exact spec) ----
BLACK = "#0D1A15"               # deep greenish-black background
DARK_PANEL = "#0F1C16"          # panel/card background -- close to BLACK, panels
                                 # read as "the same terminal surface", not separate cards
DARK_GREEN = "#12261C"          # secondary surfaces, borders
MID_GREEN = "#1E5C3A"           # inactive elements, secondary buttons
BRIGHT_GREEN = "#00FF41"        # TERMINAL GREEN -- primary accent, all text/borders
LIGHT_GREEN = "#6FFFA8"         # highlighted text, hover states
OLIVE = "#4A6B3F"                # tertiary accent, subtle neutral tags
SILVER_GREY = "#7FBF97"          # secondary/muted text -- kept green-tinted, not grey,
                                  # to stay inside the terminal-green palette rather
                                  # than reading as a "generic app" muted grey
WHITE = "#D6FFE0"                 # primary text -- very light green-white, not pure
                                   # white, so it still feels like a green phosphor screen
ALERT_RED = "#FF0000"             # pure red -- ONLY for errors/critical alerts, used
                                   # sparingly per spec, never as a decorative color
ALERT_RED_GLOW = "#FF4D4D"
AMBER_WARN = "#FFFF00"            # pure bright yellow -- ONLY for warnings, same rule

# ---- Fonts ----
# Per the requested aesthetic, these are the preferred fonts in priority
# order. IMPORTANT: VT323, Share Tech Mono, and Fira Code are NOT
# pre-installed on a stock Windows machine (they're Google Fonts) -- if
# they aren't installed, Tkinter would silently substitute a default font
# and lose the intended look. _pick_available_font() checks what's
# actually installed and picks the best real match, falling back to
# Consolas/Courier New (both guaranteed present on every Windows install)
# so the app never looks broken even without the fancy fonts installed.
#
# To get the EXACT intended look, install one of these (free, ~5 seconds):
#   VT323: https://fonts.google.com/specimen/VT323
#   Share Tech Mono: https://fonts.google.com/specimen/Share+Tech+Mono
#   Fira Code: https://fonts.google.com/specimen/Fira+Code
# Download -> right-click the .ttf -> "Install for all users" -> restart the app.

def _pick_available_font():
    try:
        import tkinter as tk
        import tkinter.font as tkfont

        # tkinter.font.families() requires a Tk instance to exist. If the
        # app hasn't created its main window yet (very likely, since
        # theme.py is imported before any window), spin up a temporary
        # hidden one just for this query, then destroy it -- this way the
        # check works correctly regardless of import order.
        temp_root = None
        if tk._default_root is None:
            temp_root = tk.Tk()
            temp_root.withdraw()

        available = set(tkfont.families())

        if temp_root is not None:
            temp_root.destroy()

        preference_order = ["VT323", "Share Tech Mono", "Fira Code", "Consolas", "Courier New"]
        for f in preference_order:
            if f in available:
                return f
        return "Courier New"  # absolute last resort, present on all Windows
    except Exception:
        return "Consolas"


FONT_FAMILY = _pick_available_font()
FONT_TITLE = (FONT_FAMILY, 32, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 14)
FONT_HEADING = (FONT_FAMILY, 18, "bold")
FONT_BODY = (FONT_FAMILY, 13)
FONT_SMALL = (FONT_FAMILY, 11)
FONT_BUTTON = (FONT_FAMILY, 14, "bold")
FONT_MONO_LOG = (FONT_FAMILY, 12)

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
