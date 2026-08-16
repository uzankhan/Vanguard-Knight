#!/usr/bin/env python3
"""
Vanguard Knight - Hacker-Vibe Visual Effects
=================================================
Reusable Canvas-based effects that give the interface a "terminal/HUD"
feel instead of a generic app look: matrix-style falling characters,
HUD corner brackets on panels, a scanning sweep line, and occasional
text glitch flicker.

All effects are pure Tkinter Canvas drawing (no external animation
libraries) using the same .after()-loop pattern as PulsingGlowButton in
gui_app.py, so they're lightweight and don't need GPU/video support.
"""

import random
import string
import math
from tkinter import Canvas

from theme import COLOR_BG, COLOR_PRIMARY, COLOR_PANEL, COLOR_BORDER, FONT_FAMILY

MATRIX_CHARS = string.ascii_uppercase + string.digits + "アイウエオカキクケコ"


class MatrixRainCanvas(Canvas):
    """
    Subtle animated falling-character background, matrix-style. Designed
    to sit behind other content at low opacity-equivalent brightness (dim
    green) so it reads as ambient texture, not a distraction -- foreground
    widgets placed on top of it (via a parent frame's pack geometry) stay
    fully readable.
    """

    def __init__(self, parent, width=300, height=400, density=14,
                 speed=1, dim=True, bg_color=None, **kwargs):
        bg_color = bg_color or COLOR_BG
        super().__init__(parent, width=width, height=height, bg=bg_color,
                         highlightthickness=0, **kwargs)
        self.canvas_width = width
        self.canvas_height = height
        self.font_size = 13
        self.dim = dim
        self.speed = speed

        col_width = self.font_size + 2
        self.num_columns = max(1, width // col_width)
        # Each column: current y position (in px) and its own fall speed/reset
        self.columns = [
            {'y': random.randint(-height, 0), 'speed': random.uniform(0.6, 1.6) * speed,
             'chars': self._random_chars(20)}
            for _ in range(self.num_columns)
        ]
        self._running = True
        self._animate()

    def _random_chars(self, n):
        return [random.choice(MATRIX_CHARS) for _ in range(n)]

    def _animate(self):
        if not self._running:
            return
        self.delete("all")
        col_width = self.canvas_width / max(1, self.num_columns)

        for i, col in enumerate(self.columns):
            x = i * col_width + col_width / 2
            # Draw a short vertical trail of characters, brightest at the
            # leading (bottom) character, fading upward -- classic matrix-
            # rain look, done with discrete brightness steps since Tkinter
            # canvas text doesn't support true alpha blending.
            trail_len = 8
            for t in range(trail_len):
                char_y = col['y'] - (t * (self.font_size + 3))
                if -20 < char_y < self.canvas_height + 20:
                    brightness = max(0, 1 - (t / trail_len))
                    color = self._green_shade(brightness)
                    ch = col['chars'][t % len(col['chars'])]
                    self.create_text(x, char_y, text=ch, fill=color,
                                     font=(FONT_FAMILY, self.font_size))

            col['y'] += col['speed'] * (2 if not self.dim else 1.4)
            if col['y'] - (trail_len * (self.font_size + 3)) > self.canvas_height:
                col['y'] = random.randint(-100, 0)
                col['chars'] = self._random_chars(20)
                col['speed'] = random.uniform(0.6, 1.6) * self.speed
            # Occasionally mutate a character mid-fall for a "glitching" look
            if random.random() < 0.05:
                idx = random.randint(0, len(col['chars']) - 1)
                col['chars'][idx] = random.choice(MATRIX_CHARS)

        self.after(70, self._animate)

    def _green_shade(self, brightness: float) -> str:
        # Interpolates from near-black up to bright green based on
        # brightness (0..1) -- dim mode caps the max brightness so it
        # reads as background texture rather than foreground content.
        max_g = 180 if self.dim else 255
        g = int(max_g * brightness)
        r = int(g * 0.15)
        b = int(g * 0.35)
        return f"#{r:02x}{g:02x}{b:02x}"

    def stop(self):
        self._running = False


def draw_hud_corners(canvas: Canvas, x: int, y: int, w: int, h: int,
                     color: str = COLOR_PRIMARY, length: int = 18, width: int = 2,
                     tag: str = "hud_corners"):
    """
    Draws four L-shaped corner brackets around a rectangle region -- the
    classic sci-fi/HUD "targeting frame" look, used instead of a plain
    solid border on panels to read as tactical/terminal UI rather than a
    generic app card.
    """
    canvas.delete(tag)
    corners = [
        # (corner_x, corner_y, dx, dy) -- dx/dy indicate which direction
        # each leg of the L extends from the corner point.
        (x, y, 1, 1),                    # top-left
        (x + w, y, -1, 1),                # top-right
        (x, y + h, 1, -1),                 # bottom-left
        (x + w, y + h, -1, -1),             # bottom-right
    ]
    for cx, cy, dx, dy in corners:
        canvas.create_line(cx, cy, cx + dx * length, cy, fill=color, width=width, tags=tag)
        canvas.create_line(cx, cy, cx, cy + dy * length, fill=color, width=width, tags=tag)


class HUDPanel(Canvas):
    """
    A drop-in replacement 'panel background' with HUD corner-bracket
    styling and a subtle animated scan-line that sweeps top-to-bottom on
    a slow loop. Place widgets INSIDE a transparent frame layered on top
    of this canvas (via .place with matching geometry), or use this as a
    standalone decorative border behind an existing CTkFrame.
    """

    def __init__(self, parent, width=300, height=200, border_color=COLOR_PRIMARY,
                 fill_color=COLOR_PANEL, scanline=True, **kwargs):
        super().__init__(parent, width=width, height=height, bg=COLOR_BG,
                         highlightthickness=0, **kwargs)
        self.panel_w = width
        self.panel_h = height
        self.border_color = border_color
        self.fill_color = fill_color
        self.scanline_enabled = scanline
        self._scanline_y = 0
        self._running = True
        self._draw_static()
        if scanline:
            self._animate_scanline()

    def _draw_static(self):
        pad = 3
        self.create_rectangle(pad, pad, self.panel_w - pad, self.panel_h - pad,
                              fill=self.fill_color, outline=self.border_color, width=1)
        draw_hud_corners(self, pad, pad, self.panel_w - pad * 2, self.panel_h - pad * 2,
                         color=self.border_color, length=16)

    def _animate_scanline(self):
        if not self._running:
            return
        self.delete("scanline")
        self.create_line(4, self._scanline_y, self.panel_w - 4, self._scanline_y,
                         fill=self.border_color, width=1, tags="scanline")
        self._scanline_y = (self._scanline_y + 2) % self.panel_h
        self.after(50, self._animate_scanline)

    def stop(self):
        self._running = False


class HUDCutPanel:
    """
    A panel with ANGLED (chamfered) corners instead of rounded ones,
    matching the reference HUD image -- plus an optional bracket-style
    title like "[ SHIELD CONTROL ]" burned into the top edge, and small
    circuit-trace tick marks near the corners for extra tactical detail.

    Usage: create one of these, then pack/place normal widgets into
    `.content` (a plain frame) as the actual panel body.
    """

    def __init__(self, parent, width=320, height=400, title=None,
                 corner_cut=18, border_color=None, fill_color=None):
        import customtkinter as ctk
        self.border_color = border_color or COLOR_PRIMARY
        self.fill_color = fill_color or COLOR_PANEL
        self.corner_cut = corner_cut
        self.panel_w = width
        self.panel_h = height

        # Outer wrapper -- plain transparent CTkFrame purely so this whole
        # thing behaves like one widget for pack()/place() purposes.
        self.outer = ctk.CTkFrame(parent, fg_color="transparent", width=width, height=height)
        self.outer.pack_propagate(False)

        # IMPORTANT: CustomTkinter frames can have fg_color="transparent",
        # which is a CTk-specific pseudo-value -- a raw Tkinter Canvas
        # (which this is) doesn't understand that string and throws
        # TclError: unknown color name "transparent". We need a REAL
        # color to use as the canvas background, so we walk up to find
        # one, falling back to the theme's background color if nothing
        # concrete is found.
        bg_for_canvas = COLOR_BG
        try:
            parent_color = parent.cget("fg_color")
            if parent_color and parent_color != "transparent":
                bg_for_canvas = parent_color
        except Exception:
            pass

        self.canvas = Canvas(self.outer, width=width, height=height,
                             bg=bg_for_canvas, highlightthickness=0)
        self.canvas.place(x=0, y=0)
        self._draw_shape(title)

        title_offset = 34 if title else 14
        content_w = max(10, width - (corner_cut + 6) * 2)
        content_h = max(10, height - title_offset - corner_cut - 6)
        self.content = ctk.CTkFrame(self.outer, fg_color="transparent",
                                    width=content_w, height=content_h)
        self.content.place(x=corner_cut + 6, y=title_offset)
        self.content.pack_propagate(False)

    def _draw_shape(self, title):
        c = self.corner_cut
        w, h = self.panel_w, self.panel_h
        points = [c, 0, w - c, 0, w, c, w, h - c, w - c, h, c, h, 0, h - c, 0, c]
        self.canvas.create_polygon(points, fill=self.fill_color,
                                   outline=self.border_color, width=2)

        if title:
            title_text = f"[ {title.upper()} ]"
            self.canvas.create_text(c + 12, 17, text=title_text, fill=self.border_color,
                                    font=(FONT_FAMILY, 12, "bold"), anchor="w")
            # underline the title area to visually separate it from content
            self.canvas.create_line(c, 30, w - c, 30, fill=self.border_color, width=1)

    def pack(self, **kwargs):
        self.outer.pack(**kwargs)

    def place(self, **kwargs):
        self.outer.place(**kwargs)


class BlinkingCursor:
    """
    A blinking `_` (or block `█`) cursor appended to a label, terminal-
    prompt style. Toggles visibility on a fixed interval.
    """

    def __init__(self, label_widget, base_text: str = "", char: str = "_",
                 interval_ms: int = 500, color=None):
        self.label = label_widget
        self.base_text = base_text
        self.char = char
        self.interval_ms = interval_ms
        self.color = color or COLOR_PRIMARY
        self._visible = True
        self._running = True
        self._tick()

    def set_base_text(self, text: str):
        self.base_text = text

    def _tick(self):
        if not self._running:
            return
        suffix = self.char if self._visible else " "
        try:
            self.label.configure(text=self.base_text + suffix)
        except Exception:
            pass
        self._visible = not self._visible
        self.label.after(self.interval_ms, self._tick)

    def stop(self):
        self._running = False


class TypewriterTextbox:
    """
    Wraps a CTkTextbox so that new lines appended via `.append_line()` are
    revealed character-by-character (typewriter effect) instead of
    appearing instantly -- reads as "the system is actively processing/
    printing", matching the requested terminal aesthetic. Falls back to
    instant insertion if the queue of pending lines grows too large (e.g.
    a burst of many log lines at once), so heavy activity never causes lag.
    """

    def __init__(self, textbox_widget, chars_per_tick: int = 2, tick_ms: int = 12,
                 max_queue_before_instant: int = 5):
        self.textbox = textbox_widget
        self.chars_per_tick = chars_per_tick
        self.tick_ms = tick_ms
        self.max_queue_before_instant = max_queue_before_instant
        self._pending_lines = []
        self._typing = False

    def append_line(self, text: str):
        self._pending_lines.append(text)
        if len(self._pending_lines) > self.max_queue_before_instant:
            # Too much backlog -- flush instantly so the UI doesn't lag
            # behind real events during a burst.
            while self._pending_lines:
                line = self._pending_lines.pop(0)
                self.textbox.insert("end", line + "\n")
            self.textbox.see("end")
            return
        if not self._typing:
            self._type_next_line()

    def _type_next_line(self):
        if not self._pending_lines:
            self._typing = False
            return
        self._typing = True
        line = self._pending_lines.pop(0)
        self._type_chars(line, 0)

    def _type_chars(self, line: str, pos: int):
        if pos == 0:
            self.textbox.insert("end", "")
        end_pos = min(len(line), pos + self.chars_per_tick)
        chunk = line[pos:end_pos]
        self.textbox.insert("end", chunk)
        self.textbox.see("end")
        if end_pos < len(line):
            self.textbox.after(self.tick_ms, lambda: self._type_chars(line, end_pos))
        else:
            self.textbox.insert("end", "\n")
            self.textbox.see("end")
            self.textbox.after(20, self._type_next_line)


class GlitchLabel:
    """
    Wraps an existing CTkLabel to occasionally 'glitch' its text -- briefly
    substituting random characters before snapping back to the real text.
    Purely cosmetic flavor for titles/headers to read as a terminal/hacker
    interface rather than a static app label.
    """

    def __init__(self, label_widget, original_text: str, glitch_chance: float = 0.003):
        self.label = label_widget
        self.original_text = original_text
        self.glitch_chance = glitch_chance
        self._running = True
        self._tick()

    def _tick(self):
        if not self._running:
            return
        if random.random() < self.glitch_chance:
            glitched = self._glitch_text(self.original_text)
            try:
                self.label.configure(text=glitched)
                self.label.after(80, self._restore)
            except Exception:
                pass
        self.label.after(120, self._tick)

    def _restore(self):
        try:
            self.label.configure(text=self.original_text)
        except Exception:
            pass

    def _glitch_text(self, text: str) -> str:
        chars = list(text)
        num_glitches = random.randint(1, max(1, len(chars) // 3))
        for _ in range(num_glitches):
            idx = random.randint(0, len(chars) - 1)
            if chars[idx] != ' ':
                chars[idx] = random.choice(MATRIX_CHARS)
        return ''.join(chars)

    def stop(self):
        self._running = False


if __name__ == "__main__":
    import customtkinter as ctk

    root = ctk.CTk()
    root.geometry("500x500")
    root.configure(fg_color=COLOR_BG)

    print("=" * 70)
    print("Structural test: creating all hacker_fx components without error")
    print("=" * 70)

    matrix = MatrixRainCanvas(root, width=200, height=200)
    matrix.place(x=10, y=10)
    print("✓ MatrixRainCanvas created")

    hud = HUDPanel(root, width=250, height=150)
    hud.place(x=220, y=10)
    print("✓ HUDPanel with corner brackets + scanline created")

    label = ctk.CTkLabel(root, text="VANGUARD KNIGHT", font=(FONT_FAMILY, 20))
    label.place(x=10, y=250)
    glitch = GlitchLabel(label, "VANGUARD KNIGHT", glitch_chance=0.5)
    print("✓ GlitchLabel wrapping a CTkLabel created")

    def finish():
        matrix.stop()
        hud.stop()
        glitch.stop()
        print("\n✓ All components stopped cleanly (no crash on teardown)")
        root.quit()

    root.after(1000, finish)
    root.mainloop()
    print("Diagnostic complete")
