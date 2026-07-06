"""
theme.py — W1CK3D SYST3MS theme for the Net Wizard (Tkinter/ttk).

Single source of truth for the app's look. Colour values are taken verbatim
from the W1CK3D SYSTEMS brand design system (``Design-System-Tokens.md`` in the
KALI ASSIST project). Aesthetic: dark cyber/military "terminal" — layered
near-black surfaces, purple neon accent, gold/silver metallic edges, stencil +
monospace type.

Usage from the app:

    import theme
    ...
    self.palette = theme.apply_theme(self)   # self is the root tk.Tk / Toplevel

Then reference colours anywhere as ``theme.C['muted']`` etc.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path
from tkinter import font as tkfont
from tkinter import ttk

# ---------------------------------------------------------------------------
# 1. Colour tokens — verbatim from the SYST3MS design system
# ---------------------------------------------------------------------------
TOKENS: dict[str, str] = {
    # backgrounds (darkest -> lightest)
    "bg_void":    "#030405",
    "bg_base":    "#06080b",
    "bg_inset":   "#07090c",
    "bg_surface": "#0b0e13",
    "bg_raised":  "#11151b",
    "bg_hover":   "#181d25",
    # text
    "text_strong": "#eef1f5",
    "text_body":   "#c2c8d2",
    "text_muted":  "#8b93a1",
    "text_faint":  "#5a626f",
    "text_invert": "#06080b",
    # accent (purple)
    "purple":      "#561593",
    "purple_glow": "#9a3eff",
    "purple_deep": "#320a63",
    # status / category palette
    "secure":        "#0f9446",
    "secure_glow":   "#3df085",
    "warning":       "#ee5a04",
    "warning_glow":  "#ff8a3d",
    "critical":      "#e51f1f",
    "critical_deep": "#7e1212",
    "info":          "#147ec2",
    "info_glow":     "#4fbdf5",
    # metallic edges
    "gold":   "#c5a45a",
    "silver": "#c2c7cf",
    # lines / borders
    "line_faint":  "#1b1f26",
    "line":        "#262c35",
    "line_strong": "#353c47",
}

# ---------------------------------------------------------------------------
# 2. Semantic palette (what the app code references)
#    Short keys keep call-sites readable: theme.C['muted'], theme.C['accent'] ...
# ---------------------------------------------------------------------------
C: dict[str, str] = {
    # surfaces
    "void":       TOKENS["bg_void"],
    "base":       TOKENS["bg_base"],
    "inset":      TOKENS["bg_inset"],
    "surface":    TOKENS["bg_surface"],
    "raised":     TOKENS["bg_raised"],
    "hover":      TOKENS["bg_hover"],
    # text
    "strong":     TOKENS["text_strong"],
    "body":       TOKENS["text_body"],
    "muted":      TOKENS["text_muted"],
    "faint":      TOKENS["text_faint"],
    "invert":     TOKENS["text_invert"],
    # accent
    "accent":     TOKENS["purple"],
    "accent_glow": TOKENS["purple_glow"],
    "accent_deep": TOKENS["purple_deep"],
    # status
    "secure":     TOKENS["secure"],
    "secure_glow": TOKENS["secure_glow"],
    "warning":    TOKENS["warning"],
    "critical":   TOKENS["critical"],
    "info":       TOKENS["info"],
    "gold":       TOKENS["gold"],
    "silver":     TOKENS["silver"],
    # lines
    "line":        TOKENS["line"],
    "line_faint":  TOKENS["line_faint"],
    "line_strong": TOKENS["line_strong"],
}

# Severity ramp (red -> orange -> gold -> blue -> grey), readable on near-black.
# base.py owns the canonical SEVERITY_COLORS used by the analyzer + HTML report;
# this mirror lets the GUI import from one place if desired.
SEVERITY_COLORS: dict[str, str] = {
    "critical": TOKENS["critical"],       # #e51f1f
    "high":     TOKENS["warning"],        # #ee5a04
    "medium":   TOKENS["gold"],           # #c5a45a
    "low":      TOKENS["info"],           # #147ec2
    "info":     TOKENS["text_muted"],     # #8b93a1
}

# ---------------------------------------------------------------------------
# 3. Fonts — bundled Google Fonts (assets/fonts). Registration is best-effort;
#    everything degrades gracefully to sane system fallbacks.
# ---------------------------------------------------------------------------
FONT_HEADING = "Orbitron"        # stencil/techno headings
FONT_BODY    = "Chakra Petch"    # body / UI
FONT_MONO    = "JetBrains Mono"  # commands / logs / terminal

_FALLBACK_BODY    = ("Chakra Petch", "Segoe UI", "TkDefaultFont")
_FALLBACK_HEADING = ("Orbitron", "Chakra Petch", "Segoe UI")
_FALLBACK_MONO    = ("JetBrains Mono", "Consolas", "Courier New")

# Resolved family names, filled in by apply_theme() once Tk knows what's
# available. Reference as theme.FONTS['heading'] for explicit font tuples.
FONTS: dict[str, str] = {"body": "Chakra Petch", "heading": "Orbitron",
                         "mono": "JetBrains Mono"}

# Accent tones — drive sidebar rails, active icons, and meters. One dominant
# tone per surface (design system rule). Matches tokens/colors.css.
TONES: dict[str, str] = {
    "purple": TOKENS["purple"],
    "blue":   TOKENS["info"],
    "green":  TOKENS["secure"],
    "orange": TOKENS["warning"],
    "red":    TOKENS["critical"],
}
# Brighter "glow" partner for each tone (for the active rail / icon tint).
TONE_GLOW: dict[str, str] = {
    "purple": TOKENS["purple_glow"],
    "blue":   TOKENS["info_glow"],
    "green":  TOKENS["secure_glow"],
    "orange": TOKENS["warning_glow"],
    "red":    TOKENS["critical"],
}


def tone(name: str) -> str:
    return TONES.get(name, TOKENS["purple"])


def tone_glow(name: str) -> str:
    return TONE_GLOW.get(name, TOKENS["purple_glow"])


def _assets_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    root = Path(base) if base else Path(__file__).resolve().parent
    return root / "assets"


def load_fonts() -> list[str]:
    """Register the bundled .ttf files with the OS font system (Windows).

    Returns the family names that were (attempted to be) registered. Never
    raises — brand fonts are cosmetic; the app must run without them.
    """
    families: list[str] = []
    fdir = _assets_dir() / "fonts"
    if not fdir.is_dir():
        return families
    if sys.platform.startswith("win"):
        try:
            import ctypes
            FR_PRIVATE = 0x10
            gdi = ctypes.windll.gdi32
            for ttf in sorted(fdir.glob("*.ttf")):
                # Load for this process only (private) so we don't pollute the OS.
                gdi.AddFontResourceExW(str(ttf), FR_PRIVATE, 0)
                families.append(ttf.stem)
        except Exception:
            pass
    return families


def _pick_family(root: tk.Misc, candidates: tuple[str, ...]) -> str:
    """Return the first candidate family Tk actually knows about."""
    try:
        available = {f.lower() for f in tkfont.families(root)}
    except Exception:
        available = set()
    for fam in candidates:
        if fam.lower() in available:
            return fam
    return candidates[-1]


def _configure_named_fonts(root: tk.Misc) -> dict[str, str]:
    """Point Tk's built-in named fonts at the brand families.

    Because the app builds most widgets with 'TkDefaultFont' / 'TkFixedFont',
    remapping these propagates the brand typography app-wide without touching
    every widget. Returns the resolved family names.
    """
    body = _pick_family(root, _FALLBACK_BODY)
    heading = _pick_family(root, _FALLBACK_HEADING)
    mono = _pick_family(root, _FALLBACK_MONO)
    try:
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont",
                     "TkHeadingFont", "TkTooltipFont", "TkIconFont"):
            try:
                tkfont.nametofont(name).configure(family=body)
            except tk.TclError:
                pass
        try:
            tkfont.nametofont("TkFixedFont").configure(family=mono)
        except tk.TclError:
            pass
    except Exception:
        pass
    resolved = {"body": body, "heading": heading, "mono": mono}
    FONTS.update(resolved)
    return resolved


# ---------------------------------------------------------------------------
# 4. Apply the theme to a root window
# ---------------------------------------------------------------------------
def apply_theme(root: tk.Misc) -> dict[str, str]:
    """Apply the SYST3MS dark theme to *root* and its ttk styles.

    Returns the semantic palette dict (``C``) for convenience.
    """
    load_fonts()
    fams = _configure_named_fonts(root)

    # Classic tk widgets read the option database — set dark defaults so
    # Menu / Text / Listbox / Entry / Toplevel are dark even before per-widget
    # colours are applied in code.
    _set_option_defaults(root, fams)

    style = ttk.Style(root)
    # 'clam' is the only cross-platform base theme that reliably honours custom
    # background/border colours (vista/aqua ignore them).
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    _configure_ttk(style, fams)

    try:
        root.configure(bg=C["base"])
    except tk.TclError:
        pass
    return C


def _set_option_defaults(root: tk.Misc, fams: dict[str, str]) -> None:
    o = root.option_add
    # Toplevels / frames
    o("*background", C["base"])
    o("*foreground", C["body"])
    # Menus
    o("*Menu.background", C["surface"])
    o("*Menu.foreground", C["body"])
    o("*Menu.activeBackground", C["accent"])
    o("*Menu.activeForeground", C["strong"])
    o("*Menu.selectColor", C["accent_glow"])
    o("*Menu.borderWidth", 0)
    o("*Menu.relief", "flat")
    # Classic Text / Listbox / Entry (ttk Entry is styled separately)
    for cls in ("Text", "Listbox", "Canvas"):
        o(f"*{cls}.background", C["inset"])
        o(f"*{cls}.foreground", C["body"])
        o(f"*{cls}.highlightBackground", C["line"])
        o(f"*{cls}.highlightColor", C["accent"])
    o("*Text.insertBackground", C["strong"])
    o("*Text.selectBackground", C["accent_deep"])
    o("*Text.selectForeground", C["strong"])
    o("*Listbox.selectBackground", C["accent_deep"])
    o("*Listbox.selectForeground", C["strong"])


def _configure_ttk(style: ttk.Style, fams: dict[str, str]) -> None:
    body, heading, mono = fams["body"], fams["heading"], fams["mono"]

    # Global defaults for every ttk widget.
    style.configure(
        ".",
        background=C["base"],
        foreground=C["body"],
        fieldbackground=C["inset"],
        troughcolor=C["inset"],
        bordercolor=C["line"],
        lightcolor=C["line"],
        darkcolor=C["line"],
        focuscolor=C["accent_glow"],
        insertcolor=C["strong"],
    )

    style.configure("TFrame", background=C["base"])
    style.configure("Toolbar.TFrame", background=C["surface"], padding=8)
    style.configure("Card.TFrame", background=C["surface"])

    style.configure("TLabel", background=C["base"], foreground=C["body"])
    style.configure("TLabelframe", background=C["base"],
                    bordercolor=C["line"], foreground=C["muted"])
    style.configure("TLabelframe.Label", background=C["base"],
                    foreground=C["muted"])

    # Buttons
    style.configure("TButton", background=C["raised"], foreground=C["strong"],
                    bordercolor=C["line_strong"], focusthickness=1,
                    focuscolor=C["accent_glow"], padding=(12, 6), relief="flat")
    style.map(
        "TButton",
        background=[("pressed", C["accent_deep"]), ("active", C["hover"])],
        bordercolor=[("active", C["accent_glow"]), ("focus", C["accent_glow"])],
        foreground=[("disabled", C["faint"])],
    )
    # Primary / accent button
    style.configure("Accent.TButton", background=C["accent"],
                    foreground=C["strong"], bordercolor=C["accent_glow"])
    style.map("Accent.TButton",
              background=[("pressed", C["accent_deep"]), ("active", C["accent_glow"])])

    # Entries / combos / spinboxes
    for cls in ("TEntry", "TCombobox", "TSpinbox"):
        style.configure(cls, fieldbackground=C["inset"], foreground=C["strong"],
                        bordercolor=C["line"], arrowcolor=C["muted"],
                        insertcolor=C["strong"], padding=4)
        style.map(cls, bordercolor=[("focus", C["accent_glow"])],
                  fieldbackground=[("readonly", C["surface"])])

    # Checkbuttons / radiobuttons
    for cls in ("TCheckbutton", "TRadiobutton"):
        style.configure(cls, background=C["base"], foreground=C["body"],
                        focuscolor=C["accent_glow"])
        style.map(cls, background=[("active", C["base"])],
                  indicatorcolor=[("selected", C["accent"]),
                                  ("!selected", C["inset"])])

    # Notebook (the report detail tabs)
    style.configure("TNotebook", background=C["base"], bordercolor=C["line"],
                    tabmargins=(2, 4, 2, 0))
    style.configure("TNotebook.Tab", background=C["surface"], foreground=C["muted"],
                    bordercolor=C["line"], padding=(14, 7), font=(heading, 9))
    style.map("TNotebook.Tab",
              background=[("selected", C["raised"])],
              foreground=[("selected", C["strong"])],
              bordercolor=[("selected", C["accent"])])

    # Treeview (reports list + findings/devices tables)
    style.configure("Treeview", background=C["surface"], fieldbackground=C["surface"],
                    foreground=C["body"], bordercolor=C["line"], rowheight=26,
                    relief="flat")
    style.map("Treeview",
              background=[("selected", C["accent_deep"])],
              foreground=[("selected", C["strong"])])
    style.configure("Treeview.Heading", background=C["raised"], foreground=C["strong"],
                    bordercolor=C["line"], relief="flat", font=(heading, 9, "bold"),
                    padding=4)
    style.map("Treeview.Heading", background=[("active", C["hover"])])

    # Scrollbars
    for cls in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
        style.configure(cls, background=C["line_strong"], troughcolor=C["base"],
                        bordercolor=C["base"], arrowcolor=C["muted"], relief="flat")
        style.map(cls, background=[("active", C["accent"])])

    # Separators / progress
    style.configure("TSeparator", background=C["line"])
    style.configure("TProgressbar", background=C["accent"], troughcolor=C["inset"],
                    bordercolor=C["line"])
    style.configure("TScale", background=C["base"], troughcolor=C["inset"])

    # Panedwindow sash
    style.configure("TPanedwindow", background=C["base"])
    style.configure("Sash", sashthickness=6, gripcount=0)

    # -- SYST3MS shell chrome --------------------------------------------- #
    # Command (title) bar + sidebar surfaces
    style.configure("CommandBar.TFrame", background=C["base"])
    style.configure("Sidebar.TFrame", background=C["surface"])
    style.configure("SidebarHead.TFrame", background=C["surface"])
    style.configure("Main.TFrame", background=C["base"])
    style.configure("Card.TFrame", background=C["surface"])

    # Labels that sit on the sidebar surface
    style.configure("Logo.TLabel", background=C["surface"], foreground=C["strong"],
                    font=(heading, 13, "bold"))
    style.configure("LogoSub.TLabel", background=C["surface"], foreground=C["faint"],
                    font=(mono, 9))
    style.configure("Arsenal.TLabel", background=C["surface"], foreground=C["faint"],
                    font=(heading, 9, "bold"))
    style.configure("SidebarBadge.TLabel", background=C["surface"], foreground=C["muted"],
                    font=(mono, 8))

    # Command-bar url path (mono, muted)
    style.configure("Url.TLabel", background=C["base"], foreground=C["muted"],
                    font=(mono, 10))
    style.configure("UrlAccent.TLabel", background=C["base"], foreground=C["accent_glow"],
                    font=(mono, 10))

    # Main header block
    style.configure("Eyebrow.TLabel", background=C["base"], foreground=C["accent_glow"],
                    font=(heading, 10, "bold"))
    style.configure("H1.TLabel", background=C["base"], foreground=C["strong"],
                    font=(heading, 22, "bold"))
    style.configure("Sub.TLabel", background=C["base"], foreground=C["muted"],
                    font=(body, 10))
    style.configure("MeterLabel.TLabel", background=C["base"], foreground=C["faint"],
                    font=(heading, 8, "bold"))
