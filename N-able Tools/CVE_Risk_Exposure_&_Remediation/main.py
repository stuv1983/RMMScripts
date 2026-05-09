"""
main.py — Tkinter GUI only.

Responsibilities:
    - Build and display the GUI
    - Validate that required files have been selected
    - Collect user inputs into a DashboardRequest
    - Show a save dialog to get the output path
    - Spawn the background thread that calls orchestrator.run()
    - Relay results / errors back to the GUI via root.after()

Zero business logic. Zero data processing. Zero Excel writing.
"""

import logging
import subprocess
import sys
import threading
from pathlib import Path
from datetime import date, timedelta, datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from orchestrator import DashboardRequest, DashboardResult, run as run_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_CVE_REPO_DEFAULT = r"C:\NoCScripts\N-able Tools\CVE_Risk_Exposure_&_Remediation\cvelistV5"

WIN_W = 560
WIN_H = 720


# ==============================================================================
# APPLICATION
# ==============================================================================

class App(tk.Tk):
    # ── Palette ────────────────────────────────────────────────────────────────
    BG      = "#1E2530"
    HEADER  = "#141920"
    CARD    = "#252D3A"
    ACCENT  = "#3B82F6"
    ACCENTH = "#2563EB"
    TEXT    = "#E2E8F0"
    SUBTEXT = "#94A3B8"
    SUCCESS = "#22C55E"
    ERROR   = "#EF4444"
    WARN    = "#F59E0B"
    BORDERC = "#374151"
    INPUT   = "#2D3748"
    LOGBG   = "#0F1419"
    LOGFG   = "#A8B2C1"

    FONT      = "Segoe UI"
    FONT_MONO = "Consolas"

    # Light-mode overrides
    _LIGHT = {
        "BG":     "#F0F4F8", "HEADER": "#E2E8F0", "CARD":   "#FFFFFF",
        "TEXT":   "#1A202C", "SUBTEXT":"#4A5568", "INPUT":  "#EDF2F7",
        "BORDERC":"#CBD5E0", "LOGBG":  "#F7FAFC", "LOGFG":  "#2D3748",
    }
    _light = False

    # ── Init ───────────────────────────────────────────────────────────────────
    def __init__(self):
        super().__init__()
        self.title("N-able CVE Dashboard & Triage Tool")
        self.configure(bg=self.BG)
        self.resizable(False, False)

        # StringVars
        self.vuln_label    = tk.StringVar(value="No file selected")
        self.rmm_label     = tk.StringVar(value="No file selected")
        self.patch_label   = tk.StringVar(value="No file selected")
        self.failure_label = tk.StringVar(value="No file selected")
        self.prev_label    = tk.StringVar(value="No file selected")

        self.vuln_path    = ""
        self.rmm_path     = ""
        self.patch_path   = ""
        self.failure_path = ""
        self.prev_path    = ""

        self.skip_rmm_var      = tk.BooleanVar()
        self.include_patch_var = tk.BooleanVar()
        self.include_fail_var  = tk.BooleanVar()
        self.include_trend_var = tk.BooleanVar()
        self.show_all_dates    = tk.BooleanVar()
        self.sync_baselines    = tk.BooleanVar()

        self.score_var        = tk.StringVar(value="9.0")
        self.date_var         = tk.StringVar(
            value=(date.today() - timedelta(days=90)).strftime("%d/%m/%Y"))
        self.report_month_var = tk.StringVar(
            value=datetime.now().strftime("%B %Y"))

        self._build_menu()
        self._build()

        self.update_idletasks()
        x = (self.winfo_screenwidth()  - WIN_W) // 2
        y = (self.winfo_screenheight() - WIN_H) // 2
        self.geometry(f"{WIN_W}x{WIN_H}+{x}+{y}")

    # ══════════════════════════════════════════════════════════════════════════
    # BUILD
    # ══════════════════════════════════════════════════════════════════════════

    def _build(self):
        # ── Fixed header ──────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=self.HEADER, pady=14)
        hdr.pack(fill="x", side="top")
        tk.Label(hdr, text="🛡  N-able CVE Dashboard & Triage Tool",
                 font=(self.FONT, 13, "bold"),
                 fg=self.TEXT, bg=self.HEADER).pack()
        tk.Label(hdr, text="Select input files, configure settings, then generate",
                 font=(self.FONT, 9),
                 fg=self.SUBTEXT, bg=self.HEADER).pack(pady=(2, 0))

        # ── Fixed footer (generate btn + log + progress) ──────────────────────
        foot = tk.Frame(self, bg=self.BG)
        foot.pack(fill="x", side="bottom")

        # Progress bar in its own fixed-height slot — no layout jitter
        prog_slot = tk.Frame(foot, bg=self.BG, height=20)
        prog_slot.pack(fill="x", padx=20, pady=(0, 8))
        prog_slot.pack_propagate(False)
        self.progress_bar = ttk.Progressbar(prog_slot, mode="indeterminate")
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        prog_slot.columnconfigure(0, weight=1)
        self.progress_bar.grid_remove()

        # Log box
        log_outer = tk.Frame(foot, bg=self.BG)
        log_outer.pack(fill="x", padx=20, pady=(0, 4))
        self.log_box = tk.Text(
            log_outer, height=4,
            font=(self.FONT_MONO, 9),
            bg=self.LOGBG, fg=self.LOGFG,
            relief="flat", state="disabled", wrap="word",
            highlightthickness=1, highlightbackground=self.BORDERC,
        )
        self.log_box.pack(fill="x")
        self.log_box.tag_config("ok",   foreground=self.SUCCESS)
        self.log_box.tag_config("err",  foreground=self.ERROR)
        self.log_box.tag_config("warn", foreground=self.WARN)
        self.log_box.tag_config("dim",  foreground=self.SUBTEXT)

        # Generate button
        btn_row = tk.Frame(foot, bg=self.BG, pady=10)
        btn_row.pack(fill="x")
        self.generate_btn = tk.Button(
            btn_row,
            text="▶  GENERATE COMPLETE DASHBOARD",
            command=self._process_reports,
            font=(self.FONT, 11, "bold"),
            bg=self.ACCENT, fg=self.TEXT,
            activebackground=self.ACCENTH, activeforeground=self.TEXT,
            relief="flat", cursor="hand2", padx=24, pady=9,
        )
        self.generate_btn.pack()
        self.generate_btn.bind("<Enter>", lambda e: self.generate_btn.config(bg=self.ACCENTH))
        self.generate_btn.bind("<Leave>", lambda e: self.generate_btn.config(bg=self.ACCENT))

        # ── Scrollable body ───────────────────────────────────────────────────
        # Canvas + inner Frame pattern: body scrolls, header + footer stay fixed.
        scroll_area = tk.Frame(self, bg=self.BG)
        scroll_area.pack(fill="both", expand=True, side="top")

        self._canvas = tk.Canvas(
            scroll_area, bg=self.BG,
            highlightthickness=0, bd=0,
        )
        scrollbar = ttk.Scrollbar(
            scroll_area, orient="vertical",
            command=self._canvas.yview,
        )
        self._canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        # Inner frame — all content lives here
        self._body = tk.Frame(self._canvas, bg=self.BG)
        self._body_id = self._canvas.create_window(
            (0, 0), window=self._body, anchor="nw",
        )

        self._body.bind("<Configure>", self._on_body_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # Mouse-wheel scroll (Windows + macOS + Linux)
        for widget in (self._canvas, self._body):
            widget.bind("<MouseWheel>",       self._on_mousewheel)   # Win/Mac
            widget.bind("<Button-4>",         self._on_mousewheel)   # Linux up
            widget.bind("<Button-5>",         self._on_mousewheel)   # Linux down

        # ── Populate body ─────────────────────────────────────────────────────
        self._populate_body()

    def _on_body_configure(self, _event):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self._canvas.itemconfig(self._body_id, width=event.width)

    def _on_mousewheel(self, event):
        if event.num == 4:      delta = -1
        elif event.num == 5:    delta = 1
        else:                   delta = -int(event.delta / 120)
        self._canvas.yview_scroll(delta, "units")

    # ── Body content ──────────────────────────────────────────────────────────

    def _populate_body(self):
        b = self._body   # shorthand

        # ── STEP 1 — Required inputs ──────────────────────────────────────────
        self._section(b, "STEP 1 — Required inputs")

        self._card_btn(b, "Vulnerability / CVE Report  (CSV or XLSX)",
                       self.vuln_label, self._pick_vuln, "🔍")

        self._card_btn(b, "Device Inventory / RMM Report  (CSV or XLSX)",
                       self.rmm_label, self._pick_rmm, "🖥")

        self._checkbox(b, "Skip RMM  (CVE export already includes device info)",
                       self.skip_rmm_var, self._toggle_rmm)

        # ── STEP 2 — Settings ─────────────────────────────────────────────────
        self._section(b, "STEP 2 — Settings")
        self._settings_card(b)

        # ── STEP 3 — Optional inputs ──────────────────────────────────────────
        self._section(b, "STEP 3 — Optional inputs")

        self._card_btn(b, "Patch Report  (CSV or XLSX)",
                       self.patch_label, self._pick_patch, "🩹")
        self._checkbox(b, "Include Patch Report matching",
                       self.include_patch_var, self._toggle_patch)

        self._card_btn(b, "Patch Failure Report  (CSV)",
                       self.failure_label, self._pick_failure, "⚠")
        self._checkbox(b, "Include Patch Failure analysis",
                       self.include_fail_var, self._toggle_failure)

        self._card_btn(b, "Previous Dashboard  (XLSX — for M-o-M trends)",
                       self.prev_label, self._pick_prev, "📈")
        self._checkbox(b, "Include month-over-month trend analysis",
                       self.include_trend_var, self._toggle_trend)

        self._checkbox(b, "Refresh product baselines before run",
                       self.sync_baselines)

        # bottom padding so last item isn't flush against the footer
        tk.Frame(b, bg=self.BG, height=12).pack()

    # ══════════════════════════════════════════════════════════════════════════
    # WIDGET FACTORIES  (all take an explicit parent — body or a sub-frame)
    # ══════════════════════════════════════════════════════════════════════════

    def _section(self, parent, text):
        row = tk.Frame(parent, bg=self.BG)
        row.pack(fill="x", padx=20, pady=(12, 2))
        tk.Label(row, text=text,
                 font=(self.FONT, 8),
                 fg=self.SUBTEXT, bg=self.BG, anchor="w").pack(anchor="w")

    def _card_btn(self, parent, title, done_var, cmd, icon="📄"):
        card = tk.Frame(
            parent, bg=self.CARD, cursor="hand2",
            highlightthickness=1, highlightbackground=self.BORDERC,
        )
        card.pack(fill="x", padx=20, pady=3)

        inner = tk.Frame(card, bg=self.CARD)
        inner.pack(fill="x", padx=14, pady=7)

        title_lbl = tk.Label(
            inner, text=f"{icon}  {title}",
            font=(self.FONT, 9, "bold"),
            fg=self.TEXT, bg=self.CARD, anchor="w",
        )
        title_lbl.pack(fill="x")

        sub_lbl = tk.Label(
            inner, textvariable=done_var,
            font=(self.FONT, 8),
            fg=self.SUBTEXT, bg=self.CARD, anchor="w",
        )
        sub_lbl.pack(fill="x")

        def _enter(_e): card.config(highlightbackground=self.ACCENT)
        def _leave(_e): card.config(highlightbackground=self.BORDERC)

        for w in (card, inner, title_lbl, sub_lbl):
            w.bind("<Button-1>", lambda _e: cmd())
            w.bind("<Enter>", _enter)
            w.bind("<Leave>", _leave)
            # Propagate scroll events through cards to the canvas
            w.bind("<MouseWheel>", self._on_mousewheel)
            w.bind("<Button-4>",   self._on_mousewheel)
            w.bind("<Button-5>",   self._on_mousewheel)

        return card

    def _checkbox(self, parent, text, variable, command=None):
        cb = tk.Checkbutton(
            parent, text=text, variable=variable,
            font=(self.FONT, 9),
            fg=self.TEXT, bg=self.BG,
            activeforeground=self.TEXT, activebackground=self.BG,
            selectcolor=self.INPUT,
            command=command,
        )
        cb.pack(anchor="w", padx=20, pady=(1, 0))
        cb.bind("<MouseWheel>", self._on_mousewheel)
        cb.bind("<Button-4>",   self._on_mousewheel)
        cb.bind("<Button-5>",   self._on_mousewheel)
        return cb

    def _settings_card(self, parent):
        card = tk.Frame(
            parent, bg=self.CARD,
            highlightthickness=1, highlightbackground=self.BORDERC,
        )
        card.pack(fill="x", padx=20, pady=3)
        inner = tk.Frame(card, bg=self.CARD)
        inner.pack(fill="x", padx=14, pady=10)

        def _entry(row_frame, var, width):
            return tk.Entry(
                row_frame, textvariable=var, width=width,
                font=(self.FONT, 9), bg=self.INPUT, fg=self.TEXT,
                insertbackground=self.TEXT, relief="flat",
                highlightthickness=1, highlightbackground=self.BORDERC,
            )

        def _lbl(row_frame, text, bold=False, color=None):
            return tk.Label(
                row_frame, text=text,
                font=(self.FONT, 9, "bold" if bold else "normal"),
                fg=color or self.TEXT, bg=self.CARD, anchor="w",
            )

        # Score
        row = tk.Frame(inner, bg=self.CARD)
        row.pack(fill="x", pady=(0, 5))
        _lbl(row, "Minimum CVE Score:", bold=True).pack(side="left")
        _entry(row, self.score_var, 7).pack(side="left", padx=8)

        # Stale date
        row2 = tk.Frame(inner, bg=self.CARD)
        row2.pack(fill="x", pady=(0, 5))
        _lbl(row2, "Exclude stale devices last seen before:", bold=True).pack(side="left")
        self.date_entry = _entry(row2, self.date_var, 12)
        self.date_entry.pack(side="left", padx=8)
        _lbl(row2, "(dd/mm/yyyy)", color=self.SUBTEXT).pack(side="left")
        tk.Checkbutton(
            row2, text="Show All",
            variable=self.show_all_dates, command=self._toggle_date,
            font=(self.FONT, 9), fg=self.TEXT, bg=self.CARD,
            activeforeground=self.TEXT, activebackground=self.CARD,
            selectcolor=self.INPUT,
        ).pack(side="left", padx=10)
        self._toggle_date()

        # Report month
        row3 = tk.Frame(inner, bg=self.CARD)
        row3.pack(fill="x")
        _lbl(row3, "Report Month:", bold=True).pack(side="left")
        _entry(row3, self.report_month_var, 15).pack(side="left", padx=8)

    # ══════════════════════════════════════════════════════════════════════════
    # MENU
    # ══════════════════════════════════════════════════════════════════════════

    def _build_menu(self):
        menubar = tk.Menu(self)

        self._view_menu = tk.Menu(menubar, tearoff=0)
        self._view_menu.add_command(label="☀  Light Mode", command=self._toggle_light)
        menubar.add_cascade(label="View", menu=self._view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(
            label="Update CVEs  (git pull cvelistV5)", command=self._update_cves)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    # ══════════════════════════════════════════════════════════════════════════
    # LIGHT / DARK TOGGLE
    # ══════════════════════════════════════════════════════════════════════════

    def _toggle_light(self):
        self._light = not self._light
        self._view_menu.entryconfigure(
            0, label="🌙  Dark Mode" if self._light else "☀  Light Mode")
        p = self._LIGHT if self._light else {
            "BG": self.BG, "HEADER": self.HEADER, "CARD": self.CARD,
            "TEXT": self.TEXT, "SUBTEXT": self.SUBTEXT, "INPUT": self.INPUT,
            "BORDERC": self.BORDERC, "LOGBG": self.LOGBG, "LOGFG": self.LOGFG,
        }
        self._apply_palette(p)

    def _apply_palette(self, p):
        self.configure(bg=p["BG"])
        self._canvas.configure(bg=p["BG"])
        self.log_box.configure(bg=p["LOGBG"], fg=p["LOGFG"])

        for w in self._all_widgets(self):
            cls = w.winfo_class()
            try:
                bg = w.cget("bg")
                if cls == "Frame":
                    if bg in (self.BG,   self._LIGHT["BG"]):   w.configure(bg=p["BG"])
                    elif bg in (self.HEADER, self._LIGHT["HEADER"]): w.configure(bg=p["HEADER"])
                    elif bg in (self.CARD,   self._LIGHT["CARD"]):   w.configure(bg=p["CARD"])
                elif cls == "Label":
                    card_bg = bg in (self.CARD, self._LIGHT["CARD"])
                    fg = w.cget("fg")
                    new_bg = p["CARD"] if card_bg else p["BG"]
                    new_fg = p["SUBTEXT"] if fg in (self.SUBTEXT, self._LIGHT["SUBTEXT"]) else p["TEXT"]
                    w.configure(bg=new_bg, fg=new_fg)
                elif cls == "Checkbutton":
                    card_bg = bg in (self.CARD, self._LIGHT["CARD"])
                    w.configure(
                        bg=p["CARD"] if card_bg else p["BG"],
                        fg=p["TEXT"],
                        activeforeground=p["TEXT"],
                        activebackground=p["CARD"] if card_bg else p["BG"],
                        selectcolor=p["INPUT"],
                    )
                elif cls == "Entry":
                    w.configure(
                        bg=p["INPUT"], fg=p["TEXT"],
                        insertbackground=p["TEXT"],
                        highlightbackground=p["BORDERC"],
                    )
                elif cls == "Canvas":
                    w.configure(bg=p["BG"])
            except tk.TclError:
                pass

        # Card border highlights
        for w in self._all_widgets(self):
            if w.winfo_class() == "Frame":
                try:
                    if int(w.cget("highlightthickness")) == 1:
                        w.configure(highlightbackground=p["BORDERC"])
                except (tk.TclError, ValueError):
                    pass

    @staticmethod
    def _all_widgets(widget, result=None):
        if result is None:
            result = []
        result.append(widget)
        for child in widget.winfo_children():
            App._all_widgets(child, result)
        return result

    # ══════════════════════════════════════════════════════════════════════════
    # FILE PICKERS
    # ══════════════════════════════════════════════════════════════════════════

    def _pick(self, path_attr, label_var, title, filetypes):
        f = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if f:
            setattr(self, path_attr, f)
            label_var.set(f"✔  {Path(f).name}")

    def _pick_vuln(self):
        self._pick("vuln_path", self.vuln_label,
                   "Select Vulnerability / CVE Report",
                   [("Data Files", "*.csv *.xlsx *.xls"), ("All", "*.*")])

    def _pick_rmm(self):
        if self.skip_rmm_var.get():
            return
        self._pick("rmm_path", self.rmm_label,
                   "Select Device Inventory / RMM Report",
                   [("Data Files", "*.csv *.xlsx *.xls"), ("All", "*.*")])

    def _pick_patch(self):
        if not self.include_patch_var.get():
            messagebox.showinfo("Tip", "Tick 'Include Patch Report matching' first.")
            return
        self._pick("patch_path", self.patch_label,
                   "Select Patch Report",
                   [("Data Files", "*.csv *.xlsx *.xls"), ("All", "*.*")])

    def _pick_failure(self):
        if not self.include_fail_var.get():
            messagebox.showinfo("Tip", "Tick 'Include Patch Failure analysis' first.")
            return
        self._pick("failure_path", self.failure_label,
                   "Select Patch Failure Report",
                   [("CSV Files", "*.csv"), ("All", "*.*")])

    def _pick_prev(self):
        if not self.include_trend_var.get():
            messagebox.showinfo("Tip", "Tick 'Include month-over-month trend analysis' first.")
            return
        self._pick("prev_path", self.prev_label,
                   "Select Previous Dashboard",
                   [("Excel Files", "*.xlsx"), ("All", "*.*")])

    # ══════════════════════════════════════════════════════════════════════════
    # TOGGLES
    # ══════════════════════════════════════════════════════════════════════════

    def _toggle_rmm(self):
        if self.skip_rmm_var.get():
            self.rmm_label.set("Skipped — CVE export includes device info")

    def _toggle_patch(self):
        if not self.include_patch_var.get():
            self.patch_path = ""
            self.patch_label.set("No file selected")

    def _toggle_failure(self):
        if not self.include_fail_var.get():
            self.failure_path = ""
            self.failure_label.set("No file selected")

    def _toggle_trend(self):
        if not self.include_trend_var.get():
            self.prev_path = ""
            self.prev_label.set("No file selected")

    def _toggle_date(self):
        self.date_entry.config(
            state=tk.DISABLED if self.show_all_dates.get() else tk.NORMAL)

    # ══════════════════════════════════════════════════════════════════════════
    # LOG
    # ══════════════════════════════════════════════════════════════════════════

    def _log(self, msg, tag=""):
        self.log_box.config(state="normal")
        self.log_box.insert("end", msg + "\n", tag)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _log_clear(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")

    # ══════════════════════════════════════════════════════════════════════════
    # MAIN ACTION
    # ══════════════════════════════════════════════════════════════════════════

    def _process_reports(self):
        if not self.vuln_path:
            messagebox.showerror("Missing", "Please select the Vulnerability Report.")
            return
        if not self.skip_rmm_var.get() and not self.rmm_path:
            messagebox.showerror("Missing", "Please select the Device Inventory / RMM Report.")
            return
        if self.include_patch_var.get() and not self.patch_path:
            messagebox.showerror(
                "Missing",
                "Patch Report matching is enabled but no file selected.\n"
                "Browse for a Patch Report or uncheck the option.",
            )
            return
        if self.include_trend_var.get() and not self.prev_path:
            messagebox.showerror(
                "Missing",
                "Trend tracking is enabled but no previous report selected.\n"
                "Browse for a previous dashboard or uncheck the option.",
            )
            return

        try:
            threshold = float(self.score_var.get())
        except ValueError:
            messagebox.showerror(
                "Invalid input",
                f"Minimum CVE Score must be a number (e.g. 9.0).\n"
                f"Current value: {self.score_var.get()!r}",
            )
            return

        if not self.show_all_dates.get() and self.date_var.get().strip():
            try:
                datetime.strptime(self.date_var.get().strip(), "%d/%m/%Y")
            except ValueError:
                messagebox.showerror(
                    "Invalid input",
                    f"Stale device date must be in dd/mm/yyyy format.\n"
                    f"Current value: {self.date_var.get()!r}",
                )
                return

        output_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")]
        )
        if not output_path:
            return

        cutoff = None if self.show_all_dates.get() else self.date_var.get().strip() or None

        request = DashboardRequest(
            vuln_path              = self.vuln_path,
            output_path            = output_path,
            rmm_path               = self.rmm_path or None,
            skip_rmm               = self.skip_rmm_var.get(),
            patch_path             = self.patch_path or None,
            include_patch          = self.include_patch_var.get(),
            failure_report_path    = self.failure_path or None,
            include_failure_report = self.include_fail_var.get(),
            prev_report_path       = self.prev_path or None,
            include_trend          = self.include_trend_var.get(),
            threshold              = threshold,
            cutoff_date            = cutoff,
            show_all_dates         = self.show_all_dates.get(),
            sync_baselines         = self.sync_baselines.get(),
            report_month           = self.report_month_var.get().strip(),
        )

        self._log_clear()
        self._log(f"CVE   : {Path(self.vuln_path).name}", "dim")
        if not self.skip_rmm_var.get() and self.rmm_path:
            self._log(f"RMM   : {Path(self.rmm_path).name}", "dim")
        if self.include_patch_var.get() and self.patch_path:
            self._log(f"Patch : {Path(self.patch_path).name}", "dim")
        if self.include_trend_var.get() and self.prev_path:
            self._log(f"Prev  : {Path(self.prev_path).name}", "dim")
        self._log("Running…", "dim")

        self.generate_btn.config(state="disabled")
        self.progress_bar.grid()
        self.progress_bar.start(12)
        threading.Thread(target=self._worker, args=(request,), daemon=True).start()

    def _worker(self, request):
        try:
            result = run_dashboard(request)
            if result.success:
                def _ok():
                    self._log(f"✔  {result.message}", "ok")
                    if result.trend_summary:
                        ts = result.trend_summary
                        self._log(
                            f"   ▲{ts['new_cve_count']:,} new  "
                            f"▼{ts['resolved_cve_count']:,} resolved  "
                            f"⏳{ts['persisting_cve_count']:,} persisting", "ok")
                    for w in result.warnings:
                        self._log(f"   ⚠  {w}", "warn")
                    self._done()
                    self._offer_open(request.output_path)
                self.after(0, _ok)
            else:
                _err = result.message
                def _fail():
                    self._log(f"✘  {_err}", "err")
                    self._done()
                    messagebox.showerror("Error", f"Processing failed:\n{_err}")
                self.after(0, _fail)
        except Exception as exc:
            import traceback
            _tb  = traceback.format_exc()
            _msg = str(exc)
            log.exception("Unexpected error in background thread")
            def _exc_show():
                self._log(f"✘  {_msg}", "err")
                self._log(_tb, "err")
                self._done()
                messagebox.showerror("Error", f"Unexpected error:\n{_msg}")
            self.after(0, _exc_show)

    def _done(self):
        self.progress_bar.stop()
        self.progress_bar.grid_remove()
        self.generate_btn.config(state="normal")

    def _offer_open(self, path):
        if messagebox.askyesno("Done!", f"Dashboard saved to:\n{path}\n\nOpen it now?"):
            import os
            if os.name == "nt":
                os.startfile(path)
            else:
                import subprocess as sp
                sp.Popen(["xdg-open" if sys.platform != "darwin" else "open", path])

    # ══════════════════════════════════════════════════════════════════════════
    # HELP MENU
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _find_cve_repo() -> Path:
        default = Path(_CVE_REPO_DEFAULT)
        if default.exists():
            return default
        here = Path(sys.argv[0]).resolve().parent
        for c in (here / "cvelistV5", here.parent / "cvelistV5"):
            if c.exists():
                return c
        return default

    def _update_cves(self):
        repo = self._find_cve_repo()

        def _pull():
            try:
                r = subprocess.run(
                    ["git", "-C", str(repo), "pull"],
                    capture_output=True, text=True, timeout=120,
                )
                out = r.stdout.strip() or r.stderr.strip() or "(no output)"
                ok  = r.returncode == 0
                def _show():
                    if ok:
                        messagebox.showinfo("Update CVEs", f"✔  CVE list updated.\n\n{out}")
                    else:
                        messagebox.showerror("Update CVEs",
                            f"git pull returned exit code {r.returncode}.\n\n{out}")
                self.after(0, _show)
            except FileNotFoundError:
                self.after(0, lambda: messagebox.showerror(
                    "Update CVEs", "git not found.\nEnsure Git is on your PATH."))
            except subprocess.TimeoutExpired:
                self.after(0, lambda: messagebox.showerror(
                    "Update CVEs", "git pull timed out after 120 seconds."))
            except Exception as exc:
                _m = str(exc)
                self.after(0, lambda: messagebox.showerror(
                    "Update CVEs", f"Unexpected error:\n{_m}"))

        threading.Thread(target=_pull, daemon=True).start()
        messagebox.showinfo("Update CVEs",
            f"Pulling latest CVEs from:\n{repo}\n\nThis runs in the background…")

    def _show_about(self):
        messagebox.showinfo(
            "About — N-able CVE Dashboard",
            "N-able CVE Dashboard & Triage Tool\n\n"
            "Automates month-over-month vulnerability triage from N-able exports.\n\n"
            "Features:\n"
            "  • Patch match & evidence scoring\n"
            "  • Stale device purge from trend math\n"
            "  • CVE enrichment via NVD / cvelistV5\n"
            "  • Redetection tracking & root-cause diagnostics\n\n"
            "© 2026 Stuart Villanti — MIT Licence",
        )


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    App().mainloop()