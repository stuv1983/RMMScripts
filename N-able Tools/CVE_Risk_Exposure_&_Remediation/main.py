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


# ==============================================================================
# THEME ENGINE
# ==============================================================================

_THEMES = {
    "light": {
        "bg":       "#F0F0F0",
        "fg":       "#1A1A1A",
        "entry_bg": "#FFFFFF",
        "entry_fg": "#1A1A1A",
        "btn_bg":   "#E1E1E1",
        "btn_fg":   "#1A1A1A",
        "gen_bg":   "#0078D7",
        "gen_fg":   "#FFFFFF",
        "frame_bg": "#F0F0F0",
    },
    "dark": {
        "bg":       "#1E1E1E",
        "fg":       "#E0E0E0",
        "entry_bg": "#2D2D2D",
        "entry_fg": "#E0E0E0",
        "btn_bg":   "#3C3C3C",
        "btn_fg":   "#E0E0E0",
        "gen_bg":   "#005A9E",
        "gen_fg":   "#FFFFFF",
        "frame_bg": "#1E1E1E",
    },
}
_current_theme = "light"


def _get_theme() -> dict:
    return _THEMES[_current_theme]


def _collect_widgets(widget, result=None):
    """Recursively collect every widget in the hierarchy."""
    if result is None:
        result = []
    result.append(widget)
    for child in widget.winfo_children():
        _collect_widgets(child, result)
    return result


def _apply_theme():
    """Re-paint every widget with the active theme colours."""
    t = _get_theme()
    root.configure(bg=t["bg"])
    for w in _collect_widgets(root):
        cls = w.winfo_class()
        try:
            if cls in ("Label", "Checkbutton"):
                w.configure(bg=t["bg"], fg=t["fg"])
            elif cls == "Frame":
                w.configure(bg=t["frame_bg"])
            elif cls == "Entry":
                w.configure(
                    bg=t["entry_bg"], fg=t["entry_fg"],
                    insertbackground=t["fg"],
                    disabledbackground=t["frame_bg"],
                    disabledforeground=t["fg"],
                )
            elif cls == "Button":
                if "GENERATE" in str(w.cget("text")).upper():
                    w.configure(
                        bg=t["gen_bg"], fg=t["gen_fg"],
                        activebackground=t["gen_bg"],
                        activeforeground=t["gen_fg"],
                    )
                else:
                    w.configure(
                        bg=t["btn_bg"], fg=t["btn_fg"],
                        activebackground=t["bg"],
                        activeforeground=t["fg"],
                    )
        except tk.TclError:
            pass  # ttk widgets ignore colour kwargs — safe to skip


def toggle_dark_mode():
    global _current_theme
    _current_theme = "dark" if _current_theme == "light" else "light"
    _apply_theme()
    _refresh_view_menu_label()


def _refresh_view_menu_label():
    label = "☀  Light Mode" if _current_theme == "dark" else "🌙  Dark Mode"
    view_menu.entryconfigure(0, label=label)


# ==============================================================================
# UPDATE CVEs  (git pull on the cvelistV5 repo)
# ==============================================================================

_CVE_REPO_DEFAULT = r"C:\NoCScripts\N-able Tools\CVE_Risk_Exposure_&_Remediation\cvelistV5"


def _find_cve_repo() -> Path:
    """
    Return the cvelistV5 repo path.
    Checks the hardcoded default first, then searches relative to this script.
    """
    default = Path(_CVE_REPO_DEFAULT)
    if default.exists():
        return default
    here = Path(sys.argv[0]).resolve().parent
    for candidate in (here / "cvelistV5", here.parent / "cvelistV5"):
        if candidate.exists():
            return candidate
    # Return the default even if missing — git will produce a clear error message.
    return default


def update_cve_list():
    """Run git pull on the cvelistV5 repo in a daemon thread, then report the result."""
    repo = _find_cve_repo()

    def _do_pull():
        try:
            result = subprocess.run(
                ["git", "-C", str(repo), "pull"],
                capture_output=True, text=True, timeout=120,
            )
            output  = result.stdout.strip() or result.stderr.strip() or "(no output)"
            success = result.returncode == 0

            def _show():
                if success:
                    messagebox.showinfo("Update CVEs", f"✔  CVE list updated.\n\n{output}")
                else:
                    messagebox.showerror(
                        "Update CVEs",
                        f"git pull returned exit code {result.returncode}.\n\n{output}",
                    )
            root.after(0, _show)

        except FileNotFoundError:
            root.after(0, lambda: messagebox.showerror(
                "Update CVEs",
                "git not found.\nEnsure Git is installed and on your PATH.",
            ))
        except subprocess.TimeoutExpired:
            root.after(0, lambda: messagebox.showerror(
                "Update CVEs", "git pull timed out after 120 seconds.",
            ))
        except Exception as exc:
            _msg = str(exc)
            root.after(0, lambda: messagebox.showerror(
                "Update CVEs", f"Unexpected error:\n{_msg}",
            ))

    threading.Thread(target=_do_pull, daemon=True).start()
    messagebox.showinfo(
        "Update CVEs",
        f"Pulling latest CVEs from:\n{repo}\n\nThis runs in the background…",
    )


def show_about():
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
# FILE HELPERS
# ==============================================================================

def select_file(label_var, filetypes=None):
    if filetypes is None:
        filetypes = [
            ("Data Files",  "*.csv *.xlsx *.xls"),
            ("CSV Files",   "*.csv"),
            ("Excel Files", "*.xlsx *.xls"),
        ]
    path = filedialog.askopenfilename(filetypes=filetypes)
    if path:
        label_var.set(path)


# ==============================================================================
# BACKGROUND THREAD
# ==============================================================================

def _run_in_thread(request, progress_bar):
    try:
        log.info("Background thread started")
        result = run_dashboard(request)

        if result.success:
            msg = result.message
            if result.trend_summary:
                ts   = result.trend_summary
                msg += (
                    "\n\nTrend vs previous report:"
                    f"\n  \u25b2 {ts['new_cve_count']:,} new CVE types   "
                    f"\u25bc {ts['resolved_cve_count']:,} resolved   "
                    f"\u23f3 {ts['persisting_cve_count']:,} persisting"
                )
            if result.warnings:
                msg += "\n\nWarnings:\n" + "\n".join(f"  - {w}" for w in result.warnings)
            _msg = msg

            def _on_success():
                progress_bar.stop()
                progress_bar.grid_remove()
                generate_btn.config(state="normal")
                messagebox.showinfo("Done", _msg)

            root.after(0, _on_success)

        else:
            _err = result.message

            def _on_failure():
                progress_bar.stop()
                progress_bar.grid_remove()
                generate_btn.config(state="normal")
                messagebox.showerror("Error", f"Processing failed:\n{_err}")

            root.after(0, _on_failure)

    except Exception as exc:
        import traceback
        tb       = traceback.format_exc()
        _exc_msg = f"Unexpected error:\n{exc}\n\n{tb}"
        log.exception("Unexpected error in background thread")

        def _on_exception():
            progress_bar.stop()
            progress_bar.grid_remove()
            generate_btn.config(state="normal")
            messagebox.showerror("Error", _exc_msg)

        root.after(0, _on_exception)


# ==============================================================================
# MAIN ACTION
# ==============================================================================

def process_reports():
    vuln_path        = vuln_var.get()
    rmm_path         = rmm_var.get()
    skip_rmm         = skip_rmm_var.get()
    include_patch    = include_patch_var.get()
    patch_path       = patch_var.get()
    include_trend    = include_trend_var.get()
    prev_report_path = prev_report_var.get()

    # ── Required-file validation ───────────────────────────────────────────────
    if not vuln_path:
        messagebox.showerror("Error", "Please select the Vulnerability Report.")
        return
    if not skip_rmm and not rmm_path:
        messagebox.showerror("Error", "Please select the Device Inventory / RMM Report.")
        return
    if include_patch and not patch_path:
        messagebox.showerror(
            "Error",
            "Patch Report matching is enabled but no file selected.\n"
            "Please browse for a Patch Report or uncheck the option.",
        )
        return
    if include_trend and not prev_report_path:
        messagebox.showerror(
            "Error",
            "Trend tracking is enabled but no previous report selected.\n"
            "Please browse for a previous dashboard or uncheck the option.",
        )
        return

    # ── Fix: validate CVE score is a real number before dispatch ──────────────
    try:
        threshold = float(score_var.get())
    except ValueError:
        messagebox.showerror(
            "Error",
            f"Minimum CVE Score must be a number (e.g. 9.0).\n"
            f"Current value: {score_var.get()!r}",
        )
        return

    # ── Fix: validate stale-cutoff date format before dispatch ────────────────
    if not show_all_dates_var.get() and date_var.get().strip():
        try:
            datetime.strptime(date_var.get().strip(), "%d/%m/%Y")
        except ValueError:
            messagebox.showerror(
                "Error",
                f"Stale device date must be in dd/mm/yyyy format.\n"
                f"Current value: {date_var.get()!r}",
            )
            return

    output_path = filedialog.asksaveasfilename(
        defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")]
    )
    if not output_path:
        log.info("User cancelled save dialog")
        return

    cutoff_date = None if show_all_dates_var.get() else date_var.get().strip() or None

    request = DashboardRequest(
        vuln_path              = vuln_path,
        output_path            = output_path,
        rmm_path               = rmm_path or None,
        skip_rmm               = skip_rmm,
        patch_path             = patch_path or None,
        include_patch          = include_patch,
        failure_report_path    = failure_var.get() or None,
        include_failure_report = include_failure_var.get(),
        prev_report_path       = prev_report_path or None,
        include_trend          = include_trend,
        threshold              = threshold,
        cutoff_date            = cutoff_date,
        show_all_dates         = show_all_dates_var.get(),
        sync_baselines         = sync_baselines_var.get(),
        report_month           = report_month_var.get().strip(),
    )

    log.info("Starting dashboard generation: %s", output_path)
    generate_btn.config(state="disabled")
    # Show the pre-reserved progress bar (no layout shift — it lives in a fixed-height frame)
    progress_bar.grid()
    progress_bar.start()
    threading.Thread(target=_run_in_thread, args=(request, progress_bar), daemon=True).start()


# ==============================================================================
# TOGGLE HELPERS
# ==============================================================================

def toggle_rmm_state():
    state = tk.DISABLED if skip_rmm_var.get() else tk.NORMAL
    rmm_entry.config(state=state)
    rmm_browse_btn.config(state=state)


def toggle_patch_state():
    state = tk.NORMAL if include_patch_var.get() else tk.DISABLED
    patch_entry.config(state=state)
    patch_browse_btn.config(state=state)


def toggle_trend_state():
    state = tk.NORMAL if include_trend_var.get() else tk.DISABLED
    prev_report_entry.config(state=state)
    prev_report_browse_btn.config(state=state)


def toggle_date_state():
    date_entry.config(state=tk.DISABLED if show_all_dates_var.get() else tk.NORMAL)


def toggle_failure_state():
    state = tk.NORMAL if include_failure_var.get() else tk.DISABLED
    failure_entry.config(state=state)
    failure_browse_btn.config(state=state)


# ==============================================================================
# ROOT WINDOW & WIDGETS
# ==============================================================================

root = tk.Tk()
root.title("N-able CVE Dashboard & Triage Tool")
root.geometry("570x860")
root.resizable(False, True)

# ── Menu bar ──────────────────────────────────────────────────────────────────
menubar   = tk.Menu(root)

view_menu = tk.Menu(menubar, tearoff=0)
view_menu.add_command(label="🌙  Dark Mode", command=toggle_dark_mode)
menubar.add_cascade(label="View", menu=view_menu)

help_menu = tk.Menu(menubar, tearoff=0)
help_menu.add_command(label="Update CVEs  (git pull cvelistV5)", command=update_cve_list)
help_menu.add_separator()
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)

root.config(menu=menubar)

# ── Title ─────────────────────────────────────────────────────────────────────
tk.Label(root, text="N-able CVE Dashboard & Triage Tool",
         font=("Arial", 13, "bold")).pack(pady=(12, 4))

# ── Vulnerability report ──────────────────────────────────────────────────────
tk.Label(root, text="Vulnerability / CVE Report  (CSV or XLSX)",
         font=("Arial", 9, "bold")).pack(anchor="w", padx=14)
vuln_var   = tk.StringVar()
vuln_entry = tk.Entry(root, textvariable=vuln_var, width=55, state="readonly")
vuln_entry.pack(padx=14)
tk.Button(root, text="Browse", command=lambda: select_file(vuln_var)).pack()

# ── RMM / Device inventory ────────────────────────────────────────────────────
tk.Label(root, text="Device Inventory / RMM Report  (CSV or XLSX)",
         font=("Arial", 9, "bold")).pack(anchor="w", padx=14, pady=(8, 0))
rmm_var        = tk.StringVar()
rmm_frame      = tk.Frame(root)
rmm_frame.pack(fill="x", padx=14)
rmm_entry      = tk.Entry(rmm_frame, textvariable=rmm_var, width=44, state="readonly")
rmm_entry.pack(side=tk.LEFT)
rmm_browse_btn = tk.Button(rmm_frame, text="Browse", command=lambda: select_file(rmm_var))
rmm_browse_btn.pack(side=tk.LEFT, padx=4)
skip_rmm_var   = tk.BooleanVar()
tk.Checkbutton(root, text="Skip RMM (CVE export includes device info)",
               variable=skip_rmm_var, command=toggle_rmm_state).pack(anchor="w", padx=14)

# ── CVE score threshold ───────────────────────────────────────────────────────
score_frame = tk.Frame(root)
score_frame.pack(anchor="w", padx=14, pady=(8, 0))
tk.Label(score_frame, text="Minimum CVE Score:", font=("Arial", 9, "bold")).pack(side=tk.LEFT)
score_var = tk.StringVar(value="9.0")
tk.Entry(score_frame, textvariable=score_var, width=6).pack(side=tk.LEFT, padx=6)

# ── Stale-device cutoff date ──────────────────────────────────────────────────
date_frame = tk.Frame(root)
date_frame.pack(anchor="w", padx=14, pady=(6, 0))
tk.Label(date_frame, text="Exclude stale devices last seen before",
         font=("Arial", 9, "bold")).pack(side=tk.LEFT)
date_var       = tk.StringVar()
_default_since = (date.today() - timedelta(days=90)).strftime("%d/%m/%Y")
date_var.set(_default_since)
date_entry = tk.Entry(date_frame, textvariable=date_var, width=12)
date_entry.pack(side=tk.LEFT, padx=6)
tk.Label(date_frame, text="(dd/mm/yyyy)").pack(side=tk.LEFT, padx=4)
show_all_dates_var = tk.BooleanVar()
tk.Checkbutton(date_frame, text="Show All Dates",
               variable=show_all_dates_var, command=toggle_date_state).pack(side=tk.LEFT)
toggle_date_state()

# ── Report month label ────────────────────────────────────────────────────────
month_frame = tk.Frame(root)
month_frame.pack(anchor="w", padx=14, pady=(6, 0))
tk.Label(month_frame, text="Report Month:", font=("Arial", 9, "bold")).pack(side=tk.LEFT)
report_month_var = tk.StringVar(value=datetime.now().strftime("%B %Y"))
tk.Entry(month_frame, textvariable=report_month_var, width=15).pack(side=tk.LEFT, padx=6)

# ── Patch report ──────────────────────────────────────────────────────────────
tk.Label(root, text="Patch Report  (optional, CSV or XLSX)",
         font=("Arial", 9, "bold")).pack(anchor="w", padx=14, pady=(10, 0))
patch_var        = tk.StringVar()
patch_frame      = tk.Frame(root)
patch_frame.pack(fill="x", padx=14)
patch_entry      = tk.Entry(patch_frame, textvariable=patch_var, width=44, state="disabled")
patch_entry.pack(side=tk.LEFT)
patch_browse_btn = tk.Button(patch_frame, text="Browse",
                             command=lambda: select_file(patch_var), state="disabled")
patch_browse_btn.pack(side=tk.LEFT, padx=4)
include_patch_var = tk.BooleanVar()
tk.Checkbutton(root, text="Include Patch Report matching",
               variable=include_patch_var, command=toggle_patch_state).pack(anchor="w", padx=14)

# ── Patch failure report ──────────────────────────────────────────────────────
tk.Label(root, text="Patch Failure Report  (optional, CSV)",
         font=("Arial", 9, "bold")).pack(anchor="w", padx=14, pady=(6, 0))
failure_var        = tk.StringVar()
failure_frame      = tk.Frame(root)
failure_frame.pack(fill="x", padx=14)
failure_entry      = tk.Entry(failure_frame, textvariable=failure_var, width=44, state="disabled")
failure_entry.pack(side=tk.LEFT)
failure_browse_btn = tk.Button(
    failure_frame, text="Browse",
    command=lambda: select_file(failure_var, [("CSV Files", "*.csv")]),
    state="disabled",
)
failure_browse_btn.pack(side=tk.LEFT, padx=4)
include_failure_var = tk.BooleanVar()
tk.Checkbutton(root, text="Include Patch Failure analysis",
               variable=include_failure_var,
               command=toggle_failure_state).pack(anchor="w", padx=14)

# ── Previous dashboard (trend) ────────────────────────────────────────────────
tk.Label(root, text="Previous Dashboard  (optional, for M-o-M trends)",
         font=("Arial", 9, "bold")).pack(anchor="w", padx=14, pady=(10, 0))
prev_report_var = tk.StringVar()
prev_frame      = tk.Frame(root)
prev_frame.pack(fill="x", padx=14)
prev_report_entry = tk.Entry(prev_frame, textvariable=prev_report_var, width=44, state="disabled")
prev_report_entry.pack(side=tk.LEFT)
prev_report_browse_btn = tk.Button(
    prev_frame, text="Browse",
    command=lambda: select_file(prev_report_var, [("Excel Files", "*.xlsx")]),
    state="disabled",
)
prev_report_browse_btn.pack(side=tk.LEFT, padx=4)
include_trend_var = tk.BooleanVar()
tk.Checkbutton(root, text="Include month-over-month trend analysis",
               variable=include_trend_var, command=toggle_trend_state).pack(anchor="w", padx=14)

# ── Sync baselines ────────────────────────────────────────────────────────────
sync_baselines_var = tk.BooleanVar()
tk.Checkbutton(root, text="Refresh product baselines before run",
               variable=sync_baselines_var).pack(anchor="w", padx=14, pady=(6, 0))

# ── Generate button ───────────────────────────────────────────────────────────
generate_btn = tk.Button(
    root,
    text="GENERATE COMPLETE DASHBOARD",
    command=process_reports,
    bg="#0078D7", fg="white",
    font=("Arial", 10, "bold"),
    height=2,
)
generate_btn.pack(pady=14)

# ── Fix: stable progress bar — lives in a fixed-height frame so the layout
#    never shifts when it appears or disappears between runs. ──────────────────
_progress_frame = tk.Frame(root, height=24)
_progress_frame.pack(fill="x", padx=14, pady=(0, 6))
_progress_frame.pack_propagate(False)        # hold height even when bar is hidden
progress_bar = ttk.Progressbar(_progress_frame, mode="indeterminate")
progress_bar.grid(row=0, column=0, sticky="ew")
_progress_frame.columnconfigure(0, weight=1)
progress_bar.grid_remove()                   # hidden until a run starts

root.mainloop()
