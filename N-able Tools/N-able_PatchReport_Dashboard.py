#!/usr/bin/env python3
"""
cve_patch_match_v3.py
---------------------
Matches a Patch Report (CSV or Excel) against a CVE detections workbook.

Filters:
  --date-from   Include only rows where Last Response >= this date
  --min-score   Include only rows where Vulnerability Score >= this value

KB Mapping:
  --kb-map  "ssms=KB4022619,KB5040711"   Fallback matching: if a CVE product
  is "Device in patch report - product not found", check whether any patch
  on that device contains one of the mapped KB numbers.

Output sheets:  CVE Marked | Summary | Filter Info | Patch Source
"""

import re
import sys
import argparse
import calendar as cal_module
from pathlib import Path
from datetime import datetime, date

import pandas as pd


# ── Normalisation ────────────────────────────────────────────────────────────

def norm_compact(v):
    return re.sub(r"[^a-z0-9]+", "", str(v).lower()).strip()

def norm_text(v):
    return re.sub(r"[^a-z0-9]+", " ", str(v).lower()).strip()


# ── Product detection ─────────────────────────────────────────────────────────

_PRODUCT_MAP = [
    ("mozilla firefox (x64)",                   "firefox"),
    ("mozilla firefox (x86)",                   "firefox"),
    ("firefox (x64)",                           "firefox"),
    ("firefox (x86)",                           "firefox"),
    ("mozilla firefox",                         "firefox"),
    ("firefox",                                 "firefox"),
    ("google chrome",                           "chrome"),
    ("chrome (x64)",                            "chrome"),
    ("chrome (x86)",                            "chrome"),
    ("chrome",                                  "chrome"),
    ("microsoft edge 80",                       "edge"),
    ("microsoft edge",                          "edge"),
    ("edge",                                    "edge"),
    ("vlc media player (x64)",                  "vlc"),
    ("vlc media player (x86)",                  "vlc"),
    ("vlc media player",                        "vlc"),
    ("vlc (x64)",                               "vlc"),
    ("vlc (x86)",                               "vlc"),
    ("vlc",                                     "vlc"),
    ("microsoft sql server management studio",  "ssms"),
    ("sql server management studio",            "ssms"),
    ("microsoft office 365",                    "office365"),
    ("office 365",                              "office365"),
    ("microsoft office",                        "office"),
    ("office",                                  "office"),
    ("windows 11",                              "windows"),
    ("windows 10",                              "windows"),
    ("windows",                                 "windows"),
]

# Human-readable labels for the GUI product dropdown
PRODUCT_LABELS = {
    "firefox":   "Mozilla Firefox",
    "chrome":    "Google Chrome",
    "edge":      "Microsoft Edge 80+",
    "vlc":       "VLC media player",
    "ssms":      "SQL Server Management Studio",
    "office365": "Microsoft Office 365",
    "office":    "Microsoft Office",
    "windows":   "Windows",
}

def detect_product(text):
    t = norm_text(str(text))
    for key, product in _PRODUCT_MAP:
        if norm_text(key) in t:
            return product
    return ""

def extract_kbs(text):
    """Return set of uppercase KB numbers found in a string, e.g. {'KB4022619'}."""
    return {kb.upper() for kb in re.findall(r"KB\d+", str(text), re.IGNORECASE)}


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_excel_safe(df):
    out = df.copy()
    for col in out.columns:
        if isinstance(out[col].dtype, pd.DatetimeTZDtype):
            out[col] = out[col].dt.tz_localize(None)
    return out

_STATUS_RANK = {
    "Installed": 6, "Reboot Required": 5, "Installing": 4,
    "Pending": 3,   "Missing": 2,         "Failed": 1,
}

_STATUS_LABEL = {
    "Installed":       "Matched - installed",
    "Reboot Required": "Matched - reboot required",
    "Installing":      "Matched - installing",
    "Pending":         "Matched - pending",
    "Missing":         "Matched - missing",
    "Failed":          "Matched - failed",
}

def parse_last_response(series):
    """Parse Last Response column; 'Not Found in RMM' becomes NaT."""
    return pd.to_datetime(
        series, format="%m/%d/%y %I:%M:%S %p", errors="coerce"
    )

_DATE_FORMATS = [
    "%d/%m/%Y", "%d/%m/%y",
    "%m/%d/%Y", "%m/%d/%y",
    "%Y-%m-%d", "%d-%m-%Y", "%d-%m-%y",
]

def parse_input_date(s):
    s = s.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    raise ValueError(
        f"Cannot parse date '{s}'.  Expected: DD/MM/YYYY, MM/DD/YYYY, or YYYY-MM-DD"
    )

def parse_kb_map(raw: dict) -> dict:
    """
    Normalise kb_map values to sets of uppercase KB strings.
    Input:  {"ssms": "KB4022619, KB5040711"}   or   {"ssms": ["KB4022619"]}
    Output: {"ssms": {"KB4022619", "KB5040711"}}
    """
    out = {}
    for product, kbs in raw.items():
        if isinstance(kbs, str):
            kbs = re.split(r"[,\s]+", kbs)
        out[product] = {k.strip().upper() for k in kbs if k.strip()}
    return out


# ── Core processing ───────────────────────────────────────────────────────────

def process_files(
    patch_path,
    cve_path,
    out_path,
    date_from=None,    # date or None  (Last Response >= date_from)
    min_score=None,    # float or None
    kb_map=None,       # {"ssms": {"KB4022619", ...}, ...}  or None
):
    """
    Returns (total_rows, filtered_rows, csv_path).
    """
    kb_map = parse_kb_map(kb_map or {})

    # ── Load ─────────────────────────────────────────────────────────────────
    if str(patch_path).lower().endswith(".csv"):
        patch = pd.read_csv(patch_path)
    else:
        patch = pd.read_excel(patch_path)

    xl = pd.ExcelFile(cve_path)
    target = next(
        (s for s in ["All Detections", "Sheet1"] if s in xl.sheet_names),
        xl.sheet_names[0],
    )
    cve = xl.parse(target)

    # ── Validate columns ──────────────────────────────────────────────────────
    miss_p = {"Client","Site","Device","Status","Patch","Discovered / Install Date"} - set(patch.columns)
    miss_c = {"Vulnerability Name","Name","Affected Products","Customer","Site"}     - set(cve.columns)
    if miss_p: raise ValueError(f"Patch report missing: {', '.join(sorted(miss_p))}")
    if miss_c: raise ValueError(f"CVE report missing: {', '.join(sorted(miss_c))}")

    total_rows = len(cve)

    # ── Apply filters ─────────────────────────────────────────────────────────
    cve = cve.copy()
    if min_score is not None and "Vulnerability Score" in cve.columns:
        cve = cve[pd.to_numeric(cve["Vulnerability Score"], errors="coerce").fillna(0) >= min_score]

    if date_from is not None and "Last Response" in cve.columns:
        parsed = parse_last_response(cve["Last Response"])
        cve = cve[parsed.dt.date >= date_from]

    filtered_rows = len(cve)

    # ── Enrich patch ──────────────────────────────────────────────────────────
    patch = patch.copy()
    patch["_ck"] = patch["Client"].map(norm_compact)
    patch["_sk"] = patch["Site"].map(norm_compact)
    patch["_dk"] = patch["Device"].map(norm_compact)
    patch["_pk"] = patch["Patch"].map(detect_product)
    patch["_pd"] = pd.to_datetime(patch["Discovered / Install Date"], errors="coerce")
    patch["_sr"] = patch["Status"].map(_STATUS_RANK).fillna(0)
    patch["_kbs"] = patch["Patch"].apply(extract_kbs)

    patch_devices = set(zip(patch["_ck"], patch["_sk"], patch["_dk"]))

    # Pre-build KB lookup: (ck, sk, dk, kb) -> best patch info dict
    # Stored as plain dicts so pandas apply() does not expand them.
    kb_patch_lookup = {}   # key=(ck,sk,dk,kb)  value=dict
    for _, row in patch.sort_values(["_sr","_pd"], ascending=[False,False]).iterrows():
        for kb in row["_kbs"]:
            key = (row["_ck"], row["_sk"], row["_dk"], kb)
            if key not in kb_patch_lookup:   # first = best rank
                kb_patch_lookup[key] = {
                    "Status": row["Status"],
                    "Patch":  row["Patch"],
                    "_pd":    row["_pd"],
                    "_sr":    row["_sr"],
                }

    # ── Enrich CVE ────────────────────────────────────────────────────────────
    cve["_ck"] = cve["Customer"].map(norm_compact)
    cve["_sk"] = cve["Site"].map(norm_compact)
    cve["_dk"] = cve["Name"].map(norm_compact)
    cve["_pk"] = cve["Affected Products"].map(detect_product)

    for dc in ["Date Published", "First detected", "Last updated"]:
        if dc in cve.columns:
            cve[dc] = (
                pd.to_datetime(
                    cve[dc].astype(str).str.replace(" UTC", "", regex=False),
                    errors="coerce", utc=True,
                ).dt.tz_localize(None)
            )

    # ── Primary merge: product-key match ─────────────────────────────────────
    merged = cve.merge(
        patch[["_ck","_sk","_dk","_pk","Status","Patch","_pd","_sr"]].rename(columns={"_ck":"_mck"}),
        left_on=["_ck","_sk","_dk","_pk"],
        right_on=["_mck","_sk","_dk","_pk"],
        how="left", suffixes=("","_p"),
    )
    merged = merged.sort_values(["_sr","_pd"], ascending=[False,False], na_position="last")
    gcols = [c for c in cve.columns if not c.startswith("_")]
    best = merged.groupby(gcols, dropna=False, as_index=False).first()

    # ── KB fallback: rows still unmatched but device is in patch report ───────
    # Iterate directly (not via apply) to avoid pandas expanding returned dicts.
    for i, row in best.iterrows():
        if not pd.isna(row.get("Patch")):
            continue   # already matched by product name
        prod = row.get("_pk", "")
        if prod not in kb_map:
            continue
        ck = row.get("_ck"); sk = row.get("_sk"); dk = row.get("_dk")
        if (ck, sk, dk) not in patch_devices:
            continue
        # Pick the highest-ranked KB match for this device
        best_fb = None
        for kb in kb_map[prod]:
            fb = kb_patch_lookup.get((ck, sk, dk, kb))
            if fb and (best_fb is None or fb["_sr"] > best_fb["_sr"]):
                best_fb = fb
        if best_fb:
            best.at[i, "Status"] = best_fb["Status"]
            best.at[i, "Patch"]  = best_fb["Patch"]
            best.at[i, "_pd"]    = best_fb["_pd"]
            best.at[i, "_sr"]    = best_fb["_sr"]

    # ── Classify ──────────────────────────────────────────────────────────────
    def classify(row):
        if not pd.isna(row.get("Patch")):
            return _STATUS_LABEL.get(
                str(row.get("Status","")).strip(),
                f"Matched - {str(row.get('Status','')).lower()}"
            )
        key = (row["_ck"], row["_sk"], row["_dk"])
        if key in patch_devices:
            prod = row["_pk"]
            if prod in kb_map:
                kbs_str = ", ".join(sorted(kb_map[prod]))
                return f"Device in patch report - product not found  [KB ref: {kbs_str}]"
            return "Device in patch report - product not found"
        return "Not found in patch report"

    best["Patch Match Result"] = best.apply(classify, axis=1)
    best["Resolved (from Patch Report)"] = (
        best["Patch Match Result"].eq("Matched - installed").map({True:"Yes",False:"No"})
    )
    best = best.rename(columns={"Patch":"Matched Patch","_pd":"Patch Install Date"})
    best = best.drop(columns=[c for c in best.columns if c.startswith("_")], errors="ignore")

    # ── Summary ───────────────────────────────────────────────────────────────
    summary = (
        best.groupby(["Affected Products","Patch Match Result"], dropna=False)
        .size().reset_index(name="Count")
        .sort_values(["Affected Products","Count"], ascending=[True,False])
    )

    # ── Filter / KB info sheet ────────────────────────────────────────────────
    kb_rows = [
        {"Parameter": f"KB mapping – {PRODUCT_LABELS.get(p, p)}", "Value": ", ".join(sorted(kbs))}
        for p, kbs in kb_map.items()
    ] if kb_map else [{"Parameter": "KB mappings", "Value": "— (none defined)"}]

    meta = pd.DataFrame([
        {"Parameter": "Last Response from",      "Value": str(date_from) if date_from else "— (no filter)"},
        {"Parameter": "Min Vulnerability Score",  "Value": str(min_score) if min_score is not None else "— (no filter)"},
        {"Parameter": "CVE rows (before filter)", "Value": total_rows},
        {"Parameter": "CVE rows (after filter)",  "Value": filtered_rows},
    ] + kb_rows)

    # ── Trimmed view sheet ────────────────────────────────────────────────────
    slim_cols = [
        "Vulnerability Name",
        "Name",
        "Device Type",
        "Threat Status",
        "Vulnerability Score",
        "Affected Products",
        "Date Published",
        "First detected",
        "Last updated",
        "Last Response",
        "Matched Patch",
        "Patch Install Date",
        "Patch Match Result",
        "Resolved (from Patch Report)",
    ]
    # Keep only columns that actually exist (guard against schema changes)
    slim_cols_present = [c for c in slim_cols if c in best.columns]
    slim = make_excel_safe(best[slim_cols_present])

    # ── Write ─────────────────────────────────────────────────────────────────
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        slim.to_excel(                 writer, sheet_name="CVE Marked",   index=False)
        make_excel_safe(best).to_excel(writer, sheet_name="Full Data",    index=False)
        summary.to_excel(              writer, sheet_name="Summary",      index=False)
        meta.to_excel(                 writer, sheet_name="Filter Info",  index=False)
        make_excel_safe(patch).to_excel(writer, sheet_name="Patch Source", index=False)

    csv_out = str(Path(out_path).with_suffix(".csv"))
    best.to_csv(csv_out, index=False)
    return total_rows, filtered_rows, csv_out


# ── Tkinter calendar popup ────────────────────────────────────────────────────

def _build_calendar_popup(parent, initial_date=None, callback=None):
    """
    Pop up a simple month-calendar window.
    Calls callback(date_object) when a day is clicked, then closes.
    """
    import tkinter as tk
    from tkinter import ttk

    today = date.today()
    sel = initial_date or today

    popup = tk.Toplevel(parent)
    popup.title("Select Date")
    popup.resizable(False, False)
    popup.grab_set()

    state = {"year": sel.year, "month": sel.month}

    # ── header ──
    header = ttk.Frame(popup, padding=(8, 6))
    header.pack(fill="x")

    lbl_month = ttk.Label(header, width=16, anchor="center", font=("", 10, "bold"))
    btn_prev  = ttk.Button(header, text="◀", width=3)
    btn_next  = ttk.Button(header, text="▶", width=3)

    btn_prev.pack(side="left")
    lbl_month.pack(side="left", expand=True)
    btn_next.pack(side="right")

    # ── weekday labels ──
    day_frame = ttk.Frame(popup, padding=(4, 0))
    day_frame.pack()
    for i, d in enumerate(["Mo","Tu","We","Th","Fr","Sa","Su"]):
        ttk.Label(day_frame, text=d, width=4, anchor="center",
                  foreground="#555").grid(row=0, column=i)

    # ── day buttons ──
    grid_frame = ttk.Frame(popup, padding=(4, 2, 4, 8))
    grid_frame.pack()
    day_btns = []
    for r in range(6):
        row_btns = []
        for c in range(7):
            b = tk.Button(grid_frame, width=3, relief="flat",
                          font=("", 9),
                          activebackground="#4a90d9",
                          activeforeground="white")
            b.grid(row=r, column=c, padx=1, pady=1)
            row_btns.append(b)
        day_btns.append(row_btns)

    def refresh():
        y, m = state["year"], state["month"]
        lbl_month.config(text=f"{cal_module.month_name[m]}  {y}")
        first_wd, num_days = cal_module.monthrange(y, m)
        # clear all
        for r in range(6):
            for c in range(7):
                day_btns[r][c].config(text="", state="disabled",
                                      bg=popup.cget("bg"))
        # fill days
        for day_n in range(1, num_days + 1):
            wd = (first_wd + day_n - 1) % 7
            row = (first_wd + day_n - 1) // 7
            d = date(y, m, day_n)
            is_today   = (d == today)
            is_sel     = (d == state.get("selected"))
            bg = "#4a90d9" if is_sel else ("#d6eaff" if is_today else popup.cget("bg"))
            fg = "white"   if is_sel else "black"

            def on_click(chosen=d):
                state["selected"] = chosen
                refresh()
                if callback:
                    callback(chosen)
                popup.destroy()

            day_btns[row][wd].config(
                text=str(day_n), state="normal",
                bg=bg, fg=fg, command=on_click,
            )

    def prev_month():
        if state["month"] == 1:
            state["year"]  -= 1
            state["month"]  = 12
        else:
            state["month"] -= 1
        refresh()

    def next_month():
        if state["month"] == 12:
            state["year"]  += 1
            state["month"]  = 1
        else:
            state["month"] += 1
        refresh()

    btn_prev.config(command=prev_month)
    btn_next.config(command=next_month)
    state["selected"] = sel
    refresh()

    # centre over parent
    popup.update_idletasks()
    px = parent.winfo_rootx() + (parent.winfo_width()  - popup.winfo_reqwidth())  // 2
    py = parent.winfo_rooty() + (parent.winfo_height() - popup.winfo_reqheight()) // 2
    popup.geometry(f"+{px}+{py}")


# ── GUI ───────────────────────────────────────────────────────────────────────

def _run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    class App:
        def __init__(self, root):
            self.root = root
            root.title("CVE Patch Matcher v3")
            root.resizable(True, True)

            self.patch_var     = tk.StringVar()
            self.cve_var       = tk.StringVar()
            self.out_var       = tk.StringVar()
            self.date_from_var = tk.StringVar()
            self.min_score_var = tk.StringVar()
            # kb_map: list of (product_key, kb_string) tuples
            self._kb_rows = []

            frame = ttk.Frame(root, padding=16)
            frame.pack(fill="both", expand=True)
            frame.columnconfigure(1, weight=1)

            # ── File rows ──────────────────────────────────────────────────
            file_rows = [
                ("Patch Report (CSV / Excel)", self.patch_var, self._pick_patch, "Browse"),
                ("CVE / Detections (Excel)",   self.cve_var,   self._pick_cve,   "Browse"),
                ("Output Excel",               self.out_var,   self._pick_out,   "Save As"),
            ]
            for i, (lbl, var, cmd, btn_lbl) in enumerate(file_rows):
                ttk.Label(frame, text=lbl).grid(
                    row=i, column=0, sticky="w", pady=5, padx=(0, 8))
                ttk.Entry(frame, textvariable=var, width=64).grid(
                    row=i, column=1, columnspan=2, sticky="ew", padx=(0, 6))
                ttk.Button(frame, text=btn_lbl, command=cmd, width=9).grid(
                    row=i, column=3, sticky="w")

            ttk.Separator(frame, orient="horizontal").grid(
                row=3, column=0, columnspan=4, sticky="ew", pady=(10, 6))

            # ── Filter heading ─────────────────────────────────────────────
            ttk.Label(frame, text="Filters  (leave blank for no filter)",
                      font=("", 9, "bold")).grid(
                row=4, column=0, columnspan=4, sticky="w", pady=(0, 6))

            # ── Date from (calendar) ───────────────────────────────────────
            date_row = ttk.Frame(frame)
            date_row.grid(row=5, column=0, columnspan=4, sticky="w", pady=(0, 4))

            ttk.Label(date_row, text="Last Response  from").pack(side="left", padx=(0, 6))
            self._date_entry = ttk.Entry(date_row, textvariable=self.date_from_var, width=13)
            self._date_entry.pack(side="left")
            ttk.Label(date_row, text="DD/MM/YYYY", foreground="grey").pack(
                side="left", padx=(4, 10))
            ttk.Button(date_row, text="📅 Pick", command=self._pick_date, width=8).pack(
                side="left")
            ttk.Button(date_row, text="✕ Clear", command=lambda: self.date_from_var.set(""),
                       width=7).pack(side="left", padx=(4, 0))

            # ── Min score ──────────────────────────────────────────────────
            score_row = ttk.Frame(frame)
            score_row.grid(row=6, column=0, columnspan=4, sticky="w", pady=(0, 6))

            ttk.Label(score_row, text="Min Vulnerability Score  ≥").pack(side="left", padx=(0, 6))
            ttk.Entry(score_row, textvariable=self.min_score_var, width=8).pack(side="left")
            ttk.Label(score_row, text="e.g. 9.0   (leave blank for all)",
                      foreground="grey").pack(side="left", padx=(8, 0))

            ttk.Separator(frame, orient="horizontal").grid(
                row=7, column=0, columnspan=4, sticky="ew", pady=(4, 6))

            # ── KB mappings ────────────────────────────────────────────────
            ttk.Label(frame, text="KB Fallback Mappings  (optional)",
                      font=("", 9, "bold")).grid(
                row=8, column=0, columnspan=4, sticky="w", pady=(0, 4))

            ttk.Label(frame,
                      text="When a product is not found by name, also search for these KBs on the device.",
                      foreground="grey").grid(
                row=9, column=0, columnspan=4, sticky="w", pady=(0, 6))

            # ── KB entry row ───────────────────────────────────────────────
            kb_input = ttk.Frame(frame)
            kb_input.grid(row=10, column=0, columnspan=4, sticky="w", pady=(0, 4))

            ttk.Label(kb_input, text="Product").pack(side="left", padx=(0, 4))
            self._kb_product_var = tk.StringVar()
            product_names = list(PRODUCT_LABELS.values())
            self._kb_product_cb = ttk.Combobox(
                kb_input, textvariable=self._kb_product_var,
                values=product_names, width=28, state="readonly")
            self._kb_product_cb.pack(side="left", padx=(0, 10))
            self._kb_product_cb.set(product_names[4])   # default: SSMS

            ttk.Label(kb_input, text="KB numbers (comma-separated)").pack(side="left", padx=(0, 4))
            self._kb_numbers_var = tk.StringVar()
            ttk.Entry(kb_input, textvariable=self._kb_numbers_var, width=30).pack(side="left")
            ttk.Button(kb_input, text="Add", command=self._add_kb_row, width=6).pack(
                side="left", padx=(8, 0))

            # ── KB list ────────────────────────────────────────────────────
            kb_list_frame = ttk.Frame(frame)
            kb_list_frame.grid(row=11, column=0, columnspan=4, sticky="ew", pady=(0, 6))
            kb_list_frame.columnconfigure(0, weight=1)

            self._kb_listbox = tk.Listbox(
                kb_list_frame, height=4, font=("Courier", 9),
                selectmode="single", activestyle="none",
                selectbackground="#4a90d9")
            self._kb_listbox.grid(row=0, column=0, sticky="ew")
            sb = ttk.Scrollbar(kb_list_frame, orient="vertical",
                               command=self._kb_listbox.yview)
            sb.grid(row=0, column=1, sticky="ns")
            self._kb_listbox.config(yscrollcommand=sb.set)

            ttk.Button(kb_list_frame, text="Remove selected",
                       command=self._remove_kb_row).grid(
                row=1, column=0, sticky="w", pady=(3, 0))

            ttk.Separator(frame, orient="horizontal").grid(
                row=12, column=0, columnspan=4, sticky="ew", pady=(4, 6))

            # ── Process ────────────────────────────────────────────────────
            ttk.Button(frame, text="▶  Process", command=self._run).grid(
                row=13, column=0, columnspan=4, sticky="ew", pady=(0, 6))

            # ── Log ────────────────────────────────────────────────────────
            self.log = tk.Text(frame, height=10, wrap="word")
            self.log.grid(row=14, column=0, columnspan=4, sticky="nsew")
            frame.rowconfigure(14, weight=1)

            root.update_idletasks()
            root.minsize(700, root.winfo_reqheight())

        # ── File pickers ──────────────────────────────────────────────────

        def _pick_patch(self):
            v = filedialog.askopenfilename(
                filetypes=[("CSV / Excel","*.csv *.xlsx *.xls"), ("All files","*.*")])
            if v: self.patch_var.set(v)

        def _pick_cve(self):
            v = filedialog.askopenfilename(
                filetypes=[("Excel","*.xlsx *.xls"), ("All files","*.*")])
            if v: self.cve_var.set(v)

        def _pick_out(self):
            v = filedialog.asksaveasfilename(
                defaultextension=".xlsx", filetypes=[("Excel Workbook","*.xlsx")])
            if v: self.out_var.set(v)

        # ── Calendar ──────────────────────────────────────────────────────

        def _pick_date(self):
            current = None
            raw = self.date_from_var.get().strip()
            if raw:
                try:
                    current = parse_input_date(raw)
                except ValueError:
                    pass

            def on_select(d):
                self.date_from_var.set(d.strftime("%d/%m/%Y"))

            _build_calendar_popup(self.root, initial_date=current, callback=on_select)

        # ── KB list ───────────────────────────────────────────────────────

        def _add_kb_row(self):
            product_label = self._kb_product_var.get().strip()
            kbs_raw       = self._kb_numbers_var.get().strip()
            if not product_label or not kbs_raw:
                return
            # find product key from label
            product_key = next(
                (k for k, v in PRODUCT_LABELS.items() if v == product_label),
                product_label.lower()
            )
            kbs = [k.strip().upper() for k in re.split(r"[,\s]+", kbs_raw) if k.strip()]
            if not kbs:
                return
            display = f"{product_label:<32}  {', '.join(kbs)}"
            # deduplicate by product key
            self._kb_rows = [(pk, k) for pk, k in self._kb_rows if pk != product_key]
            self._kb_rows.append((product_key, kbs))
            self._refresh_kb_listbox()
            self._kb_numbers_var.set("")

        def _remove_kb_row(self):
            sel = self._kb_listbox.curselection()
            if sel:
                del self._kb_rows[sel[0]]
                self._refresh_kb_listbox()

        def _refresh_kb_listbox(self):
            self._kb_listbox.delete(0, "end")
            for pk, kbs in self._kb_rows:
                label = PRODUCT_LABELS.get(pk, pk)
                self._kb_listbox.insert(
                    "end", f"  {label:<32}  {', '.join(kbs)}"
                )

        def _get_kb_map(self):
            return {pk: kbs for pk, kbs in self._kb_rows}

        # ── Run ───────────────────────────────────────────────────────────

        def _run(self):
            self.log.delete("1.0", "end")
            try:
                date_from = None
                min_score = None

                raw_date = self.date_from_var.get().strip()
                if raw_date:
                    date_from = parse_input_date(raw_date)

                raw_score = self.min_score_var.get().strip()
                if raw_score:
                    try:
                        min_score = float(raw_score)
                    except ValueError:
                        raise ValueError(f"Min Score must be a number (got '{raw_score}').")

                kb_map = self._get_kb_map()

                self._log("Filters:")
                self._log(f"  Last Response from : {date_from or '—'}")
                self._log(f"  Min Score          : {min_score or '—'}")
                if kb_map:
                    for pk, kbs in kb_map.items():
                        self._log(f"  KB map  {PRODUCT_LABELS.get(pk, pk):<28} → {', '.join(kbs)}")
                self._log("")
                self._log("Processing…")

                total, filtered, csv_out = process_files(
                    self.patch_var.get(), self.cve_var.get(), self.out_var.get(),
                    date_from=date_from, min_score=min_score, kb_map=kb_map,
                )
                self._log(f"CVE rows before filter : {total}")
                self._log(f"CVE rows after  filter : {filtered}")
                self._log(f"Excel  → {self.out_var.get()}")
                self._log(f"CSV    → {csv_out}")
                self._log("Done.")
                messagebox.showinfo(
                    "Complete",
                    f"Done.\n\nRows before filter: {total}\nRows after filter:  {filtered}"
                )
            except Exception as exc:
                self._log(f"ERROR: {exc}")
                messagebox.showerror("Error", str(exc))

        def _log(self, text):
            self.log.insert("end", text + "\n")
            self.log.see("end")
            self.root.update_idletasks()

    root = tk.Tk()
    App(root)
    root.mainloop()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Match Patch Report against CVE detections workbook."
    )
    parser.add_argument("--patch")
    parser.add_argument("--cve")
    parser.add_argument("--out")
    parser.add_argument("--date-from",  help="Last Response >= date  (DD/MM/YYYY)")
    parser.add_argument("--min-score",  type=float)
    parser.add_argument(
        "--kb-map", action="append", metavar="PRODUCT=KB1,KB2",
        help="KB fallback e.g. --kb-map ssms=KB4022619,KB5040711  (repeatable)",
    )
    args = parser.parse_args()

    if args.patch and args.cve and args.out:
        date_from = parse_input_date(args.date_from) if args.date_from else None
        kb_map = {}
        for entry in (args.kb_map or []):
            if "=" in entry:
                prod, kbs = entry.split("=", 1)
                kb_map[prod.strip()] = kbs
        total, filtered, csv_out = process_files(
            args.patch, args.cve, args.out,
            date_from=date_from, min_score=args.min_score, kb_map=kb_map,
        )
        print(f"CVE rows before filter : {total}")
        print(f"CVE rows after  filter : {filtered}")
        print(f"Excel  -> {args.out}")
        print(f"CSV    -> {csv_out}")
    else:
        try:
            _run_gui()
        except ImportError:
            print("tkinter not available. Use CLI flags: --patch --cve --out")
            sys.exit(1)


if __name__ == "__main__":
    main()
