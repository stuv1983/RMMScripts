#!/usr/bin/env python3
"""
cve_patch_match_v4.py
---------------------
Matches a Patch Report (CSV or Excel) against a CVE detections workbook.

What changed from v3:
- Added automatic KB extraction from matched patch text
- Added version extraction from matched patch text
- Added fixed-version checking layer
- Default minimum CVE score is 9.0
- Simplified resolved status to Resolved / Unresolved

Notes:
- Fixed-version validation uses, in order:
    1. A "Fixed Version" column in the CVE workbook, if present
    2. BUILTIN_FIXED_VERSION_RULES below, if populated for a product/CVE
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


# ── Product detection ────────────────────────────────────────────────────────

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

# Optional built-in fixed version baselines.
# Example:
# BUILTIN_FIXED_VERSION_RULES = {
#     "chrome": {
#         "CVE-2026-12345": "136.0.7103.114",
#     },
#     "firefox": {
#         "CVE-2026-5678": "147.0.2",
#     },
# }
BUILTIN_FIXED_VERSION_RULES = {
}


def detect_product(text):
    t = norm_text(str(text))
    for key, product in _PRODUCT_MAP:
        if norm_text(key) in t:
            return product
    return ""


def extract_kbs(text):
    return sorted({kb.upper() for kb in re.findall(r"KB\d+", str(text), re.IGNORECASE)})


def extract_cves(text):
    return sorted({cve.upper() for cve in re.findall(r"CVE-\d{4}-\d{4,7}", str(text), re.IGNORECASE)})


def extract_versions(text):
    return re.findall(r"\b\d+(?:\.\d+){1,4}\b", str(text))


def extract_best_version(text):
    versions = extract_versions(text)
    if not versions:
        return ""
    versions = sorted(
        versions,
        key=lambda v: (len(v.split(".")), [int(x) for x in v.split(".")])
    )
    return versions[-1]


def parse_version(value):
    value = str(value).strip()
    if not value:
        return None
    parts = re.findall(r"\d+", value)
    if not parts:
        return None
    return tuple(int(p) for p in parts)


def version_gte(left, right):
    l = parse_version(left)
    r = parse_version(right)
    if l is None or r is None:
        return None
    max_len = max(len(l), len(r))
    l = l + (0,) * (max_len - len(l))
    r = r + (0,) * (max_len - len(r))
    return l >= r


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_excel_safe(df):
    out = df.copy()
    for col in out.columns:
        if isinstance(out[col].dtype, pd.DatetimeTZDtype):
            out[col] = out[col].dt.tz_localize(None)
    return out


_STATUS_RANK = {
    "Installed": 6,
    "Reboot Required": 5,
    "Installing": 4,
    "Pending": 3,
    "Missing": 2,
    "Failed": 1,
}

_STATUS_LABEL = {
    "Installed":       "Matched - installed",
    "Reboot Required": "Matched - reboot required",
    "Installing":      "Matched - installing",
    "Pending":         "Matched - pending",
    "Missing":         "Matched - missing",
    "Failed":          "Matched - failed",
}

_INSTALLED_STATUSES = {"Installed", "Reboot Required"}


def parse_last_response(series):
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
        f"Cannot parse date '{s}'. Expected: DD/MM/YYYY, MM/DD/YYYY, or YYYY-MM-DD"
    )


def resolve_fixed_version(row):
    # 1) Direct CVE workbook column
    if "Fixed Version" in row.index:
        value = str(row.get("Fixed Version", "")).strip()
        if value:
            return value, "CVE workbook column"

    # 2) Built-in map by product + CVE
    product = row.get("_pk", "")
    if not product:
        return "", ""

    rules = BUILTIN_FIXED_VERSION_RULES.get(product, {})
    vuln_name = str(row.get("Vulnerability Name", ""))
    for cve in extract_cves(vuln_name):
        if cve in rules:
            return rules[cve], f"Built-in rule ({cve})"

    return "", ""


def classify_version_check(row):
    patch_status = str(row.get("Status", "")).strip()
    patch_version = str(row.get("Matched Patch Version", "")).strip()
    fixed_version = str(row.get("Fixed Version Used", "")).strip()

    if patch_status not in _INSTALLED_STATUSES:
        if patch_status:
            return "Patch not yet installed"
        return "No patch evidence"

    if not fixed_version:
        if patch_version:
            return "Installed version found - no fixed baseline"
        return "Installed - version unknown"

    if not patch_version:
        return "Fixed baseline known - installed version not found"

    cmp_result = version_gte(patch_version, fixed_version)
    if cmp_result is True:
        return "Version compliant"
    if cmp_result is False:
        return "Below fixed version"
    return "Version comparison failed"


def classify_resolution(row):
    patch_status = str(row.get("Status", "")).strip()
    if patch_status in _INSTALLED_STATUSES:
        return "Resolved"
    return "Unresolved"


# ── Core processing ──────────────────────────────────────────────────────────

def process_files(
    patch_path,
    cve_path,
    out_path,
    date_from=None,
    min_score=9.0,
):
    """
    Returns (total_rows, filtered_rows, csv_path).
    """
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

    miss_p = {"Client", "Site", "Device", "Status", "Patch", "Discovered / Install Date"} - set(patch.columns)
    miss_c = {"Vulnerability Name", "Name", "Affected Products", "Customer", "Site"} - set(cve.columns)
    if miss_p:
        raise ValueError(f"Patch report missing: {', '.join(sorted(miss_p))}")
    if miss_c:
        raise ValueError(f"CVE report missing: {', '.join(sorted(miss_c))}")

    total_rows = len(cve)

    cve = cve.copy()
    if "Vulnerability Score" in cve.columns:
        cve = cve[
            pd.to_numeric(cve["Vulnerability Score"], errors="coerce").fillna(0) >= min_score
        ]

    if date_from is not None and "Last Response" in cve.columns:
        parsed = parse_last_response(cve["Last Response"])
        cve = cve[parsed.dt.date >= date_from]

    filtered_rows = len(cve)

    patch = patch.copy()
    patch["_ck"] = patch["Client"].map(norm_compact)
    patch["_sk"] = patch["Site"].map(norm_compact)
    patch["_dk"] = patch["Device"].map(norm_compact)
    patch["_pk"] = patch["Patch"].map(detect_product)
    patch["_pd"] = pd.to_datetime(patch["Discovered / Install Date"], errors="coerce")
    patch["_sr"] = patch["Status"].map(_STATUS_RANK).fillna(0)
    patch["_kbs"] = patch["Patch"].apply(extract_kbs)
    patch["_pv"] = patch["Patch"].apply(extract_best_version)

    patch_devices = set(zip(patch["_ck"], patch["_sk"], patch["_dk"]))

    cve["_ck"] = cve["Customer"].map(norm_compact)
    cve["_sk"] = cve["Site"].map(norm_compact)
    cve["_dk"] = cve["Name"].map(norm_compact)
    cve["_pk"] = cve["Affected Products"].map(detect_product)
    cve["_cves"] = cve["Vulnerability Name"].apply(extract_cves)

    for dc in ["Date Published", "First detected", "Last updated"]:
        if dc in cve.columns:
            cve[dc] = (
                pd.to_datetime(
                    cve[dc].astype(str).str.replace(" UTC", "", regex=False),
                    errors="coerce", utc=True,
                ).dt.tz_localize(None)
            )

    merged = cve.merge(
        patch[["_ck", "_sk", "_dk", "_pk", "Status", "Patch", "_pd", "_sr", "_kbs", "_pv"]].rename(columns={"_ck": "_mck"}),
        left_on=["_ck", "_sk", "_dk", "_pk"],
        right_on=["_mck", "_sk", "_dk", "_pk"],
        how="left",
        suffixes=("", "_p"),
    )
    merged = merged.sort_values(["_sr", "_pd"], ascending=[False, False], na_position="last")
    gcols = [c for c in cve.columns if not c.startswith("_")]
    best = merged.groupby(gcols, dropna=False, as_index=False).first()

    def classify_patch_match(row):
        if not pd.isna(row.get("Patch")):
            return _STATUS_LABEL.get(
                str(row.get("Status", "")).strip(),
                f"Matched - {str(row.get('Status', '')).lower()}"
            )
        key = (row["_ck"], row["_sk"], row["_dk"])
        if key in patch_devices:
            return "Device in patch report - product not found"
        return "Not found in patch report"

    best["Patch Match Result"] = best.apply(classify_patch_match, axis=1)

    fixed_versions = best.apply(resolve_fixed_version, axis=1, result_type="expand")
    fixed_versions.columns = ["Fixed Version Used", "Fixed Version Source"]
    best = pd.concat([best, fixed_versions], axis=1)

    best["Matched Patch Version"] = best["_pv"].fillna("")
    best["Matched KBs"] = best["_kbs"].apply(lambda v: ", ".join(v) if isinstance(v, list) else "")
    best["Version Check Result"] = best.apply(classify_version_check, axis=1)
    best["Resolved (from Patch Report)"] = best.apply(classify_resolution, axis=1)

    best = best.rename(columns={"Patch": "Matched Patch", "_pd": "Patch Install Date"})
    best = best.drop(columns=[c for c in best.columns if c.startswith("_")], errors="ignore")

    overview_cols = [
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
    overview_cols_present = [c for c in overview_cols if c in best.columns]
    overview = make_excel_safe(best[overview_cols_present])

    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        overview.to_excel(writer, sheet_name="Overview", index=False)
        make_excel_safe(best).to_excel(writer, sheet_name="Full Data", index=False)
        make_excel_safe(patch).to_excel(writer, sheet_name="Patch Report (Full)", index=False)

    csv_out = str(Path(out_path).with_suffix(".csv"))
    best.to_csv(csv_out, index=False)
    return total_rows, filtered_rows, csv_out


# ── Tkinter calendar popup ───────────────────────────────────────────────────

def _build_calendar_popup(parent, initial_date=None, callback=None):
    import tkinter as tk
    from tkinter import ttk

    today = date.today()
    sel = initial_date or today

    popup = tk.Toplevel(parent)
    popup.title("Select Date")
    popup.resizable(False, False)
    popup.grab_set()

    state = {"year": sel.year, "month": sel.month}

    header = ttk.Frame(popup, padding=(8, 6))
    header.pack(fill="x")

    lbl_month = ttk.Label(header, width=16, anchor="center", font=("", 10, "bold"))
    btn_prev = ttk.Button(header, text="◀", width=3)
    btn_next = ttk.Button(header, text="▶", width=3)

    btn_prev.pack(side="left")
    lbl_month.pack(side="left", expand=True)
    btn_next.pack(side="right")

    day_frame = ttk.Frame(popup, padding=(4, 0))
    day_frame.pack()
    for i, d in enumerate(["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"]):
        ttk.Label(day_frame, text=d, width=4, anchor="center", foreground="#555").grid(row=0, column=i)

    grid_frame = ttk.Frame(popup, padding=(4, 2, 4, 8))
    grid_frame.pack()
    day_btns = []
    for r in range(6):
        row_btns = []
        for c in range(7):
            b = tk.Button(
                grid_frame,
                width=3,
                relief="flat",
                font=("", 9),
                activebackground="#4a90d9",
                activeforeground="white",
            )
            b.grid(row=r, column=c, padx=1, pady=1)
            row_btns.append(b)
        day_btns.append(row_btns)

    def refresh():
        y, m = state["year"], state["month"]
        lbl_month.config(text=f"{cal_module.month_name[m]}  {y}")
        first_wd, num_days = cal_module.monthrange(y, m)

        for r in range(6):
            for c in range(7):
                day_btns[r][c].config(text="", state="disabled", bg=popup.cget("bg"))

        for day_n in range(1, num_days + 1):
            wd = (first_wd + day_n - 1) % 7
            row = (first_wd + day_n - 1) // 7
            d = date(y, m, day_n)
            is_today = (d == today)
            is_sel = (d == state.get("selected"))
            bg = "#4a90d9" if is_sel else ("#d6eaff" if is_today else popup.cget("bg"))
            fg = "white" if is_sel else "black"

            def on_click(chosen=d):
                state["selected"] = chosen
                refresh()
                if callback:
                    callback(chosen)
                popup.destroy()

            day_btns[row][wd].config(
                text=str(day_n),
                state="normal",
                bg=bg,
                fg=fg,
                command=on_click,
            )

    def prev_month():
        if state["month"] == 1:
            state["year"] -= 1
            state["month"] = 12
        else:
            state["month"] -= 1
        refresh()

    def next_month():
        if state["month"] == 12:
            state["year"] += 1
            state["month"] = 1
        else:
            state["month"] += 1
        refresh()

    btn_prev.config(command=prev_month)
    btn_next.config(command=next_month)
    state["selected"] = sel
    refresh()

    popup.update_idletasks()
    px = parent.winfo_rootx() + (parent.winfo_width() - popup.winfo_reqwidth()) // 2
    py = parent.winfo_rooty() + (parent.winfo_height() - popup.winfo_reqheight()) // 2
    popup.geometry(f"+{px}+{py}")


# ── GUI ──────────────────────────────────────────────────────────────────────

def _run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    class App:
        def __init__(self, root):
            self.root = root
            root.title("CVE Patch Matcher v4")
            root.resizable(True, True)

            self.patch_var = tk.StringVar()
            self.cve_var = tk.StringVar()
            self.out_var = tk.StringVar()
            self.date_from_var = tk.StringVar()
            self.min_score_var = tk.StringVar(value="9.0")

            frame = ttk.Frame(root, padding=16)
            frame.pack(fill="both", expand=True)
            frame.columnconfigure(1, weight=1)

            file_rows = [
                ("Patch Report (CSV / Excel)", self.patch_var, self._pick_patch, "Browse"),
                ("CVE / Detections (Excel)",   self.cve_var,   self._pick_cve,   "Browse"),
                ("Output Excel",               self.out_var,   self._pick_out,   "Save As"),
            ]
            for i, (lbl, var, cmd, btn_lbl) in enumerate(file_rows):
                ttk.Label(frame, text=lbl).grid(row=i, column=0, sticky="w", pady=5, padx=(0, 8))
                ttk.Entry(frame, textvariable=var, width=64).grid(row=i, column=1, columnspan=2, sticky="ew", padx=(0, 6))
                ttk.Button(frame, text=btn_lbl, command=cmd, width=9).grid(row=i, column=3, sticky="w")

            ttk.Separator(frame, orient="horizontal").grid(row=3, column=0, columnspan=4, sticky="ew", pady=(10, 6))

            ttk.Label(frame, text="Filters", font=("", 9, "bold")).grid(
                row=4, column=0, columnspan=4, sticky="w", pady=(0, 6)
            )

            date_row = ttk.Frame(frame)
            date_row.grid(row=5, column=0, columnspan=4, sticky="w", pady=(0, 4))

            ttk.Label(date_row, text="Last Response from").pack(side="left", padx=(0, 6))
            self._date_entry = ttk.Entry(date_row, textvariable=self.date_from_var, width=13)
            self._date_entry.pack(side="left")
            ttk.Label(date_row, text="DD/MM/YYYY", foreground="grey").pack(side="left", padx=(4, 10))
            ttk.Button(date_row, text="📅 Pick", command=self._pick_date, width=8).pack(side="left")
            ttk.Button(date_row, text="✕ Clear", command=lambda: self.date_from_var.set(""), width=7).pack(side="left", padx=(4, 0))

            score_row = ttk.Frame(frame)
            score_row.grid(row=6, column=0, columnspan=4, sticky="w", pady=(0, 6))

            ttk.Label(score_row, text="Min Vulnerability Score ≥").pack(side="left", padx=(0, 6))
            ttk.Entry(score_row, textvariable=self.min_score_var, width=8).pack(side="left")
            ttk.Label(score_row, text="default 9.0", foreground="grey").pack(side="left", padx=(8, 0))

            ttk.Separator(frame, orient="horizontal").grid(row=7, column=0, columnspan=4, sticky="ew", pady=(4, 6))

            ttk.Label(frame, text="Version checking", font=("", 9, "bold")).grid(
                row=8, column=0, columnspan=4, sticky="w", pady=(0, 4)
            )
            ttk.Label(
                frame,
                text="Fixed versions are taken from a 'Fixed Version' column in the CVE workbook if present, otherwise from built-in rules in the script.",
                foreground="grey",
                wraplength=700,
                justify="left",
            ).grid(row=9, column=0, columnspan=4, sticky="w", pady=(0, 6))

            ttk.Button(frame, text="▶  Process", command=self._run).grid(
                row=10, column=0, columnspan=4, sticky="ew", pady=(0, 6)
            )

            self.log = tk.Text(frame, height=12, wrap="word")
            self.log.grid(row=11, column=0, columnspan=4, sticky="nsew")
            frame.rowconfigure(11, weight=1)

            root.update_idletasks()
            root.minsize(700, root.winfo_reqheight())

        def _pick_patch(self):
            v = filedialog.askopenfilename(filetypes=[("CSV / Excel", "*.csv *.xlsx *.xls"), ("All files", "*.*")])
            if v:
                self.patch_var.set(v)

        def _pick_cve(self):
            v = filedialog.askopenfilename(filetypes=[("Excel", "*.xlsx *.xls"), ("All files", "*.*")])
            if v:
                self.cve_var.set(v)

        def _pick_out(self):
            v = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel Workbook", "*.xlsx")])
            if v:
                self.out_var.set(v)

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

        def _run(self):
            self.log.delete("1.0", "end")
            try:
                date_from = None
                min_score = 9.0

                raw_date = self.date_from_var.get().strip()
                if raw_date:
                    date_from = parse_input_date(raw_date)

                raw_score = self.min_score_var.get().strip()
                if raw_score:
                    try:
                        min_score = float(raw_score)
                    except ValueError:
                        raise ValueError(f"Min Score must be a number (got '{raw_score}').")

                self._log("Filters:")
                self._log(f"  Last Response from : {date_from or '—'}")
                self._log(f"  Min Score          : {min_score}")
                self._log("  KB extraction      : automatic")
                self._log("")

                self._log("Processing…")
                total, filtered, csv_out = process_files(
                    self.patch_var.get(),
                    self.cve_var.get(),
                    self.out_var.get(),
                    date_from=date_from,
                    min_score=min_score,
                )
                self._log(f"CVE rows before filter : {total}")
                self._log(f"CVE rows after  filter : {filtered}")
                self._log(f"Excel  → {self.out_var.get()}")
                self._log(f"CSV    → {csv_out}")
                self._log("Done.")
                messagebox.showinfo(
                    "Complete",
                    f"Done.\n\nRows before filter: {total}\nRows after filter: {filtered}"
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


# ── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Match Patch Report against CVE detections workbook.")
    parser.add_argument("--patch")
    parser.add_argument("--cve")
    parser.add_argument("--out")
    parser.add_argument("--date-from", help="Last Response >= date (DD/MM/YYYY)")
    parser.add_argument("--min-score", type=float, default=9.0)
    args = parser.parse_args()

    if args.patch and args.cve and args.out:
        date_from = parse_input_date(args.date_from) if args.date_from else None
        total, filtered, csv_out = process_files(
            args.patch,
            args.cve,
            args.out,
            date_from=date_from,
            min_score=args.min_score,
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