# ==========================================
# N-ABLE CVE REPORT MERGER & DASHBOARD UTILITY
# ==========================================

import pandas as pd                  
import tkinter as tk                 
from tkinter import filedialog, messagebox 
import re                            

# ==========================================
# --- HELPER FUNCTIONS ---
# ==========================================

def select_file(label_var):
    """Opens a Windows file dialog to select a CSV or Excel file."""
    file_path = filedialog.askopenfilename(
        filetypes=[("Data Files", "*.csv *.xlsx *.xls"), ("CSV Files", "*.csv"), ("Excel Files", "*.xlsx *.xls")]
    )
    if file_path:
        label_var.set(file_path)

def load_data(file_path):
    """Smartly loads data into pandas based on the file extension."""
    if file_path.lower().endswith(('.xlsx', '.xls')):
        return pd.read_excel(file_path)
    else:
        return pd.read_csv(file_path)

def normalize_device_name(name):
    """Cleans device names so the Vulnerability and Inventory reports match perfectly."""
    name = str(name).strip().upper()
    if '\\' in name:
        name = name.split('\\')[-1] 
    if '.' in name:
        name = name.split('.')[0]   
    return name

def get_base_product(prod_name):
    """Unifies fractured product names."""
    p = str(prod_name).strip()
    p = re.sub(r'\bx64\b', '', p, flags=re.IGNORECASE)
    p = re.sub(r'\bx86\b', '', p, flags=re.IGNORECASE)
    p = re.sub(r'\b32-bit\b', '', p, flags=re.IGNORECASE)
    p = re.sub(r'\b64-bit\b', '', p, flags=re.IGNORECASE)
    p = re.sub(r'\s+v?\d+(\.\d+)*\s*$', '', p)
    return p.strip()

def clean_sheet_name(name, used_names):
    """Sanitizes sheet names to prevent Excel from crashing."""
    if pd.isna(name) or str(name).strip() == "":
        name = "Unknown Product"
        
    invalid_chars = r'[\[\]\:\*\?\/\\\'\000]'
    clean_name = re.sub(invalid_chars, '', str(name)).strip()
    clean_name = clean_name[:31].strip() 
    
    if not clean_name:  
        clean_name = "Unknown Product"
        
    final_name = clean_name
    counter = 1
    while final_name.lower() in [n.lower() for n in used_names]:
        suffix = f"_{counter}"
        final_name = clean_name[:31 - len(suffix)] + suffix
        counter += 1
        
    used_names.add(final_name)
    return final_name

def extract_nvd_link(row):
    """Scans the vulnerability name for a valid CVE ID and builds an NVD hyperlink."""
    for col in ['CVE', 'CVE ID', 'Vulnerability Name', 'Name']:
        if col in row.index and pd.notna(row[col]):
            match = re.search(r'(CVE-\d{4}-\d+)', str(row[col]), re.IGNORECASE)
            if match:
                cve_id = match.group(1).upper()
                return f'=HYPERLINK("https://nvd.nist.gov/vuln/detail/{cve_id}", "View")'
    return ""

def make_cve_org_link(val):
    """Wraps the original Vulnerability Name text in a cve.org hyperlink."""
    val_str = str(val)
    if pd.isna(val) or val_str.strip() == "" or val_str.lower() == 'nan':
        return val
    
    match = re.search(r'(CVE-\d{4}-\d+)', val_str, re.IGNORECASE)
    if match:
        cve_id = match.group(1).upper()
        # Escape quotes for Excel formulas and truncate to prevent crashing on massive strings
        display_text = val_str.replace('"', '""')
        if len(display_text) > 250:
            display_text = display_text[:247] + "..."
        return f'=HYPERLINK("https://www.cve.org/CVERecord?id={cve_id}", "{display_text}")'
    return val

def determine_device_type(os_string):
    """Tags the device as a Server or Workstation."""
    val = str(os_string).lower()
    if val == 'nan' or val == 'unknown':
        return 'Unknown'
    if 'server' in val:
        return 'Server'
    return 'Workstation'

def parse_last_response(val):
    """
    Parses N-able's various time strings into actual dates for mathematical sorting.
    Missing devices get year 1900 so they sink to the bottom.
    """
    val = str(val).strip()
    epoch = pd.to_datetime('1900-01-01') 
    
    if val in ["Not Found in RMM", "N/A", ""]:
        return epoch
    
    try:
        return pd.to_datetime(val)
    except:
        pass
    
    if val.startswith("overdue_"):
        try:
            clean_val = val.replace("overdue_", "").split(" -")[0]
            return pd.to_datetime(clean_val)
        except:
            pass
            
    if "days" in val or "hrs" in val:
        try:
            days = 0
            match = re.search(r'(\d+)\s*days', val)
            if match:
                days = int(match.group(1))
            return pd.Timestamp.now() - pd.Timedelta(days=days)
        except:
            pass
            
    return epoch

def get_col_letter(col_idx):
    """Converts 0-indexed column number to an Excel letter (e.g. 0 -> A)."""
    letter = ''
    col_idx += 1
    while col_idx > 0:
        col_idx, remainder = divmod(col_idx - 1, 26)
        letter = chr(65 + remainder) + letter
    return letter

def toggle_rmm_state():
    if skip_rmm_var.get():
        rmm_entry.config(state=tk.DISABLED)
        rmm_button.config(state=tk.DISABLED)
    else:
        rmm_entry.config(state=tk.NORMAL)
        rmm_button.config(state=tk.NORMAL)

# ==========================================
# --- MAIN PROCESSING FUNCTION ---
# ==========================================

def process_reports():
    vuln_path = vuln_var.get()
    rmm_path = rmm_var.get()
    skip_rmm = skip_rmm_var.get()
    
    if not vuln_path:
        messagebox.showerror("Error", "Please select the Vulnerability Report.")
        return
    if not skip_rmm and not rmm_path:
        messagebox.showerror("Error", "Please select the Device Inventory / RMM Report.")
        return

    try:
        threshold = float(score_var.get())
        
        # --- 1. LOAD & CLEAN VULN DATA ---
        try:
            df_vuln = load_data(vuln_path)
        except Exception as e:
            messagebox.showerror("File Error", f"Could not read Vulnerability Report:\n{e}")
            return
        
        df_vuln['Name_Join'] = df_vuln['Name'].apply(normalize_device_name)
        df_vuln['Affected Products'] = df_vuln['Affected Products'].fillna('Unknown Product')
        df_vuln['Base Product'] = df_vuln['Affected Products'].apply(get_base_product)

        # --- 2. LOAD & CLEAN DEVICE INVENTORY / RMM DATA ---
        if not skip_rmm:
            try:
                df_rmm = load_data(rmm_path)
            except Exception as e:
                messagebox.showerror("File Error", f"Could not read Device Inventory Report:\n{e}")
                return
            
            col_lower = {c.lower(): c for c in df_rmm.columns}
            
            dev_col, resp_col, os_col = None, None, None
            
            if 'device name' in col_lower: dev_col = col_lower['device name']
            elif 'device' in col_lower: dev_col = col_lower['device']
            elif 'name' in col_lower: dev_col = col_lower['name']
                
            if 'last response (local time)' in col_lower: resp_col = col_lower['last response (local time)']
            elif 'last response (utc)' in col_lower: resp_col = col_lower['last response (utc)']
            elif 'last response' in col_lower: resp_col = col_lower['last response']
            elif 'last check-in' in col_lower: resp_col = col_lower['last check-in']
            
            if 'os version' in col_lower: os_col = col_lower['os version']
            elif 'os' in col_lower: os_col = col_lower['os']
                
            if not dev_col or not resp_col:
                if len(df_rmm.columns) == 9:
                    df_rmm.columns = ['Type', 'Client', 'Site', 'Device', 'Description', 'OS', 'Username', 'Last Response', 'Last Boot']
                    dev_col = 'Device'
                    resp_col = 'Last Response'
                    os_col = 'OS'
                else:
                    messagebox.showerror("Format Error", "Could not identify 'Device name' and 'Last response' columns.")
                    return
            
            df_rmm.rename(columns={dev_col: 'Device', resp_col: 'Last Response'}, inplace=True)
            df_rmm['Device_Join'] = df_rmm['Device'].apply(normalize_device_name)
            df_rmm['Device Type'] = df_rmm[os_col].apply(determine_device_type) if os_col else 'Unknown'
            
            df_rmm_unique = df_rmm.drop_duplicates(subset=['Device_Join'], keep='first')
            
            merged_df = pd.merge(df_vuln, df_rmm_unique[['Device_Join', 'Last Response', 'Device Type']], left_on='Name_Join', right_on='Device_Join', how='left')
            merged_df['Last Response'] = merged_df['Last Response'].fillna("Not Found in RMM")
            merged_df['Device Type'] = merged_df['Device Type'].fillna("Unknown")
            
        else:
            merged_df = df_vuln.copy()
            merged_df['Last Response'] = "N/A"
            merged_df['Device Type'] = merged_df['Operating System Role'].str.title() if 'Operating System Role' in merged_df.columns else "Unknown"

        merged_df['Vulnerability Score'] = pd.to_numeric(merged_df['Vulnerability Score'], errors='coerce')
        merged_df['_Sort_Time'] = merged_df['Last Response'].apply(parse_last_response)

        # --- 3. EXPORT TO EXCEL ---
        output_file = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")])
        if not output_file: return 

        with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
            workbook = writer.book
            
            link_format = workbook.add_format({'font_color': 'blue', 'underline': True})
            header_format = workbook.add_format({'bold': True, 'font_size': 12, 'bg_color': '#D9D9D9', 'border': 1})
            missing_row_format = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})

            filtered_for_sheets_df = merged_df[merged_df['Vulnerability Score'] >= threshold].copy()
            used_sheet_names = set(['overview', 'all detections'])
            product_to_sheet = {}
            
            for product, _ in filtered_for_sheets_df.groupby('Base Product'):
                product_to_sheet[product] = clean_sheet_name(product, used_sheet_names)

            # ==========================================
            # SHEET 1: OVERVIEW DASHBOARD
            # ==========================================
            overview_sheet = workbook.add_worksheet('Overview')
            
            overview_sheet.write('A1', 'Unique CVEs by Severity', header_format)
            unique_cves_df = merged_df.drop_duplicates(subset=['Vulnerability Name']).copy()
            sev_counts = unique_cves_df['Vulnerability Severity'].value_counts()
            
            row = 1
            for sev, count in sev_counts.items():
                overview_sheet.write(row, 0, str(sev))
                overview_sheet.write(row, 1, count)
                row += 1
            
            chart_sev = workbook.add_chart({'type': 'pie'})
            chart_sev.add_series({
                'name': 'Severity Breakdown',
                'categories': ['Overview', 1, 0, row - 1, 0],
                'values':     ['Overview', 1, 1, row - 1, 1],
            })
            chart_sev.set_title({'name': 'Unique CVEs by Severity'})
            overview_sheet.insert_chart('D1', chart_sev)

            dt_row = max(8, row + 2)
            overview_sheet.write(dt_row, 0, f'Unique Devices by Type (Score {threshold}+)', header_format)
            dt_counts = filtered_for_sheets_df.groupby('Device Type')['Name'].nunique()
            
            r = dt_row + 1
            for dt, count in dt_counts.items():
                overview_sheet.write(r, 0, str(dt))
                overview_sheet.write(r, 1, count)
                r += 1

            chart_dt = workbook.add_chart({'type': 'pie'})
            chart_dt.add_series({
                'name': 'Device Type',
                'categories': ['Overview', dt_row + 1, 0, r - 1, 0],
                'values':     ['Overview', dt_row + 1, 1, r - 1, 1],
            })
            chart_dt.set_title({'name': 'Servers vs Workstations'})
            overview_sheet.insert_chart('K1', chart_dt)

            start_p_row = max(18, r + 2)
            overview_sheet.write(start_p_row, 0, f'Top 10 Products (Score {threshold}+)', header_format)
            prod_counts = filtered_for_sheets_df.groupby('Base Product')['Name'].nunique().sort_values(ascending=False).head(10)
            
            p_idx = start_p_row + 1
            for prod, count in prod_counts.items():
                if prod in product_to_sheet:
                    target = product_to_sheet[prod]
                    overview_sheet.write_url(p_idx, 0, f"internal:'{target}'!A1", string=str(prod), cell_format=link_format)
                else:
                    overview_sheet.write(p_idx, 0, str(prod))
                overview_sheet.write(p_idx, 1, count)
                p_idx += 1

            chart_prod = workbook.add_chart({'type': 'bar'})
            chart_prod.add_series({
                'name': 'Unique Devices',
                'categories': ['Overview', start_p_row + 1, 0, p_idx - 1, 0],
                'values':     ['Overview', start_p_row + 1, 1, p_idx - 1, 1],
            })
            chart_prod.set_title({'name': 'Top 10 Affected Products'})
            overview_sheet.insert_chart('D16', chart_prod)
            
            overview_sheet.set_column('A:A', 40)
            overview_sheet.autofilter(start_p_row, 0, p_idx - 1, 1)

            missing_row = p_idx + 2
            overview_sheet.write(missing_row, 0, f"Devices Not Found in RMM (Score {threshold}+)", header_format)
            missing_devices = filtered_for_sheets_df[filtered_for_sheets_df['Last Response'] == "Not Found in RMM"]['Name'].unique()
            
            m_idx = missing_row + 1
            if len(missing_devices) == 0:
                overview_sheet.write(m_idx, 0, "All devices synced")
            else:
                for dev in sorted(missing_devices):
                    overview_sheet.write(m_idx, 0, str(dev))
                    m_idx += 1

            # ==========================================
            # SHEET 2: ALL DETECTIONS (Raw Data)
            # ==========================================
            merged_df_export = merged_df.copy()
            
            for col in ['Name_Join', 'Device_Join', 'Base Product']:
                if col in merged_df_export.columns: merged_df_export.drop(columns=[col], inplace=True)
            
            # Generate the dual links (NVD in its column, cve.org in Vulnerability Name)
            merged_df_export['NVD'] = merged_df_export.apply(extract_nvd_link, axis=1)
            merged_df_export['Vulnerability Name'] = merged_df_export['Vulnerability Name'].apply(make_cve_org_link)
            
            cols = merged_df_export.columns.tolist()
            if 'Device Type' in cols and 'Name' in cols:
                cols.insert(cols.index('Name') + 1, cols.pop(cols.index('Device Type')))
                merged_df_export = merged_df_export[cols]

            merged_df_export = merged_df_export.sort_values(by=['Vulnerability Score', '_Sort_Time', 'Name'], ascending=[False, False, True])
            if '_Sort_Time' in merged_df_export.columns: merged_df_export.drop(columns=['_Sort_Time'], inplace=True)

            merged_df_export.to_excel(writer, sheet_name='All Detections', index=False)
            ws_all = writer.sheets['All Detections']
            
            ws_all.autofilter(0, 0, len(merged_df_export), len(merged_df_export.columns) - 1)
            
            # Explicitly format the link and width columns
            cols_export_list = merged_df_export.columns.tolist()
            if 'Vulnerability Name' in cols_export_list:
                vn_idx = cols_export_list.index('Vulnerability Name')
                ws_all.set_column(vn_idx, vn_idx, 25, link_format)
            if 'NVD' in cols_export_list:
                nvd_idx = cols_export_list.index('NVD')
                ws_all.set_column(nvd_idx, nvd_idx, 10, link_format)
            if 'Name' in cols_export_list:
                ws_all.set_column(cols_export_list.index('Name'), cols_export_list.index('Name'), 25)
            
            if 'Last Response' in cols_export_list:
                lr_idx = cols_export_list.index('Last Response')
                lr_col_letter = get_col_letter(lr_idx)
                ws_all.conditional_format(1, 0, len(merged_df_export), len(cols_export_list) - 1, {
                    'type': 'formula',
                    'criteria': f'=${lr_col_letter}2="Not Found in RMM"',
                    'format': missing_row_format
                })

            # ==========================================
            # SHEETS 3+: PRODUCT TABS (Triage View)
            # ==========================================
            cols_order = ['Vulnerability Name', 'Name', 'Device Type', 'Vulnerability Severity', 'Vulnerability Score', 'Risk Severity Index', 'Has Known Exploit', 'CISA KEV', 'Last Response', 'Affected Products', 'NVD']

            for product, group in filtered_for_sheets_df.groupby('Base Product'):
                sheet_name = product_to_sheet[product]
                
                group = group.drop_duplicates(subset=['Name', 'Vulnerability Name']).copy()
                group = group.sort_values(by=['Vulnerability Score', '_Sort_Time', 'Name'], ascending=[False, False, True])
                
                # Apply dual linking
                group['NVD'] = group.apply(extract_nvd_link, axis=1)
                group['Vulnerability Name'] = group['Vulnerability Name'].apply(make_cve_org_link)
                
                final_cols = [c for c in cols_order if c in group.columns]
                group[final_cols].to_excel(writer, sheet_name=sheet_name, index=False)
                
                ws_p = writer.sheets[sheet_name]
                ws_p.autofilter(0, 0, len(group), len(final_cols) - 1)
                
                # Explicit column sizing and blue text application
                if 'Vulnerability Name' in final_cols:
                    vn_idx = final_cols.index('Vulnerability Name')
                    ws_p.set_column(vn_idx, vn_idx, 25, link_format)
                if 'NVD' in final_cols:
                    n_idx = final_cols.index('NVD')
                    ws_p.set_column(n_idx, n_idx, 10, link_format)
                if 'Name' in final_cols:
                    ws_p.set_column(final_cols.index('Name'), final_cols.index('Name'), 25)
                if 'Device Type' in final_cols:
                    ws_p.set_column(final_cols.index('Device Type'), final_cols.index('Device Type'), 15)
                
                if 'Last Response' in final_cols:
                    lr_idx = final_cols.index('Last Response')
                    lr_col_letter = get_col_letter(lr_idx)
                    ws_p.conditional_format(1, 0, len(group), len(final_cols) - 1, {
                        'type': 'formula',
                        'criteria': f'=${lr_col_letter}2="Not Found in RMM"',
                        'format': missing_row_format
                    })

        messagebox.showinfo("Success", f"Full Dashboard saved to:\n{output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Processing failed: {e}")

# ==========================================
# GUI SETUP
# ==========================================
root = tk.Tk()
root.title("N-able CVE Dashboard & Triage Tool")
root.geometry("540x420")
vuln_var, rmm_var, score_var, skip_rmm_var = tk.StringVar(), tk.StringVar(), tk.StringVar(value="9.0"), tk.BooleanVar(value=False)

tk.Label(root, text="1. Vulnerability Report (CSV or XLSX)", font=('Arial', 10, 'bold')).pack(pady=5)
tk.Entry(root, textvariable=vuln_var, width=65).pack()
tk.Button(root, text="Browse", command=lambda: select_file(vuln_var)).pack()

tk.Label(root, text="2. Device Inventory / RMM Report (CSV or XLSX)", font=('Arial', 10, 'bold')).pack(pady=5)
rmm_entry = tk.Entry(root, textvariable=rmm_var, width=65)
rmm_entry.pack()
rmm_button = tk.Button(root, text="Browse", command=lambda: select_file(rmm_var))
rmm_button.pack()
tk.Checkbutton(root, text="Skip Device Report (Disables 'Last Response')", variable=skip_rmm_var, command=toggle_rmm_state).pack()

tk.Label(root, text="3. Score Threshold (Show in Tabs)", font=('Arial', 10, 'bold')).pack(pady=5)
tk.Entry(root, textvariable=score_var, width=10).pack()

tk.Button(root, text="GENERATE COMPLETE DASHBOARD", command=process_reports, bg="#0078D7", fg="white", font=('Arial', 10, 'bold'), height=2).pack(pady=20)
root.mainloop()