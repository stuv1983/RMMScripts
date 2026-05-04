# NVD API Key Support

This build adds optional NVD API key support to `cve_lookup.py`.

## Recommended setup

Use an environment variable so the key is not committed to GitHub:

```powershell
[Environment]::SetEnvironmentVariable("NVD_API_KEY", "YOUR_KEY_HERE", "User")
```

For the current PowerShell session only:

```powershell
$env:NVD_API_KEY = "YOUR_KEY_HERE"
```

## Optional config.json fallback

`config.json` now supports:

```json
"api": {
  "nvd_api_key": ""
}
```

Leave this blank if you use `NVD_API_KEY`.

## Confirm NVD API access

Run:

```powershell
python cve_lookup.py --test-nvd-api
```

Expected success feedback:

```text
cve_lookup: NVD API key detected from environment variable NVD_API_KEY (****ABCD)
cve_lookup: testing NVD API access with CVE-2024-21413
cve_lookup: NVD API access OK — received 1 vulnerability record(s) for CVE-2024-21413
```

If no key is configured, the tool will warn that unauthenticated NVD requests are being used.

You can test a specific CVE:

```powershell
python cve_lookup.py --test-nvd-api --test-cve CVE-2025-55315
```
