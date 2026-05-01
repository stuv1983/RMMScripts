"""
cve_lookup.py — fetch fixed version data from public CVE APIs and
                automatically populate config.json fixed_version_rules.

Sources (tried in order, first success wins):
    1. CVE.org JSON API   — cveawg.mitre.org/api/cve/{id}
                            Uses CVE JSON 5.0 schema — most authoritative source
    2. NVD API 2.0        — services.nvd.nist.gov/rest/json/cves/2.0
                            Returns CPE match criteria with version ranges
    3. OSV.dev API        — api.osv.dev/v1/vulns/{id}
                            Best for open-source packages (Chrome, Firefox etc.)

Run manually:
    python cve_lookup.py CVE-2026-5288 CVE-2026-5289
    python cve_lookup.py --auto           # fetch all CVEs in config.json rules
    python cve_lookup.py --dry-run CVE-2026-5288

Or from code:
    from cve_lookup import lookup_fixed_version, enrich_config

What it does
------------
For each CVE it finds the minimum fixed version (the first version that
contains the fix) and writes it into config.json fixed_version_rules under
the matching canonical product key.

The product key is determined by matching the CVE's vendor/product string
against config.json product_map — the same matching logic used by the pipeline.

Example config.json update:
    "chrome": {
        "CVE-2026-5288": "136.0.7103.116",   ← added automatically
        "_baseline": "148.0.7778.97"
    }
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_UA      = 'Mozilla/5.0 N-able-CVE-Dashboard/1.0 (automated; contact your-email@example.com)'
_TIMEOUT = 12
_RETRY   = 2
_DELAY   = 0.5   # seconds between API calls — be a polite client


# ==============================================================================
# API FETCHERS
# ==============================================================================

def _get(url: str) -> Optional[dict]:
    """HTTP GET with retries. Returns parsed JSON or None on failure."""
    for attempt in range(_RETRY):
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': _UA, 'Accept': 'application/json'},
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None          # CVE not found — not a retry candidate
            if e.code == 429:
                log.warning("Rate limited by %s — waiting 5s", url[:60])
                time.sleep(5)
            else:
                log.debug("HTTP %d from %s (attempt %d)", e.code, url[:60], attempt + 1)
        except Exception as e:
            log.debug("Fetch failed %s: %s (attempt %d)", url[:60], e, attempt + 1)
        time.sleep(_DELAY)
    return None


def _parse_cve_org(data: dict) -> list[dict]:
    """
    Extract affected version ranges from CVE.org JSON 5.0 schema.

    Returns list of:
        { vendor, product, fixed_version }
    """
    results = []
    try:
        cna = data.get('containers', {}).get('cna', {})
        for affected in cna.get('affected', []):
            vendor  = str(affected.get('vendor', '')).strip()
            product = str(affected.get('product', '')).strip()
            for v in affected.get('versions', []):
                if v.get('status') != 'affected':
                    continue
                # lessThan = first version that is NOT affected (the fix)
                fixed = v.get('lessThan') or v.get('lessThanOrEqual')
                if fixed:
                    results.append({
                        'vendor':        vendor,
                        'product':       product,
                        'fixed_version': str(fixed).strip(),
                    })
    except Exception as e:
        log.debug("CVE.org parse error: %s", e)
    return results


def _parse_nvd(data: dict) -> list[dict]:
    """
    Extract version ranges from NVD API 2.0 CPE match criteria.

    Returns list of:
        { vendor, product, fixed_version }
    """
    results = []
    try:
        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return results
        cve_data = vulns[0].get('cve', {})
        for config in cve_data.get('configurations', []):
            for node in config.get('nodes', []):
                for cpe in node.get('cpeMatch', []):
                    if not cpe.get('vulnerable'):
                        continue
                    fixed = (cpe.get('versionEndExcluding')
                             or cpe.get('versionEndIncluding'))
                    if not fixed:
                        continue
                    # CPE URI: cpe:2.3:a:vendor:product:...
                    cpe_uri = cpe.get('criteria', '')
                    parts   = cpe_uri.split(':')
                    vendor  = parts[3] if len(parts) > 3 else ''
                    product = parts[4] if len(parts) > 4 else ''
                    results.append({
                        'vendor':        vendor,
                        'product':       product,
                        'fixed_version': str(fixed).strip(),
                    })
    except Exception as e:
        log.debug("NVD parse error: %s", e)
    return results


def _parse_osv(data: dict) -> list[dict]:
    """
    Extract fixed versions from OSV.dev API response.
    OSV uses explicit 'fixed' events in version ranges.
    """
    results = []
    try:
        for affected in data.get('affected', []):
            pkg     = affected.get('package', {})
            product = pkg.get('name', '')
            vendor  = pkg.get('ecosystem', '')
            for rng in affected.get('ranges', []):
                for event in rng.get('events', []):
                    fixed = event.get('fixed')
                    if fixed:
                        results.append({
                            'vendor':        vendor,
                            'product':       product,
                            'fixed_version': str(fixed).strip(),
                        })
    except Exception as e:
        log.debug("OSV parse error: %s", e)
    return results


# ==============================================================================
# PRODUCT MATCHING
# ==============================================================================

_VERSION_ONLY = re.compile(r'^\d+(?:\.\d+){1,5}$')

def _match_product(vendor: str, product: str,
                   product_map: list[tuple[str, str]]) -> Optional[str]:
    """
    Try to match a vendor+product string against config.json product_map.
    Returns the canonical product key or None.
    """
    combined = f'{vendor} {product}'.lower().strip()
    for key, canonical in product_map:
        if key in combined:
            return canonical
    return None


def _is_valid_version(v: str) -> bool:
    """Basic sanity check — reject garbage strings."""
    return bool(v) and bool(_VERSION_ONLY.match(v.strip()))


# ==============================================================================
# MAIN LOOKUP
# ==============================================================================

def lookup_fixed_version(cve_id: str,
                         product_map: list[tuple[str, str]]) -> dict[str, str]:
    """
    Fetch the fixed version(s) for a CVE from public APIs.

    Returns dict of { canonical_product_key: fixed_version_string }
    e.g. { 'chrome': '136.0.7103.116', 'edge': '136.0.3240.64' }

    Returns empty dict if CVE not found or no version data available.
    """
    cve_id = cve_id.strip().upper()
    log.info("cve_lookup: fetching %s", cve_id)

    results: list[dict] = []

    # Source 1: CVE.org
    data = _get(f'https://cveawg.mitre.org/api/cve/{cve_id}')
    if data:
        results = _parse_cve_org(data)
        if results:
            log.debug("cve_lookup: %s → CVE.org returned %d affected entries", cve_id, len(results))

    # Source 2: NVD (fallback)
    if not results:
        time.sleep(_DELAY)
        data = _get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}')
        if data:
            results = _parse_nvd(data)
            if results:
                log.debug("cve_lookup: %s → NVD returned %d CPE entries", cve_id, len(results))

    # Source 3: OSV.dev (fallback)
    if not results:
        time.sleep(_DELAY)
        data = _get(f'https://api.osv.dev/v1/vulns/{cve_id}')
        if data:
            results = _parse_osv(data)
            if results:
                log.debug("cve_lookup: %s → OSV returned %d affected entries", cve_id, len(results))

    if not results:
        log.warning("cve_lookup: no version data found for %s", cve_id)
        return {}

    # Match each result against product_map
    matched: dict[str, str] = {}
    for r in results:
        fv = r.get('fixed_version', '').strip()
        if not _is_valid_version(fv):
            continue
        pk = _match_product(r.get('vendor', ''), r.get('product', ''), product_map)
        if not pk:
            log.debug("cve_lookup: no product_map match for %s %s",
                      r.get('vendor'), r.get('product'))
            continue
        # If we get multiple results for the same product, keep the lowest fixed version
        # (most conservative — ensures devices are on at least the minimum safe release)
        if pk not in matched or _version_lt(fv, matched[pk]):
            matched[pk] = fv

    if matched:
        log.info("cve_lookup: %s → %s",
                 cve_id, ', '.join(f'{k}={v}' for k, v in matched.items()))
    else:
        log.warning("cve_lookup: %s — data found but no product_map matches", cve_id)

    return matched


def _version_lt(a: str, b: str) -> bool:
    """Return True if version a < version b."""
    def _t(v):
        try:
            return tuple(int(x) for x in v.split('.'))
        except ValueError:
            return (0,)
    return _t(a) < _t(b)


# ==============================================================================
# CONFIG ENRICHMENT
# ==============================================================================

def enrich_config(cve_ids: Optional[list[str]] = None,
                  config_path: Optional[str] = None,
                  dry_run: bool = False,
                  overwrite: bool = False) -> dict[str, dict[str, str]]:
    """
    Look up fixed versions for a list of CVEs and write them into config.json.

    cve_ids:     list of CVE IDs to look up. If None, reads all CVE IDs already
                 present in config.json fixed_version_rules (auto mode).
    config_path: path to config.json. Defaults to same directory as this file.
    dry_run:     if True, print what would be written without modifying config.
    overwrite:   if True, replace existing entries. Default: skip if already set.

    Returns dict of { cve_id: { product: fixed_version } } for all found results.
    """
    if config_path is None:
        config_path = Path(__file__).parent / 'config.json'
    config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"config.json not found at {config_path}")

    with open(config_path, 'r', encoding='utf-8') as fh:
        cfg = json.load(fh)

    product_map  = [(str(k).lower(), str(v).lower()) for k, v in cfg.get('product_map', [])]
    fvr: dict    = cfg.get('fixed_version_rules', {})

    # Auto mode: collect all CVE IDs already in the rules (these need version data)
    if cve_ids is None:
        cve_ids = []
        for pk_rules in fvr.values():
            if isinstance(pk_rules, dict):
                for k in pk_rules:
                    if k.upper().startswith('CVE-') and k not in cve_ids:
                        cve_ids.append(k.upper())

    results: dict[str, dict[str, str]] = {}

    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        matched = lookup_fixed_version(cve_id, product_map)
        if not matched:
            continue

        results[cve_id] = matched

        for pk, fv in matched.items():
            if pk not in fvr:
                fvr[pk] = {}
            if not isinstance(fvr[pk], dict):
                fvr[pk] = {}

            if cve_id in fvr[pk] and not overwrite:
                log.info("cve_lookup: %s/%s already has value %s — skipping (use --overwrite to replace)",
                         pk, cve_id, fvr[pk][cve_id])
                continue

            old = fvr[pk].get(cve_id, '(not set)')
            fvr[pk][cve_id] = fv
            log.info("cve_lookup: config.json %s/%s: %s → %s", pk, cve_id, old, fv)

        time.sleep(_DELAY)   # be polite between CVE lookups

    if results and not dry_run:
        cfg['fixed_version_rules'] = fvr
        with open(config_path, 'w', encoding='utf-8') as fh:
            json.dump(cfg, fh, indent=2)
        log.info("cve_lookup: config.json updated with %d CVE(s)", len(results))
    elif dry_run:
        log.info("cve_lookup: dry run — no changes written")

    return results


# ==============================================================================
# INTEGRATION WITH ORCHESTRATOR
# ==============================================================================

def enrich_from_detections(cve_df: 'pd.DataFrame',
                            config_path: Optional[str] = None) -> int:
    """
    Called by the orchestrator with the loaded CVE DataFrame.
    Finds all CVE IDs in the data that don't have a fixed_version_rules entry
    and looks them up automatically.

    config.json is the persistent cache — each CVE is only looked up once per
    product. Once written, subsequent runs read from config.json and skip the API.

    Returns the number of CVEs enriched.
    """
    try:
        from data_pipeline import extract_cve_id

        if config_path is None:
            config_path = Path(__file__).parent / 'config.json'

        with open(config_path, 'r', encoding='utf-8') as fh:
            cfg = json.load(fh)
        fvr          = cfg.get('fixed_version_rules', {})
        product_map  = [(str(k).lower(), str(v).lower())
                        for k, v in cfg.get('product_map', [])]

        # Build set of CVE IDs already fully covered in config.json
        # A CVE is "known" if it appears in at least one product's rules
        # (the API returns all affected products in one call)
        known: set[str] = set()
        for pk_rules in fvr.values():
            if isinstance(pk_rules, dict):
                known.update(k.upper() for k in pk_rules
                             if k.upper().startswith('CVE-'))

        all_cves = cve_df['Vulnerability Name'].apply(extract_cve_id).unique()
        missing  = [c for c in all_cves
                    if c.upper() not in known and c.upper().startswith('CVE-')]

        if not missing:
            log.debug("cve_lookup: all %d CVEs already have version data", len(all_cves))
            return 0

        log.info("cve_lookup: %d of %d CVE(s) without version data — looking up",
                 len(missing), len(all_cves))
        results = enrich_config(cve_ids=missing, config_path=config_path)
        return len(results)

    except Exception as e:
        log.warning("cve_lookup: auto-enrich failed: %s", e)
        return 0


# ==============================================================================
# CLI
# ==============================================================================

if __name__ == '__main__':
    import sys
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s  %(levelname)-8s  %(message)s',
        datefmt='%H:%M:%S',
    )

    p = argparse.ArgumentParser(
        description='Fetch CVE fixed versions from CVE.org/NVD and update config.json.'
    )
    p.add_argument('cves', nargs='*', metavar='CVE-ID',
                   help='CVE IDs to look up (e.g. CVE-2026-5288 CVE-2026-5289)')
    p.add_argument('--auto',      action='store_true',
                   help='Auto mode: look up all CVEs already in config.json rules')
    p.add_argument('--dry-run',   action='store_true',
                   help='Show what would be written without modifying config.json')
    p.add_argument('--overwrite', action='store_true',
                   help='Replace existing fixed_version_rules entries')
    p.add_argument('--config',    default=None, metavar='PATH',
                   help='Path to config.json')
    args = p.parse_args()

    cve_ids = None if args.auto else (args.cves or None)

    if cve_ids is None and not args.auto:
        p.print_help()
        sys.exit(1)

    results = enrich_config(
        cve_ids     = cve_ids,
        config_path = args.config,
        dry_run     = args.dry_run,
        overwrite   = args.overwrite,
    )

    if results:
        print(f"\nEnriched {len(results)} CVE(s):")
        for cve_id, matched in results.items():
            for pk, fv in matched.items():
                print(f"  {cve_id}  →  {pk}: {fv}")
    else:
        print("No new version data found.")
