#!/usr/bin/env python3
"""
antibot_check.py — CloudGuard WAF Anti-Bot HAR checker

A self-contained, dependency-free tool that:
  1. SANITIZES a browser HAR capture (removes cookies, auth headers, tokens,
     credentials and binary bodies) so it is safe to share with your
     security team.
  2. ANALYZES the sanitized capture to check the Anti-Bot configuration:
       - Which HTML pages should have the JS sensor injected ("Injected URIs")
       - Which endpoints should be validated ("Validated URIs")
       - Whether an anti-bot sensor is ALREADY present in the pages

Requirements: Python 3.8+ (standard library only — no pip install needed).
Works on Windows, macOS and Linux.

Usage:
    python antibot_check.py capture.har
    python antibot_check.py capture.har --host portal.example.com

Output (created next to the input file):
    capture.SANITIZED.har   -> safe-to-share copy (send THIS one, never the original)
    capture.REPORT.txt      -> human-readable analysis report
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Sanitization settings
# --------------------------------------------------------------------------

# Headers whose values are always redacted (request and response)
SENSITIVE_HEADERS = {
    'cookie', 'set-cookie', 'authorization', 'proxy-authorization',
    'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token',
    'x-amz-security-token', 'x-goog-authuser',
}

# Field/parameter names that indicate sensitive values (values are redacted,
# names are kept — they are needed to identify login forms)
SENSITIVE_PARAMS = re.compile(
    r'(pass|pwd|senha|token|session|sess|auth|secret|key|user|login|email|'
    r'mail|nif|dni|nie|cc|iban|card|phone|tel|otp|pin|code)', re.I)

# Response bodies to KEEP (needed to detect the injected sensor);
# everything else (images, fonts, downloads...) is stripped
KEEP_MIMES = ('html', 'javascript', 'json', 'xml', 'css')

REDACTED = '[REDACTED]'

# Signatures of known anti-bot / bot-management sensors
KNOWN_SENSORS = re.compile(
    r'(cloudguard|checkpoint|/cp-|appsec|perimeterx|px-cdn|datadome|'
    r'imperva|incapsula|akamai.*bmp|_bm/|kasada|shape|f5.*bot|recaptcha|'
    r'hcaptcha|turnstile)', re.I)


# --------------------------------------------------------------------------
# Step 1 — Sanitize
# --------------------------------------------------------------------------

def sanitize(har: dict) -> dict:
    """Redact sensitive data in-place. Returns redaction statistics."""
    stats = {'headers': 0, 'cookies': 0, 'query_params': 0,
             'post_fields': 0, 'response_bodies_removed': 0}

    for entry in har['log']['entries']:
        req, resp = entry['request'], entry['response']

        # Sensitive headers and all cookie values, on both sides
        for side in (req, resp):
            for h in side.get('headers', []):
                if h['name'].lower() in SENSITIVE_HEADERS:
                    h['value'] = REDACTED
                    stats['headers'] += 1
            for c in side.get('cookies', []):
                c['value'] = REDACTED
                stats['cookies'] += 1

        # Sensitive query string parameters
        for p in req.get('queryString', []):
            if SENSITIVE_PARAMS.search(p['name']):
                p['value'] = REDACTED
                stats['query_params'] += 1

        # POST bodies: redact values, keep field names
        pd = req.get('postData')
        if pd:
            for p in pd.get('params', []):
                if SENSITIVE_PARAMS.search(p.get('name', '')):
                    p['value'] = REDACTED
                    stats['post_fields'] += 1
            text = pd.get('text', '')
            if text and SENSITIVE_PARAMS.search(text):
                if text.lstrip().startswith(('{', '[')):
                    # JSON body: redact every string value
                    pd['text'] = re.sub(r':\s*"[^"]*"', f': "{REDACTED}"', text)
                else:
                    # form-urlencoded: redact values, keep names
                    pd['text'] = re.sub(r'=([^&\s]+)', '=' + REDACTED, text)
                stats['post_fields'] += 1

        # Strip response bodies we don't need for the analysis
        content = resp.get('content', {})
        mime = content.get('mimeType', '')
        if 'text' in content and not any(t in mime for t in KEEP_MIMES):
            size = content.get('size', 0)
            content['text'] = f'[BODY REMOVED - {mime} - {size} bytes]'
            stats['response_bodies_removed'] += 1

    # Marker so downstream tooling can verify the file was sanitized
    har['log']['_sanitized'] = True
    return stats


# --------------------------------------------------------------------------
# Step 2 — Analyze
# --------------------------------------------------------------------------

def _header(req_or_resp, name):
    for h in req_or_resp.get('headers', []):
        if h['name'].lower() == name:
            return h['value']
    return ''


def _dedup(seq, key=lambda x: x[0]):
    seen, out = set(), []
    for item in seq:
        if key(item) not in seen:
            seen.add(key(item))
            out.append(item)
    return out


def analyze(har: dict, host: str | None, out) -> None:
    """Write the analysis report for one host to the `out` stream."""
    entries = har['log']['entries']

    hosts = Counter(urlparse(e['request']['url']).netloc for e in entries)
    print('Hosts found in the capture:', file=out)
    for h, c in hosts.most_common():
        print(f'  {c:4d}  {h}', file=out)
    target = host or hosts.most_common(1)[0][0]
    print(f'\nAnalyzed host: {target}\n', file=out)

    html_docs, fragments, posts, xhr_get = [], [], [], []
    scripts, form_actions, redirects = [], set(), []

    for e in entries:
        req, resp = e['request'], e['response']
        u = urlparse(req['url'])
        if u.netloc != target:
            continue
        method = req['method']
        status = resp['status']
        mime = resp.get('content', {}).get('mimeType', '')
        body = resp.get('content', {}).get('text', '') or ''
        dest = _header(req, 'sec-fetch-dest')
        xrw = _header(req, 'x-requested-with')
        loc = _header(resp, 'location')

        if loc:
            redirects.append((status, u.path, loc))

        if 'html' in mime and method == 'GET':
            # Full document navigation vs. HTML fragment loaded via XHR
            if dest == 'document' or (not dest and not xrw):
                html_docs.append((u.path, status, len(body)))
            else:
                fragments.append((u.path, status))
            for m in re.finditer(
                    r'<script[^>]{0,300}src=["\']([^"\']+)["\']', body, re.I):
                scripts.append((u.path, m.group(1)))
            for m in re.finditer(
                    r'<form[^>]+action=["\']([^"\']+)', body, re.I):
                form_actions.add(f'form action -> {m.group(1)} (in {u.path})')

        if method in ('POST', 'PUT', 'DELETE'):
            pd = req.get('postData', {})
            ctype = pd.get('mimeType', '')
            fields = [p['name'] for p in pd.get('params', [])]
            if not fields and pd.get('text'):
                if pd['text'].lstrip().startswith(('{', '[')):
                    fields = ['<JSON body>']
                else:
                    fields = re.findall(r'(?:^|&)([^=&]+)=', pd['text'])
            flags = []
            fset = ' '.join(fields)
            if '__CALLBACKID' in fset:
                flags.append('DevExpress callback')
            if '__VIEWSTATE' in fset:
                flags.append('WebForms postback')
            if 'json' in ctype or fields == ['<JSON body>']:
                flags.append('JSON API (possible SPA)')
            if re.search(r'(user|login|senha|pass|pwd|email|utilizador)',
                         fset, re.I):
                flags.append('** possible LOGIN **')
            posts.append((method, u.path, status, ctype, flags, fields[:12]))

        if method == 'GET' and 'html' not in mime and \
                (xrw or dest == 'empty') and \
                not any(t in mime for t in ('image', 'font', 'css')):
            q = u.path + (('?' + u.query) if u.query else '')
            xhr_get.append((q, status, mime))

    print('=== HTML DOCUMENTS (candidates for INJECTED URIs) ===', file=out)
    for p, s, l in _dedup(html_docs):
        note = '  [!] empty body in HAR' if l == 0 else f'  ({l} bytes)'
        print(f'  [{s}] {p}{note}', file=out)

    if fragments:
        print('\n=== HTML FRAGMENTS via XHR (do NOT inject) ===', file=out)
        for p, s in _dedup(fragments):
            print(f'  [{s}] {p}', file=out)

    print('\n=== POST/PUT/DELETE (candidates for VALIDATED URIs) ===',
          file=out)
    for m, p, s, c, fl, fi in posts:
        print(f'  [{s}] {m} {p}  ct={c}  {" | ".join(fl)}', file=out)
        if fi:
            print(f'        fields: {fi}', file=out)

    if xhr_get:
        print('\n=== XHR/API GET (context) ===', file=out)
        for p, s, mm in _dedup(xhr_get):
            print(f'  [{s}] {p}  ({mm})', file=out)

    if redirects:
        print('\n=== REDIRECTS (check for case variants) ===', file=out)
        for s, p, loc in _dedup(redirects, key=lambda x: (x[1], x[2])):
            print(f'  [{s}] {p} -> {loc}', file=out)

    print('\n=== SCRIPTS REFERENCED IN HTML (sensor detection) ===', file=out)
    sensor_found = False
    for page, src in _dedup(scripts, key=lambda x: x[1]):
        mark = ''
        if KNOWN_SENSORS.search(src):
            mark = '   <<< ANTI-BOT SENSOR DETECTED'
            sensor_found = True
        print(f'  {src}   (in {page}){mark}', file=out)
    print(('\n  RESULT: an anti-bot sensor IS present in the captured pages.'
           if sensor_found else
           '\n  RESULT: NO known anti-bot sensor was detected in the '
           'captured pages.'), file=out)

    if form_actions:
        print('\n=== FRAMEWORK HINTS ===', file=out)
        for f in sorted(form_actions):
            print(f'  {f}', file=out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description='Sanitize a HAR capture and check the CloudGuard WAF '
                    'Anti-Bot configuration.')
    ap.add_argument('har', help='HAR file exported from the browser')
    ap.add_argument('--host',
                    help='host to analyze (default: the most frequent one)')
    args = ap.parse_args()

    src = Path(args.har)
    if not src.exists():
        print(f'ERROR: file not found: {src}', file=sys.stderr)
        return 1

    try:
        with open(src, encoding='utf-8-sig') as f:
            har = json.load(f)
        har['log']['entries']
    except (json.JSONDecodeError, KeyError, TypeError):
        print('ERROR: this does not look like a valid HAR file. '
              'Please re-export it from the browser (see README).',
              file=sys.stderr)
        return 1

    # 1) Sanitize — always first
    stats = sanitize(har)
    sanitized_path = src.parent / (src.stem + '.SANITIZED.har')
    with open(sanitized_path, 'w', encoding='utf-8') as f:
        json.dump(har, f, ensure_ascii=False)

    # 2) Analyze the sanitized copy and write the report
    report_path = src.parent / (src.stem + '.REPORT.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        analyze(har, args.host, f)

    # Console summary
    print('Done.\n')
    print('Sanitization summary (redacted items):')
    for k, v in stats.items():
        print(f'  {k}: {v}')
    print(f'\nFiles created:')
    print(f'  {sanitized_path}')
    print(f'  {report_path}')
    print('\nSend BOTH files to your security contact. '
          'Do NOT send the original .har file.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
