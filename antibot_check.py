#!/usr/bin/env python3
"""
antibot_check.py — CloudGuard WAF Anti-Bot HAR checker

A self-contained, dependency-free tool that:
  1. SANITIZES a browser HAR capture (removes cookies, auth headers, tokens,
     credentials, form/JSON values, page content and binary bodies) so it is
     safe to share with your security team.
  2. ANALYZES the sanitized capture of a login and recommends the Anti-Bot
     practice values:
       - Injected URIs: the login/registration pages (GET) where the JS
         sensor must be injected
       - Validated URIs: the login/registration submissions (POST) whose
         sensor output is validated
       - Whether an anti-bot sensor is ALREADY present in the pages

Requirements: Python 3.8+ (standard library only — no pip install needed).
Works on Windows, macOS and Linux.

Usage:
    python antibot_check.py capture.har
    python antibot_check.py capture.har --host portal.example.com
    python antibot_check.py capture.har --verbose

Output (created next to the input file):
    capture.SANITIZED.har   -> safe-to-share copy (send THIS one, never the original)
    capture.REPORT.txt      -> human-readable analysis report
"""

import argparse
import base64
import binascii
import html
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Optional
from urllib.parse import (parse_qsl, unquote_plus, urlencode, urljoin,
                          urlparse, urlunparse)

# --------------------------------------------------------------------------
# Sanitization settings
# --------------------------------------------------------------------------

# Headers whose values are always redacted (request and response)
SENSITIVE_HEADERS = {
    'cookie', 'set-cookie', 'authorization', 'proxy-authorization',
    'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token',
    'x-amz-security-token', 'x-goog-authuser',
}

# Any other header whose name contains one of these words is redacted too
SENSITIVE_HEADER_WORDS = re.compile(
    r'(token|auth|secret|session|csrf|xsrf|key|cookie|signature|'
    r'credential|password|jwt)', re.I)

# Headers that carry full URLs: their query string / fragment is redacted
URL_HEADERS = {'referer', 'location', 'content-location', 'refresh',
               ':path'}

# Response bodies to KEEP (needed to detect the injected sensor). HTML is
# reduced to a skeleton (scripts, forms, field names) — page text is dropped.
# JSON keeps its keys only. Everything else is stripped.
KEEP_MIMES = ('javascript', 'ecmascript', 'css')

REDACTED = '[REDACTED]'

# String literals and JWTs inside inline scripts. Literals are redacted
# unless they look like a URL/path (needed to spot a sensor loader).
JS_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|'
                       r'`(?:[^`\\]|\\.)*`')
JWT = re.compile(r'eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*')

# Signatures of known anti-bot / bot-management sensors: (vendor, regex)
# matched against script URLs and inline script bodies
KNOWN_SENSORS = [
    ('Check Point CloudGuard', re.compile(r'cloudguard|checkpoint|/cp-', re.I)),
    ('HUMAN / PerimeterX', re.compile(r'perimeterx|px-cdn|px-cloud|/px/', re.I)),
    ('DataDome', re.compile(r'datadome', re.I)),
    ('Imperva / Incapsula', re.compile(r'imperva|incapsula|_Incapsula_', re.I)),
    ('Akamai Bot Manager', re.compile(r'akamai.*bmp|/_bm/|/akam/', re.I)),
    ('Kasada', re.compile(r'kasada|/ips\.js|kpsdk', re.I)),
    ('F5 / Shape', re.compile(r'shapesecurity|f5.*bot', re.I)),
    ('Cloudflare Bot Management',
     re.compile(r'/cdn-cgi/challenge-platform/|challenges\.cloudflare\.com',
                re.I)),
]

# CAPTCHAs are reported separately: they are not a passive sensor
KNOWN_CAPTCHAS = re.compile(r'recaptcha|hcaptcha|turnstile|arkoselabs|funcaptcha',
                            re.I)

# Cookie names set by known bot-management vendors (names survive sanitizing)
KNOWN_SENSOR_COOKIES = [
    ('Akamai Bot Manager', re.compile(r'^(_abck|bm_sz|bm_sv|ak_bmsc)$')),
    ('HUMAN / PerimeterX', re.compile(r'^_px')),
    ('DataDome', re.compile(r'^datadome$', re.I)),
    ('Imperva / Incapsula', re.compile(r'^(incap_ses_|visid_incap_|reese84)')),
    ('Cloudflare Bot Management', re.compile(r'^(__cf_bm|cf_clearance)$')),
]


# --------------------------------------------------------------------------
# Step 1 — Sanitize
# --------------------------------------------------------------------------

def _redact_query(qs: str) -> str:
    """Keep parameter names, redact every value."""
    if not qs:
        return qs
    pairs = parse_qsl(qs, keep_blank_values=True)
    if not pairs:
        return REDACTED
    return urlencode([(k, REDACTED) for k, _ in pairs], safe='[]')


def _redact_url(url: str) -> str:
    """Redact query-string and fragment values, keep scheme/host/path."""
    try:
        u = urlparse(url)
    except ValueError:
        return REDACTED
    if not (u.query or u.fragment or u.username or u.password):
        return url
    netloc = u.netloc.rsplit('@', 1)[-1]
    return urlunparse(u._replace(netloc=netloc, query=_redact_query(u.query),
                                 fragment=_redact_query(u.fragment)))


def _redact_json(obj):
    """Recursively replace every scalar value, keep keys and structure."""
    if isinstance(obj, dict):
        return {k: _redact_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_json(v) for v in obj]
    if obj is None or isinstance(obj, bool):
        return obj
    return REDACTED


def _decode_body(content: dict) -> str:
    """Return the response body as text, decoding base64 if needed."""
    text = content.get('text') or ''
    if text and content.get('encoding') == 'base64':
        try:
            return base64.b64decode(text).decode('utf-8', 'replace')
        except (binascii.Error, ValueError):
            return ''
    return text


def _redact_inline_js(code: str) -> str:
    def literal(m):
        s = m.group(0)
        if '/' in s and '@' not in s and ' ' not in s:
            return _redact_url(s[1:-1]).join((s[0], s[-1]))
        return f'{s[0]}{REDACTED}{s[-1]}'
    return JWT.sub(REDACTED, JS_STRING.sub(literal, code))


def _html_skeleton(doc: str) -> str:
    """Reduce an HTML page to what the analysis needs: script tags (inline
    bodies with tokens redacted), forms and input names. Page text, hidden
    field values and meta contents are dropped."""
    out = []
    for m in re.finditer(r'<script\b([^>]*)>(.*?)</script\s*>', doc,
                         re.I | re.S):
        attrs, body = m.group(1), m.group(2)
        attrs = re.sub(r'\b(nonce|integrity)\s*=\s*["\'][^"\']*["\']', '',
                       attrs, flags=re.I)
        attrs = re.sub(r'\bsrc\s*=\s*(["\'])([^"\']*)\1',
                       lambda a: f'src={a.group(1)}'
                                 f'{_redact_url(html.unescape(a.group(2)))}'
                                 f'{a.group(1)}', attrs, flags=re.I)
        out.append(f'<script{attrs}>{_redact_inline_js(body)}</script>')
    for m in re.finditer(r'<form\b[^>]*>', doc, re.I):
        tag = re.sub(r'\baction\s*=\s*(["\'])([^"\']*)\1',
                     lambda a: f'action={a.group(1)}'
                               f'{_redact_url(a.group(2))}{a.group(1)}',
                     m.group(0), flags=re.I)
        out.append(tag)
    for m in re.finditer(r'<(input|textarea|select)\b[^>]*>', doc, re.I):
        tag = re.sub(r'\bvalue\s*=\s*(["\'])[^"\']*\1', f'value="{REDACTED}"',
                     m.group(0), flags=re.I)
        out.append(tag)
    return '\n'.join(out)


def _sanitize_post(pd: dict, stats: dict) -> None:
    for p in pd.get('params', []):
        p['value'] = REDACTED
        if p.get('fileName'):
            p['fileName'] = REDACTED
        stats['post_fields'] += 1

    text = pd.get('text')
    if not text:
        return
    ctype = pd.get('mimeType', '').lower()
    stripped = text.lstrip()
    if 'json' in ctype or stripped.startswith(('{', '[')):
        try:
            pd['text'] = json.dumps(_redact_json(json.loads(text)))
        except ValueError:
            pd['text'] = f'[BODY REDACTED - {ctype} - {len(text)} bytes]'
    elif 'multipart' in ctype:
        names = re.findall(r'name="([^"]*)"', text)
        if names and not pd.get('params'):
            pd['params'] = [{'name': n, 'value': REDACTED} for n in names]
        pd['text'] = f'[MULTIPART BODY REDACTED - fields: {", ".join(names)}]'
    elif 'x-www-form-urlencoded' in ctype or \
            re.match(r'^[\w.\-\[\]%]+=', stripped):
        pd['text'] = _redact_query(text)
    else:
        pd['text'] = f'[BODY REDACTED - {ctype} - {len(text)} bytes]'
    stats['post_fields'] += 1


def sanitize(har: dict) -> dict:
    """Redact sensitive data in-place. Returns redaction statistics."""
    stats = {'headers': 0, 'cookies': 0, 'urls': 0, 'query_params': 0,
             'post_fields': 0, 'response_bodies_reduced': 0,
             'response_bodies_removed': 0}

    for page in har['log'].get('pages', []):
        if '://' in page.get('title', ''):
            page['title'] = _redact_url(page['title'])

    for entry in har['log']['entries']:
        req, resp = entry.get('request', {}), entry.get('response', {})

        # Sensitive headers and all cookie values, on both sides
        for side in (req, resp):
            for h in side.get('headers', []):
                name = h.get('name', '').lower()
                if name in SENSITIVE_HEADERS or \
                        SENSITIVE_HEADER_WORDS.search(name):
                    h['value'] = REDACTED
                    stats['headers'] += 1
                elif name in URL_HEADERS:
                    new = _redact_url(h.get('value', ''))
                    if new != h.get('value'):
                        h['value'] = new
                        stats['headers'] += 1
            for c in side.get('cookies', []):
                c['value'] = REDACTED
                stats['cookies'] += 1

        # URLs and query strings: keep parameter names, redact all values
        for side, key in ((req, 'url'), (resp, 'redirectURL')):
            if side.get(key):
                new = _redact_url(side[key])
                if new != side[key]:
                    side[key] = new
                    stats['urls'] += 1
        for p in req.get('queryString', []):
            p['value'] = REDACTED
            stats['query_params'] += 1

        # Request bodies: redact values, keep field names
        if req.get('postData'):
            _sanitize_post(req['postData'], stats)

        # Browser-specific extras that may carry data or full URLs
        entry.pop('_initiator', None)
        for msg in entry.get('_webSocketMessages', []):
            msg['data'] = REDACTED

        # Response bodies: keep JS/CSS, reduce HTML/JSON, strip the rest
        content = resp.get('content', {})
        if not content.get('text'):
            continue
        mime = content.get('mimeType', '').lower()
        body = _decode_body(content)
        size = content.get('size', len(body))
        content.pop('encoding', None)
        if any(t in mime for t in KEEP_MIMES):
            content['text'] = body
        elif 'html' in mime:
            content['text'] = _html_skeleton(body)
            content['_originalSize'] = size
            stats['response_bodies_reduced'] += 1
        elif 'json' in mime:
            try:
                content['text'] = json.dumps(_redact_json(json.loads(body)))
            except ValueError:
                content['text'] = f'[BODY REMOVED - {mime} - {size} bytes]'
            stats['response_bodies_reduced'] += 1
        else:
            content['text'] = f'[BODY REMOVED - {mime} - {size} bytes]'
            stats['response_bodies_removed'] += 1

    # Marker so downstream tooling can verify the file was sanitized
    har['log']['_sanitized'] = True
    return stats


# --------------------------------------------------------------------------
# Step 2 — Analyze
# --------------------------------------------------------------------------

# Field names that hold a password (login, registration, password change)
PASSWORD_FIELDS = re.compile(
    r'(pass|pwd|contrase|senha|clave|passwort|mot_?de_?passe|wachtwoord)',
    re.I)
# Field names that hold the account identifier
USER_FIELDS = re.compile(
    r'(user|usuari|login|logon|e?mail|utilizador|account|nif|dni|'
    r'identifica)', re.I)
LOGIN_PATHS = re.compile(
    r'(login|logon|signin|sign-in|sign_in|auth|token|session|register|'
    r'signup)', re.I)
# Framework callbacks / partial postbacks: user actions inside an already
# loaded page, not credential submissions
CALLBACK_FIELDS = ('__CALLBACKID', '__ASYNCPOST')
# Identity providers: a login performed there is outside this WAF asset
KNOWN_IDPS = re.compile(
    r'(login\.microsoftonline\.com|login\.live\.com|accounts\.google\.com|'
    r'\.okta\.com|\.auth0\.com|b2clogin\.com|/adfs/|/realms/[^/]+/protocol/'
    r'openid-connect)', re.I)


def _header(req_or_resp, name):
    for h in req_or_resp.get('headers', []):
        if h.get('name', '').lower() == name:
            return h.get('value', '')
    return ''


def _hostname(netloc_or_url: str) -> str:
    """Lowercase host without port or credentials."""
    if '://' not in netloc_or_url:
        netloc_or_url = '//' + netloc_or_url
    return (urlparse(netloc_or_url).hostname or '').lower()


def _path(url: str) -> str:
    return urlparse(url).path or '/'


def _attr(tag: str, name: str) -> Optional[str]:
    m = re.search(r'(?:^|\s)' + name + r'\s*=\s*(["\'])(.*?)\1', tag,
                  re.I | re.S)
    return html.unescape(m.group(2)) if m else None


def _short(field: str) -> str:
    """Last segment of a framework-generated name (ctl00$Panel$txtUser)."""
    return re.split(r'[$.:]', field)[-1] or field


def _dedup(seq, key=lambda x: x[0]):
    seen, out = set(), []
    for item in seq:
        if key(item) not in seen:
            seen.add(key(item))
            out.append(item)
    return out


def _json_keys(obj, prefix=''):
    """Flatten the key names of a JSON document (values are not needed)."""
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(prefix + k)
            keys.extend(_json_keys(v, prefix + k + '.'))
    elif isinstance(obj, list) and obj:
        keys.extend(_json_keys(obj[0], prefix))
    return keys


def _post_fields(pd: dict):
    """Return (field names, is_json) of a request body."""
    fields = [unquote_plus(p.get('name', '')) for p in pd.get('params', [])]
    text = pd.get('text') or ''
    if fields or not text:
        return fields, False
    if 'json' in pd.get('mimeType', '') or text.lstrip().startswith(('{', '[')):
        try:
            return _json_keys(json.loads(text)), True
        except ValueError:
            return ['<JSON body>'], True
    return [k for k, _ in parse_qsl(text, keep_blank_values=True)], False


def _classify(post: dict, password_inputs: set) -> None:
    """Tag a POST as 'login', 'possible' (login/registration) or 'other'."""
    fields = post['fields']
    pw = [f for f in fields
          if f in password_inputs or PASSWORD_FIELDS.search(_short(f))]
    user = [f for f in fields if f not in pw and USER_FIELDS.search(_short(f))]
    callback = any(c in fields for c in CALLBACK_FIELDS)
    post['password'], post['user'], post['callback'] = pw, user, callback
    if post['method'] != 'POST':
        post['kind'] = 'other'
    elif pw or 'grant_type' in fields:
        post['kind'] = 'login'
    elif not callback and user and LOGIN_PATHS.search(post['path']):
        post['kind'] = 'possible'
    else:
        post['kind'] = 'other'


def _collect(har: dict, target: str) -> dict:
    """Walk the capture once and gather everything the report needs."""
    d = {'pages': {}, 'fragments': [], 'posts': [], 'xhr_get': [],
         'redirects': [], 'scripts': [], 'inline': [], 'js_loaded': [],
         'cookies': set(), 'external_logins': [], 'idp_redirects': set()}
    last_doc = None

    for e in har['log']['entries']:
        req, resp = e['request'], e.get('response', {})
        u = urlparse(req['url'])
        method = req.get('method', '').upper()
        status = resp.get('status', 0)
        content = resp.get('content', {})
        mime = content.get('mimeType', '').lower()
        dest = _header(req, 'sec-fetch-dest')
        xrw = _header(req, 'x-requested-with')
        loc = _header(resp, 'location') or resp.get('redirectURL', '')
        if loc and KNOWN_IDPS.search(loc):
            d['idp_redirects'].add(_hostname(urljoin(req['url'], loc)))

        # Sensor evidence is collected from every host: sensors are often
        # served from a vendor CDN or a dedicated subdomain
        for c in req.get('cookies', []) + resp.get('cookies', []):
            d['cookies'].add(c.get('name', ''))
        if 'javascript' in mime or dest == 'script':
            d['js_loaded'].append(u.netloc + u.path)

        if _hostname(req['url']) != target:
            if method == 'POST' and req.get('postData'):
                fields, _ = _post_fields(req['postData'])
                if any(PASSWORD_FIELDS.search(_short(f)) for f in fields):
                    d['external_logins'].append(u.netloc + u.path)
            continue

        body = _decode_body(content)
        if loc and 300 <= status < 400:
            d['redirects'].append((status, method, u.path,
                                   _path(urljoin(req['url'], loc)), loc))
            if method == 'GET':
                continue

        if 'html' in mime and method == 'GET':
            # Full document navigation vs. HTML fragment loaded via XHR
            if dest in ('document', 'iframe') or (not dest and not xrw):
                last_doc = u.path
                page = d['pages'].setdefault(u.path, {
                    'status': status, 'size': 0, 'iframe': dest == 'iframe',
                    'password': set(), 'user': set(), 'actions': set(),
                    'query': set()})
                page['size'] = max(page['size'],
                                   content.get('_originalSize', len(body)))
                page['query'].update(
                    k for k, _ in parse_qsl(u.query, keep_blank_values=True))
                for m in re.finditer(r'<input\b[^>]*>', body, re.I):
                    name = _attr(m.group(0), 'name')
                    kind = (_attr(m.group(0), 'type') or 'text').lower()
                    if not name:
                        continue
                    if kind == 'password':
                        page['password'].add(name)
                    elif kind in ('text', 'email', 'tel') and \
                            USER_FIELDS.search(_short(name)):
                        page['user'].add(name)
                for m in re.finditer(r'<form\b[^>]*>', body, re.I):
                    action = _attr(m.group(0), 'action')
                    page['actions'].add(
                        _path(urljoin(req['url'], action)) if action
                        else u.path)
            else:
                d['fragments'].append((u.path, status))
            for m in re.finditer(r'<script\b([^>]*)>(.*?)</script\s*>', body,
                                 re.I | re.S):
                src = _attr(m.group(1), 'src')
                if src:
                    d['scripts'].append((u.path, src))
                elif m.group(2).strip():
                    d['inline'].append((u.path, m.group(2)))

        if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            pd = req.get('postData') or {}
            fields, is_json = _post_fields(pd)
            referer = _header(req, 'referer')
            d['posts'].append({
                'method': method, 'path': u.path, 'status': status,
                'ctype': pd.get('mimeType', ''), 'fields': fields,
                'is_json': is_json or 'json' in pd.get('mimeType', ''),
                'xhr': bool(xrw) or dest == 'empty',
                'location': _path(urljoin(req['url'], loc)) if loc else '',
                'referer': _path(referer)
                if referer and _hostname(referer) == target else '',
                'last_doc': last_doc,
                'set_cookies': sorted(c.get('name', '')
                                      for c in resp.get('cookies', []))})

        if method == 'GET' and 'html' not in mime and \
                (xrw or dest == 'empty') and \
                not any(t in mime for t in ('image', 'font', 'css')):
            q = u.path
            if u.query:
                q += '?' + '&'.join(k for k, _ in
                                    parse_qsl(u.query, keep_blank_values=True))
            d['xhr_get'].append((q, status, mime))

    password_inputs = set()
    for page in d['pages'].values():
        password_inputs |= page['password']
    for post in d['posts']:
        _classify(post, password_inputs)
    return d


def _recommend(d: dict):
    """Build the Validated and Injected URI lists with their evidence."""
    validated = {}
    for post in d['posts']:
        if post['kind'] == 'other':
            continue
        v = validated.setdefault(post['path'], {'posts': [], 'why': []})
        v['posts'].append(post)
    for path, v in validated.items():
        why, posts = v['why'], v['posts']
        if not any(p['kind'] == 'login' for p in posts):
            why.append('[?] no password field — possible first step of a '
                       'multi-step login or a registration form; confirm')
        pw = sorted({_short(f) for p in posts for f in p['password']})
        user = sorted({_short(f) for p in posts for f in p['user']})
        if pw:
            why.append('password field(s): ' + ', '.join(pw))
        if user:
            why.append('user field(s): ' + ', '.join(user))
        for p in _dedup(posts, key=lambda p: (p['status'], p['location'],
                                              p['xhr'])):
            how = 'XHR/fetch (SPA)' if p['xhr'] else 'browser form submit'
            res = f'{p["status"]}'
            if p['location']:
                res += f' -> {p["location"]}'
            why.append(f'{how}, response {res}')
        cookies = sorted({c for p in posts for c in p['set_cookies']})
        if cookies:
            why.append('response sets cookies: ' + ', '.join(cookies))
        if any('__VIEWSTATE' in p['fields'] for p in posts):
            why.append('ASP.NET WebForms: the page is a single form, so '
                       'login, password change, recovery and 2FA all post '
                       'to this same URI')

    injected = {}

    def add(path, reason):
        page = d['pages'].get(path)
        if page is None:
            return False
        injected.setdefault(path, [])
        if reason not in injected[path]:
            injected[path].append(reason)
        return True

    for path, v in validated.items():
        for page_path, page in d['pages'].items():
            if path in page['actions']:
                add(page_path, f'its <form> posts to {path} (Validated URI)')
        for p in v['posts']:
            if p['referer'] and not add(p['referer'],
                                        f'Referer of the POST to {path}'):
                if p['last_doc'] and add(
                        p['last_doc'],
                        f'document that loaded the app before the POST to '
                        f'{path} (Referer {p["referer"]} is a client-side '
                        f'route)'):
                    pass
            elif not p['referer'] and p['last_doc'] and \
                    p['last_doc'] not in injected:
                add(p['last_doc'],
                    f'last page loaded before the POST to {path}')
    for page_path, page in d['pages'].items():
        if page['password']:
            add(page_path, 'contains password field(s): ' + ', '.join(
                sorted({_short(f) for f in page['password']})))

    # Pages only reached as part of the logged-in session are not login
    # pages: drop "last page loaded" guesses that point at a POST target
    for path in list(injected):
        if all(r.startswith('last page') for r in injected[path]) and \
                any(p['location'] == path for v in validated.values()
                    for p in v['posts']):
            del injected[path]
    return validated, injected


def analyze(har: dict, host: Optional[str], out,
            verbose: bool = False) -> None:
    """Write the analysis report for one host to the `out` stream."""
    entries = har['log']['entries']

    hosts = Counter(_hostname(e['request']['url']) for e in entries)
    print('Hosts found in the capture:', file=out)
    for h, c in hosts.most_common():
        print(f'  {c:4d}  {h}', file=out)
    target = _hostname(host) if host else hosts.most_common(1)[0][0]
    print(f'\nAnalyzed host: {target}\n', file=out)

    d = _collect(har, target)
    validated, injected = _recommend(d)
    seen_paths = set(d['pages']) | {r[2] for r in d['redirects']} | \
        {p['path'] for p in d['posts']}

    print('=' * 72, file=out)
    print('ANTI-BOT CONFIGURATION — recommended values', file=out)
    print('(relative URIs, without domain, as the Anti-Bot practice expects)',
          file=out)
    print('=' * 72, file=out)

    print('\nINJECTED URIs  (login/registration pages, GET):', file=out)
    if not injected:
        print('  (none found)', file=out)
    for path, why in injected.items():
        page = d['pages'][path]
        print(f'  {path}', file=out)
        for w in why:
            print(f'      - {w}', file=out)
        if not page['size']:
            print('      - [!] empty body in HAR: re-capture with "Preserve '
                  'log" to verify the form/sensor', file=out)
        if page['iframe']:
            print('      - [!] loaded inside an iframe', file=out)
        if page['query']:
            print('      - loaded with query parameters: '
                  + ', '.join(sorted(page['query'])), file=out)
        for s, m, src, dst, _ in _dedup(d['redirects'],
                                        key=lambda r: (r[2], r[3])):
            if dst == path and src != path and m == 'GET':
                print(f'      - also reached via {s} redirect from {src}',
                      file=out)
        variants = sorted(p for p in seen_paths
                          if p.lower() == path.lower() and p != path)
        if variants:
            print('      - [!] case variants seen, add them too: '
                  + ', '.join(variants), file=out)

    print('\nVALIDATED URIs (login/registration submissions, POST):',
          file=out)
    if not validated:
        print('  (none found)', file=out)
    for path, v in validated.items():
        print(f'  {path}', file=out)
        for w in v['why']:
            print(f'      - {w}', file=out)

    warnings = []
    if not validated:
        warnings.append('No login submission was found. Re-capture and make '
                        'sure you actually submit the login form, with '
                        '"Preserve log" enabled.')
    if validated and not injected:
        warnings.append('The login page itself (GET) is not in the capture. '
                        'Start the recording BEFORE opening the login page.')
    for ext in _dedup(d['external_logins'], key=lambda x: x):
        warnings.append(f'Credentials are also posted to another host: {ext}. '
                        f'Analyze it with --host if it is behind this WAF.')
    for idp in sorted(d['idp_redirects']):
        warnings.append(f'Redirect to identity provider {idp} (SSO): that '
                        f'login is not protected by this WAF asset.')
    if warnings:
        print('\nNOTES:', file=out)
        for w in warnings:
            print(f'  [!] {w}', file=out)

    print('\n' + '=' * 72, file=out)
    print('DETAILS', file=out)
    print('=' * 72, file=out)

    print('\n=== HTML DOCUMENTS (all pages navigated to) ===', file=out)
    if not d['pages']:
        print('  (none — capture the page load with "Preserve log" enabled)',
              file=out)
    for path, page in d['pages'].items():
        note = '  [!] empty body in HAR' if not page['size'] \
            else f'  ({page["size"]} bytes)'
        mark = '   <<< INJECTED URI' if path in injected else ''
        kind = ' (iframe)' if page['iframe'] else ''
        print(f'  [{page["status"]}] {path}{kind}{note}{mark}', file=out)

    if d['fragments']:
        print('\n=== HTML FRAGMENTS via XHR (do NOT inject) ===', file=out)
        for p, s in _dedup(d['fragments']):
            print(f'  [{s}] {p}', file=out)

    others = [p for p in d['posts'] if p['path'] not in validated]
    if others:
        print('\n=== OTHER POST/PUT/PATCH/DELETE (not login — normally NOT '
              'Validated URIs) ===', file=out)
        calls = Counter((p['method'], p['path']) for p in others)
        for p in _dedup(others, key=lambda p: (p['method'], p['path'])):
            n = calls[(p['method'], p['path'])]
            flags = []
            if p['callback']:
                flags.append('AJAX callback')
            if p['xhr']:
                flags.append('XHR/fetch')
            if p['is_json']:
                flags.append('JSON')
            times = f' (x{n})' if n > 1 else ''
            print(f'  [{p["status"]}] {p["method"]} {p["path"]}{times}  '
                  f'{" | ".join(flags)}', file=out)
            if verbose and p['fields']:
                print(f'        fields: {[_short(f) for f in p["fields"]]}',
                      file=out)

    if verbose:
        for path, v in validated.items():
            fields = _dedup([f for p in v['posts'] for f in p['fields']],
                            key=lambda x: x)
            print(f'\n=== FIELDS POSTED TO {path} ===', file=out)
            print(f'  {[_short(f) for f in fields]}', file=out)
        if d['xhr_get']:
            print('\n=== XHR/API GET (context) ===', file=out)
            for p, s, mm in _dedup(d['xhr_get']):
                print(f'  [{s}] {p}  ({mm})', file=out)

    if d['redirects']:
        print('\n=== REDIRECTS (check for case variants) ===', file=out)
        for s, m, src, _, loc in _dedup(d['redirects'],
                                        key=lambda r: (r[1], r[2], r[4])):
            print(f'  [{s}] {m} {src} -> {loc}', file=out)

    _report_sensor(d, out, verbose)


def _report_sensor(d: dict, out, verbose: bool) -> None:
    print('\n=== ANTI-BOT SENSOR DETECTION ===', file=out)
    vendors = set()

    def _match(text):
        return [v for v, rx in KNOWN_SENSORS if rx.search(text)]

    scripts = _dedup(d['scripts'], key=lambda x: x[1])
    shown = 0
    for page, src in scripts:
        found = _match(src)
        vendors.update(found)
        mark = f'   <<< ANTI-BOT SENSOR ({", ".join(found)})' if found else ''
        if KNOWN_CAPTCHAS.search(src):
            mark += '   <<< CAPTCHA'
        if verbose or mark:
            print(f'  {src}   (in {page}){mark}', file=out)
            shown += 1
    if len(scripts) > shown:
        print(f'  {len(scripts) - shown} other <script src> in the captured '
              f'HTML (use --verbose to list them)', file=out)

    evidence = []
    for page, code in d['inline']:
        for v in _match(code):
            evidence.append((f'inline <script> in {page}', v))
    for js in _dedup(d['js_loaded'], key=lambda x: x):
        for v in _match(js):
            evidence.append((f'script loaded: {js}', v))
    for name in sorted(d['cookies']):
        for v, rx in KNOWN_SENSOR_COOKIES:
            if rx.search(name):
                evidence.append((f'cookie {name}', v))
    for what, v in _dedup(evidence, key=lambda x: x):
        print(f'  {what}   <<< {v}', file=out)
        vendors.add(v)

    print((f'\n  RESULT: an anti-bot sensor IS present in the captured pages '
           f'({", ".join(sorted(vendors))}).'
           if vendors else
           '\n  RESULT: NO known anti-bot sensor was detected in the '
           'captured pages.'), file=out)


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
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='list every script, posted field and XHR call')
    args = ap.parse_args()

    src = Path(args.har)
    if not src.is_file():
        print(f'ERROR: file not found: {src}', file=sys.stderr)
        return 1

    try:
        with open(src, encoding='utf-8-sig') as f:
            har = json.load(f)
        entries = har['log']['entries']
        for e in entries:
            e['request']['url']
    except (OSError, UnicodeDecodeError) as exc:
        print(f'ERROR: cannot read {src}: {exc}', file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError):
        print('ERROR: this does not look like a valid HAR file. '
              'Please re-export it from the browser (see README).',
              file=sys.stderr)
        return 1

    if not entries:
        print('ERROR: the capture contains no requests. Re-capture with the '
              'Network tab open and "Preserve log" enabled (see README).',
              file=sys.stderr)
        return 1

    hosts = {_hostname(e['request']['url']) for e in entries}
    if args.host and _hostname(args.host) not in hosts:
        print(f'ERROR: host {args.host} not found in the capture. '
              f'Hosts present: {", ".join(sorted(hosts))}', file=sys.stderr)
        return 1

    # 1) Sanitize — always first
    stats = sanitize(har)
    sanitized_path = src.parent / (src.stem + '.SANITIZED.har')
    with open(sanitized_path, 'w', encoding='utf-8') as f:
        json.dump(har, f, ensure_ascii=False)

    # 2) Analyze the sanitized copy and write the report
    report_path = src.parent / (src.stem + '.REPORT.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        analyze(har, args.host, f, args.verbose)

    # Console summary
    print('Done.\n')
    print('Sanitization summary (redacted items):')
    for k, v in stats.items():
        print(f'  {k}: {v}')
    print('\nFiles created:')
    print(f'  {sanitized_path}')
    print(f'  {report_path}')
    print('\nSend BOTH files to your security contact. '
          'Do NOT send the original .har file.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
