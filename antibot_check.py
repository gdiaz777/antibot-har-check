#!/usr/bin/env python3
"""
antibot_check.py — find the CloudGuard WAF Anti-Bot URIs in a HAR capture

Capture a HAR while you open the login page, log in and land on the
authenticated page. The tool prints the two lists the Anti-Bot practice
needs, as relative URIs:

  Injected URIs   the login/registration pages (GET)
  Validated URIs  the login/registration submissions (POST)

or why it could not recognize the login.

Requirements: Python 3.8+ (standard library only). Windows, macOS, Linux.

Usage:
    python antibot_check.py capture.har
    python antibot_check.py capture.har --sanitize   # also write a safe copy

Exit codes: 0 = URIs found, 2 = login not recognized, 1 = error.
"""

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import (parse_qsl, unquote_plus, urlencode, urljoin,
                          urlparse, urlunparse)

# --------------------------------------------------------------------------
# Login detection
# --------------------------------------------------------------------------

# Field names that hold a password (login, registration, password change)
PASSWORD_FIELDS = re.compile(
    r'(pass|pwd|contrase|senha|clave|passwort|mot_?de_?passe|wachtwoord)',
    re.I)


def _header(req_or_resp: dict, name: str) -> str:
    for h in req_or_resp.get('headers', []):
        if h.get('name', '').lower() == name:
            return h.get('value', '')
    return ''


def _decode_body(content: dict) -> str:
    """Return the response body as text, decoding base64 if needed."""
    text = content.get('text') or ''
    if text and content.get('encoding') == 'base64':
        try:
            return base64.b64decode(text).decode('utf-8', 'replace')
        except (binascii.Error, ValueError):
            return ''
    return text


def _location(url: str) -> Tuple[str, str]:
    """(host, path) of a URL: host without port, path as the WAF sees it."""
    u = urlparse(url)
    return (u.hostname or '').lower(), u.path or '/'


def _attr(tag: str, name: str) -> Optional[str]:
    m = re.search(r'(?:^|\s)' + name + r'\s*=\s*(["\'])(.*?)\1', tag,
                  re.I | re.S)
    return m.group(2).replace('&amp;', '&') if m else None


def _short(field: str) -> str:
    """Last segment of a framework-generated name (ctl00$Panel$txtUser)."""
    return re.split(r'[$.:]', field)[-1] or field


def _json_keys(obj, prefix: str = '') -> List[str]:
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(prefix + k)
            keys.extend(_json_keys(v, prefix + k + '.'))
    elif isinstance(obj, list) and obj:
        keys.extend(_json_keys(obj[0], prefix))
    return keys


def _post_fields(pd: dict) -> List[str]:
    """Field names of a request body (form, multipart or JSON)."""
    fields = [unquote_plus(p.get('name', '')) for p in pd.get('params', [])]
    text = pd.get('text') or ''
    if fields or not text:
        return fields
    if 'multipart' in pd.get('mimeType', ''):
        return re.findall(r'name="([^"]*)"', text)
    if 'json' in pd.get('mimeType', '') or text.lstrip().startswith(('{', '[')):
        try:
            return _json_keys(json.loads(text))
        except ValueError:
            return []
    return [k for k, _ in parse_qsl(text, keep_blank_values=True)]


def find_uris(har: dict):
    """Return (injected, validated, reason).

    injected / validated are lists of (host, path) in capture order; reason
    explains why the login was not recognized (None when it was).
    """
    pages = {}          # (host, path) -> form actions and password inputs
    logins = []         # POSTs that submit a password
    last_page = None

    for e in har['log']['entries']:
        req, resp = e.get('request', {}), e.get('response', {})
        method = req.get('method', '').upper()
        loc = _location(req.get('url', ''))
        dest = _header(req, 'sec-fetch-dest')
        xhr = bool(_header(req, 'x-requested-with')) or dest == 'empty'

        if method == 'GET' and not xhr and \
                'html' in resp.get('content', {}).get('mimeType', '') and \
                dest in ('', 'document', 'iframe') and \
                not 300 <= resp.get('status', 0) < 400:
            page = pages.setdefault(loc, {'actions': set(),
                                          'passwords': set()})
            last_page = loc
            body = _decode_body(resp.get('content', {}))
            for m in re.finditer(r'<form\b[^>]*>', body, re.I):
                action = _attr(m.group(0), 'action')
                page['actions'].add(_location(urljoin(req['url'], action))
                                    if action else loc)
            for m in re.finditer(r'<input\b[^>]*>', body, re.I):
                if (_attr(m.group(0), 'type') or '').lower() == 'password':
                    page['passwords'].add(_attr(m.group(0), 'name') or '')

        if method == 'POST' and req.get('postData'):
            fields = _post_fields(req['postData'])
            referer = _header(req, 'referer')
            logins.append({'loc': loc, 'fields': fields,
                           'referer': _location(referer) if referer else None,
                           'last_page': last_page})

    password_inputs = set()
    for page in pages.values():
        password_inputs |= page['passwords']
    logins = [p for p in logins
              if any(f in password_inputs or PASSWORD_FIELDS.search(_short(f))
                     for f in p['fields'])]
    if not logins:
        return [], [], ('no request in the capture submits a password field. '
                        'Capture the login submission with "Preserve log" '
                        'enabled.')

    validated = list(dict.fromkeys(p['loc'] for p in logins))
    injected = []
    for post in logins:
        found = [loc for loc, page in pages.items()
                 if post['loc'] in page['actions'] and page['passwords']]
        if not found and post['referer'] in pages:
            found = [post['referer']]
        if not found and post['last_page']:
            # SPA: the Referer is a client-side route, not a loaded page
            found = [post['last_page']]
        injected.extend(found)
    injected = list(dict.fromkeys(injected))
    if not injected:
        return [], validated, ('the login page itself (GET) is not in the '
                               'capture. Start recording before opening the '
                               'login page.')
    return injected, validated, None


def report(injected, validated, reason) -> str:
    hosts = {h for h, _ in injected + validated}

    def fmt(locs):
        return '\n'.join(f'  {f"{h} " if len(hosts) > 1 else ""}{p}'
                         for h, p in locs)

    lines = []
    if injected:
        lines += ['Injected URIs:', fmt(injected), '']
    if validated:
        lines += ['Validated URIs:', fmt(validated), '']
    if reason:
        lines.append(f'Could not identify the login: {reason}')
    return '\n'.join(lines).rstrip()


# --------------------------------------------------------------------------
# Optional: sanitized copy (--sanitize)
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

REDACTED = '[REDACTED]'


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


def _html_skeleton(doc: str) -> str:
    """Keep only what the analysis reads: <form> tags (action redacted) and
    input fields (values redacted). Page text and scripts are dropped."""
    out = []
    for m in re.finditer(r'<form\b[^>]*>', doc, re.I):
        out.append(re.sub(r'\baction\s*=\s*(["\'])([^"\']*)\1',
                          lambda a: f'action={a.group(1)}'
                                    f'{_redact_url(a.group(2))}{a.group(1)}',
                          m.group(0), flags=re.I))
    for m in re.finditer(r'<(input|textarea|select)\b[^>]*>', doc, re.I):
        out.append(re.sub(r'\bvalue\s*=\s*(["\'])[^"\']*\1',
                          f'value="{REDACTED}"', m.group(0), flags=re.I))
    return '\n'.join(out)


def _sanitize_post(pd: dict) -> None:
    for p in pd.get('params', []):
        p['value'] = REDACTED
        if p.get('fileName'):
            p['fileName'] = REDACTED
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
        pd['text'] = ''.join(f'name="{n}"\n' for n in names)
    elif 'x-www-form-urlencoded' in ctype or \
            re.match(r'^[\w.\-\[\]%]+=', stripped):
        pd['text'] = _redact_query(text)
    else:
        pd['text'] = f'[BODY REDACTED - {ctype} - {len(text)} bytes]'


def sanitize(har: dict) -> None:
    """Redact sensitive data in place. Field names, paths and form structure
    are kept, so the sanitized copy gives the same result."""
    for page in har['log'].get('pages', []):
        if '://' in page.get('title', ''):
            page['title'] = _redact_url(page['title'])

    for entry in har['log']['entries']:
        req, resp = entry.get('request', {}), entry.get('response', {})

        for side in (req, resp):
            for h in side.get('headers', []):
                name = h.get('name', '').lower()
                if name in SENSITIVE_HEADERS or \
                        SENSITIVE_HEADER_WORDS.search(name):
                    h['value'] = REDACTED
                elif name in URL_HEADERS:
                    h['value'] = _redact_url(h.get('value', ''))
            for c in side.get('cookies', []):
                c['value'] = REDACTED

        for side, key in ((req, 'url'), (resp, 'redirectURL')):
            if side.get(key):
                side[key] = _redact_url(side[key])
        for p in req.get('queryString', []):
            p['value'] = REDACTED
        if req.get('postData'):
            _sanitize_post(req['postData'])

        entry.pop('_initiator', None)
        for msg in entry.get('_webSocketMessages', []):
            msg['data'] = REDACTED

        # Response bodies: HTML reduced to forms and fields, the rest removed
        content = resp.get('content', {})
        if content.get('text'):
            mime = content.get('mimeType', '').lower()
            body = _decode_body(content)
            content.pop('encoding', None)
            content['text'] = _html_skeleton(body) if 'html' in mime else \
                f'[BODY REMOVED - {mime} - {content.get("size", 0)} bytes]'

    har['log']['_sanitized'] = True


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description='Find the CloudGuard WAF Anti-Bot Injected and Validated '
                    'URIs in a HAR capture of a login.')
    ap.add_argument('har', help='HAR file exported from the browser')
    ap.add_argument('--sanitize', action='store_true',
                    help='also write <name>.SANITIZED.har, safe to share')
    args = ap.parse_args()

    src = Path(args.har)
    try:
        with open(src, encoding='utf-8-sig') as f:
            har = json.load(f)
        for e in har['log']['entries']:
            e['request']['url']
    except OSError as exc:
        print(f'ERROR: cannot read {src}: {exc}', file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError):
        print('ERROR: this is not a valid HAR file. Export it again from the '
              'browser (see README).', file=sys.stderr)
        return 1

    injected, validated, reason = find_uris(har)
    print(report(injected, validated, reason))

    if args.sanitize:
        sanitize(har)
        out = src.parent / (src.stem + '.SANITIZED.har')
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(har, f, ensure_ascii=False)
        print(f'\nSanitized copy: {out}')
    return 2 if reason else 0


if __name__ == '__main__':
    sys.exit(main())
