import base64
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import antibot_check as ac  # noqa: E402

SECRETS = [
    'ATOKEN-SECRET', 'RT-SECRET', 'hunter2', 'MULTISECRET', 'OAUTHCODE',
    'URLTOKEN', 'REFTOKEN', 'HDRSECRET', 'FRAGTOKEN', 'SESSQ', 'CSRFSECRET',
    'eyJhbGciOiJIUzI1NiJ9', 'a@b.example', 'Juan Perez', 'WSSECRET',
    'COOKIEVAL', 'BEARERVAL', 'USERINFO',
]

HTML = (
    '<html><head><title>Hola Juan Perez</title>'
    '<script src="/static/app.js"></script>'
    '<script data-src="/lazy/checkpoint.js"></script>'
    '<script>window.__t="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc";'
    'window.user={email:"a@b.example"};'
    'load("/cdn-cgi/challenge-platform/x.js");</script></head>'
    '<body><form action="/login" method="post">'
    '<input type="hidden" name="csrf" value="CSRFSECRET">'
    '<input name="username"></form><p>Juan Perez</p></body></html>')


def _h(**kw):
    return [{'name': k.replace('_', '-'), 'value': v} for k, v in kw.items()]


def _entry(method, url, status=200, mime='text/html', text='', reqh=None,
           resph=None, pd=None, qs=None, enc=None, cookies=None):
    content = {'mimeType': mime, 'size': len(text), 'text': text}
    if enc:
        content['encoding'] = enc
    req = {'method': method, 'url': url, 'headers': reqh or [],
           'cookies': cookies or [], 'queryString': qs or []}
    if pd:
        req['postData'] = pd
    return {'request': req,
            'response': {'status': status, 'headers': resph or [],
                         'cookies': [], 'content': content,
                         'redirectURL': ''}}


def make_har():
    b = 'https://app.example.com:443'
    return {'log': {'version': '1.2', 'pages': [
        {'title': b + '/cb?code=OAUTHCODE'}], 'entries': [
        _entry('GET', b + '/', reqh=_h(sec_fetch_dest='document',
                                       authorization='Bearer BEARERVAL'),
               cookies=[{'name': '_abck', 'value': 'COOKIEVAL'}], text=HTML),
        _entry('GET', b + '/b64', reqh=_h(sec_fetch_dest='document'),
               text=base64.b64encode(
                   b'<script src="https://cdn.datadome.co/tags.js"></script>'
               ).decode(), enc='base64'),
        _entry('POST', b + '/api/auth', mime='application/json',
               text='{"access_token":"ATOKEN-SECRET","refresh_token":"RT-SECRET"}',
               pd={'mimeType': 'application/json',
                   'text': '{"u":"bob","p":"hunter2 \\"x\\" y"}'}),
        _entry('POST', b + '/api/v2/session', mime='application/json',
               text='{}', pd={'mimeType': 'application/json',
                              'text': '{"creds":{"username":"x","password":"y"}}'}),
        _entry('POST', b + '/upload', text='ok', pd={
            'mimeType': 'multipart/form-data; boundary=XX',
            'text': '--XX\r\nContent-Disposition: form-data; name="password"'
                    '\r\n\r\nMULTISECRET\r\n--XX--'}),
        _entry('GET', 'https://USERINFO:pw@app.example.com/cb?code=OAUTHCODE'
                      '&access_token=URLTOKEN', status=302,
               qs=[{'name': 'code', 'value': 'OAUTHCODE'}],
               reqh=_h(referer='https://idp.example.com/a?id_token=REFTOKEN',
                       x_access_token='HDRSECRET')
               + [{'name': ':path', 'value': '/cb?code=OAUTHCODE'}],
               resph=_h(location=b + '/home#access_token=FRAGTOKEN')),
        _entry('GET', b + '/api/data?sessionid=SESSQ', mime='application/json',
               reqh=_h(sec_fetch_dest='empty'), text='{"ok":1}'),
        _entry('PATCH', b + '/api/profile', mime='application/json', text='{}',
               pd={'mimeType': 'application/json',
                   'text': '{"email":"a@b.example"}'}),
        _entry('GET', 'https://cdn.example.net/img.png', mime='image/png',
               text='iVBORw0KGgo=', enc='base64'),
    ]}}


class SanitizeTest(unittest.TestCase):
    def setUp(self):
        self.har = make_har()
        self.har['log']['entries'][0]['_webSocketMessages'] = [
            {'type': 'send', 'data': 'WSSECRET'}]
        self.stats = ac.sanitize(self.har)
        self.dump = json.dumps(self.har)

    def test_no_secret_survives(self):
        leaked = [s for s in SECRETS if s in self.dump]
        self.assertEqual(leaked, [])

    def test_names_are_kept(self):
        for name in ('access_token', 'username', 'password', 'csrf',
                     'sessionid', '/static/app.js', '/login'):
            self.assertIn(name, self.dump)

    def test_binary_body_removed(self):
        img = self.har['log']['entries'][-1]['response']['content']
        self.assertTrue(img['text'].startswith('[BODY REMOVED'))

    def test_marker(self):
        self.assertTrue(self.har['log']['_sanitized'])


def _report(har, host=None):
    ac.sanitize(har)
    out = io.StringIO()
    ac.analyze(har, host, out)
    return out.getvalue()


def _section(report, title):
    """Lines of one block of the recommended configuration."""
    block = report.split(title, 1)[1]
    return block.split('\n\n', 1)[0]


def webforms_har():
    """ASP.NET WebForms login: GET page, POST to itself, 302 to the portal,
    then DevExpress callbacks inside the portal."""
    b = 'https://portal.example.com/App'
    login = ('<form method="post" action="./Default.aspx" id="form1">'
             '<input type="hidden" name="__VIEWSTATE" value="VS">'
             '<input type="text" name="ctl00$Main$txtUser">'
             '<input type="password" name="ctl00$Main$_txtClave">'
             '<input type="submit" name="ctl00$Main$btnEntrar"></form>')
    nav = _h(sec_fetch_dest='document')
    xhr = _h(sec_fetch_dest='empty', referer=b + '/portal.aspx')
    form = 'application/x-www-form-urlencoded'
    return {'log': {'entries': [
        _entry('GET', b + '/default.aspx', status=302, reqh=nav,
               resph=_h(location='/App/Default.aspx')),
        _entry('GET', b + '/Default.aspx', reqh=nav, text=login),
        _entry('POST', b + '/Default.aspx', status=302, reqh=_h(
            sec_fetch_dest='document', referer=b + '/Default.aspx'),
            resph=_h(location='/App/portal.aspx'), pd={'mimeType': form,
            'params': [{'name': '__VIEWSTATE', 'value': 'VS'},
                       {'name': 'ctl00%24Main%24txtUser', 'value': 'bob'},
                       {'name': 'ctl00%24Main%24_txtClave', 'value': 'x'}]}),
        _entry('GET', b + '/portal.aspx', reqh=nav,
               text='<form action="./portal.aspx"></form>'),
        _entry('POST', b + '/portal.aspx', reqh=xhr, mime='text/plain',
               pd={'mimeType': form, 'params': [
                   {'name': '__CALLBACKID', 'value': 'grid'},
                   {'name': 'ctl00%24Nav%24CodigoUsuario', 'value': '1'}]}),
    ]}}


def spa_har():
    """SPA: one document, client-side /login route, JSON login via fetch."""
    b = 'https://spa.example.com'
    return {'log': {'entries': [
        _entry('GET', b + '/app/', reqh=_h(sec_fetch_dest='document'),
               text='<script src="/app/main.js"></script><div id="root">'),
        _entry('GET', b + '/app/main.js', mime='application/javascript',
               reqh=_h(sec_fetch_dest='script'), text='render()'),
        _entry('POST', b + '/api/v2/session', mime='application/json',
               text='{"token":"T"}', reqh=_h(sec_fetch_dest='empty',
                                             referer=b + '/app/login'),
               pd={'mimeType': 'application/json',
                   'text': '{"creds":{"email":"a","password":"b"}}'}),
        _entry('POST', b + '/api/telemetry', mime='application/json',
               reqh=_h(sec_fetch_dest='empty'), text='{}',
               pd={'mimeType': 'application/json', 'text': '{"ev":"x"}'}),
    ]}}


class WebFormsTest(unittest.TestCase):
    def setUp(self):
        self.report = _report(webforms_har())
        self.inj = _section(self.report, 'INJECTED URIs')
        self.val = _section(self.report, 'VALIDATED URIs')

    def test_injected_is_login_page_only(self):
        self.assertIn('/App/Default.aspx', self.inj)
        self.assertIn('_txtClave', self.inj)
        self.assertNotIn('portal.aspx', self.inj.split('also reached')[0])

    def test_validated_is_login_post(self):
        self.assertIn('/App/Default.aspx', self.val)
        self.assertIn('302 -> /App/portal.aspx', self.val)
        self.assertIn('WebForms', self.val)
        self.assertNotIn('\n  /App/portal.aspx', self.val)

    def test_callbacks_are_not_login(self):
        other = self.report.split('=== OTHER POST')[1]
        self.assertIn('POST /App/portal.aspx', other)
        self.assertIn('AJAX callback', other)

    def test_case_variant_and_redirect(self):
        self.assertIn('also reached via 302 redirect from /App/default.aspx',
                      self.inj)
        self.assertIn('case variants seen, add them too: /App/default.aspx',
                      self.inj)


class SpaTest(unittest.TestCase):
    def setUp(self):
        self.report = _report(spa_har())
        self.inj = _section(self.report, 'INJECTED URIs')
        self.val = _section(self.report, 'VALIDATED URIs')

    def test_injected_is_spa_document(self):
        self.assertIn('/app/\n', self.inj)
        self.assertIn('client-side route', self.inj)

    def test_validated_is_json_login(self):
        self.assertIn('/api/v2/session', self.val)
        self.assertIn('password', self.val)
        self.assertIn('XHR/fetch', self.val)
        self.assertNotIn('telemetry', self.val)


class NoLoginTest(unittest.TestCase):
    def test_warns_when_login_not_captured(self):
        har = {'log': {'entries': [
            _entry('GET', 'https://x.example.com/', text='<p>hi</p>',
                   reqh=_h(sec_fetch_dest='document'),
                   resph=_h(location='https://login.microsoftonline.com/'
                                     'common/oauth2/authorize?x=1'),
                   status=302),
            _entry('GET', 'https://x.example.com/home', text='<p>hi</p>',
                   reqh=_h(sec_fetch_dest='document'))]}}
        report = _report(har, 'x.example.com')
        self.assertIn('No login submission was found', report)
        self.assertIn('login.microsoftonline.com (SSO)', report)


class SensorTest(unittest.TestCase):
    def setUp(self):
        self.report = _report(make_har(), 'app.example.com')

    def test_host_without_port_matches(self):
        self.assertIn('[200] / ', self.report)

    def test_redirect_not_listed_as_document(self):
        docs = self.report.split('=== HTML DOCUMENTS')[1].split('===')[0]
        self.assertNotIn('/cb', docs)

    def test_json_login_detected(self):
        self.assertIn('/api/v2/session', _section(self.report,
                                                  'VALIDATED URIs'))

    def test_sensor_detection(self):
        self.assertIn('DataDome', self.report)       # base64 body
        self.assertIn('Akamai', self.report)         # cookie name
        self.assertIn('Cloudflare', self.report)     # inline loader
        self.assertNotIn('Check Point', self.report)  # data-src ignored
        self.assertIn('RESULT: an anti-bot sensor IS present', self.report)

    def test_report_has_no_secrets(self):
        self.assertEqual([s for s in SECRETS if s in self.report], [])


class CliTest(unittest.TestCase):
    def run_cli(self, har, *args):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'cap.har')
            p.write_text(json.dumps(har))
            r = subprocess.run([sys.executable, str(ROOT / 'antibot_check.py'),
                                str(p), *args], capture_output=True, text=True)
            return r, Path(d, 'cap.REPORT.txt').exists()

    def test_empty_capture(self):
        r, _ = self.run_cli({'log': {'entries': []}})
        self.assertEqual(r.returncode, 1)
        self.assertIn('no requests', r.stderr)

    def test_unknown_host(self):
        r, _ = self.run_cli(make_har(), '--host', 'nope.example.com')
        self.assertEqual(r.returncode, 1)
        self.assertIn('app.example.com', r.stderr)

    def test_ok(self):
        r, report = self.run_cli(make_har())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(report)


if __name__ == '__main__':
    unittest.main()
