import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import antibot_check as ac  # noqa: E402


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


NAV = _h(sec_fetch_dest='document')
FORM = 'application/x-www-form-urlencoded'


def webforms_har():
    """ASP.NET WebForms login: self-redirect, GET page, POST to itself,
    302 to the portal, then DevExpress callbacks inside the portal."""
    b = 'https://portal.example.com:443/App'
    login = ('<form method="post" action="./Default.aspx" id="form1">'
             '<input type="hidden" name="__VIEWSTATE" value="VS">'
             '<input type="text" name="ctl00$Main$txtUser">'
             '<input type="password" name="ctl00$Main$_txtClave">'
             '<input type="submit" name="ctl00$Main$btnEntrar"></form>')
    return {'log': {'entries': [
        _entry('GET', b + '/Default.aspx', status=302, reqh=NAV,
               resph=_h(location='/App/Default.aspx')),
        _entry('GET', b + '/Default.aspx', reqh=NAV, text=login),
        _entry('GET', b + '/bundles/js?v=1', mime='text/javascript',
               reqh=_h(sec_fetch_dest='script'), text='x()'),
        _entry('POST', b + '/Default.aspx', status=302, reqh=_h(
            sec_fetch_dest='document', referer=b + '/Default.aspx'),
            resph=_h(location='/App/portal.aspx'), pd={'mimeType': FORM,
            'params': [{'name': '__VIEWSTATE', 'value': 'VS'},
                       {'name': 'ctl00%24Main%24txtUser', 'value': 'bob'},
                       {'name': 'ctl00%24Main%24_txtClave', 'value': 'x'}]}),
        _entry('GET', b + '/portal.aspx', reqh=NAV,
               text='<form action="./portal.aspx"></form>'),
        _entry('POST', b + '/portal.aspx', mime='text/plain',
               reqh=_h(sec_fetch_dest='empty',
                       referer=b + '/portal.aspx'),
               pd={'mimeType': FORM, 'params': [
                   {'name': '__CALLBACKID', 'value': 'grid'},
                   {'name': 'ctl00%24Nav%24CodigoUsuario', 'value': '1'}]}),
        _entry('POST', 'https://telemetry.example.net/e/',
               mime='application/json', reqh=_h(sec_fetch_dest='empty'),
               pd={'mimeType': 'application/json', 'text': '{"ev":"x"}'}),
    ]}}


def lab_har():
    """Form login, SPA login (fetch + JSON, client-side route) and a
    registration form, as captured from the lab application."""
    b = 'https://lab.example.com'
    login = ('<form method="post" action="/login"><input name="username">'
             '<input type="password" name="password"></form>')
    register = ('<form method="post" action="/register">'
                '<input name="username"><input type="email" name="email">'
                '<input type="password" name="password">'
                '<input type="password" name="confirm_password"></form>')
    spa = ('<form id="f"><input id="u"><input id="p" type="password">'
           '</form><script>fetch("/api/login")</script>')
    return {'log': {'entries': [
        _entry('GET', b + '/login', reqh=NAV, text=login),
        _entry('POST', b + '/login', status=302,
               reqh=_h(sec_fetch_dest='document', referer=b + '/login'),
               resph=_h(location='/home'), pd={'mimeType': FORM, 'params': [
                   {'name': 'username', 'value': 'demo'},
                   {'name': 'password', 'value': 'SECRET'}]}),
        _entry('GET', b + '/home', reqh=NAV, text='<p>Welcome</p>'),
        _entry('GET', b + '/spa/', reqh=NAV, text=spa),
        _entry('POST', b + '/api/login', mime='application/json',
               text='{"ok":true}',
               reqh=_h(sec_fetch_dest='empty', referer=b + '/spa/login'),
               pd={'mimeType': 'application/json',
                   'text': '{"username":"demo","password":"SECRET"}'}),
        _entry('GET', b + '/register', reqh=NAV, text=register),
        _entry('POST', b + '/register', status=302,
               reqh=_h(sec_fetch_dest='document', referer=b + '/register'),
               resph=_h(location='/login'), pd={
                   'mimeType': 'multipart/form-data; boundary=XX',
                   'text': '--XX\r\nContent-Disposition: form-data; '
                           'name="username"\r\n\r\nana\r\n--XX\r\n'
                           'Content-Disposition: form-data; '
                           'name="password"\r\n\r\nSECRET\r\n--XX--'}),
    ]}}


class FindUrisTest(unittest.TestCase):
    def test_webforms(self):
        inj, val, reason = ac.find_uris(webforms_har())
        self.assertIsNone(reason)
        self.assertEqual(inj, [('portal.example.com', '/App/Default.aspx')])
        self.assertEqual(val, [('portal.example.com', '/App/Default.aspx')])

    def test_form_spa_and_registration(self):
        inj, val, reason = ac.find_uris(lab_har())
        self.assertIsNone(reason)
        self.assertEqual([p for _, p in inj], ['/login', '/spa/', '/register'])
        self.assertEqual([p for _, p in val],
                         ['/login', '/api/login', '/register'])

    def test_base64_login_page(self):
        har = lab_har()
        content = har['log']['entries'][0]['response']['content']
        content['text'] = base64.b64encode(content['text'].encode()).decode()
        content['encoding'] = 'base64'
        inj, _, _ = ac.find_uris(har)
        self.assertIn(('lab.example.com', '/login'), inj)

    def test_no_login_submitted(self):
        har = lab_har()
        har['log']['entries'] = [e for e in har['log']['entries']
                                 if e['request']['method'] == 'GET']
        inj, val, reason = ac.find_uris(har)
        self.assertEqual((inj, val), ([], []))
        self.assertIn('no request in the capture submits a password', reason)

    def test_login_page_not_captured(self):
        har = webforms_har()
        del har['log']['entries'][:2]
        for h in har['log']['entries'][1]['request']['headers']:
            if h['name'] == 'referer':
                h['value'] = 'https://elsewhere.example.org/'
        inj, val, reason = ac.find_uris(har)
        self.assertEqual(inj, [])
        self.assertEqual(val, [('portal.example.com', '/App/Default.aspx')])
        self.assertIn('login page itself (GET) is not in the capture', reason)


class ReportTest(unittest.TestCase):
    def test_only_the_uris(self):
        out = ac.report(*ac.find_uris(webforms_har()))
        self.assertEqual(out, 'Injected URIs:\n  /App/Default.aspx\n\n'
                              'Validated URIs:\n  /App/Default.aspx')

    def test_host_shown_only_when_several(self):
        out = ac.report([('a.example.com', '/login')],
                        [('b.example.com', '/auth')], None)
        self.assertIn('a.example.com /login', out)
        self.assertIn('b.example.com /auth', out)


class SanitizeTest(unittest.TestCase):
    SECRETS = ['SECRET', 'OAUTHCODE', 'REFTOKEN', 'COOKIEVAL', 'BEARERVAL',
               'HDRSECRET', 'CSRFVAL', 'demo', 'ana', 'PATHTOKEN', 'Welcome']

    def har(self):
        har = lab_har()
        e = har['log']['entries']
        e[0]['response']['content']['text'] = e[0]['response']['content'][
            'text'].replace('<input name="username">',
                            '<input type="hidden" name="csrf" value="CSRFVAL">'
                            '<input name="username">')
        e[0]['request']['headers'] += _h(
            authorization='Bearer BEARERVAL', x_access_token='HDRSECRET',
            referer='https://idp.example.com/cb?code=OAUTHCODE&t=REFTOKEN')
        e[0]['request']['headers'].append(
            {'name': ':path', 'value': '/login?token=PATHTOKEN'})
        e[0]['request']['cookies'] = [{'name': 'sid', 'value': 'COOKIEVAL'}]
        return har

    def test_no_secret_survives(self):
        har = self.har()
        ac.sanitize(har)
        dump = json.dumps(har)
        self.assertEqual([s for s in self.SECRETS if s in dump], [])
        self.assertTrue(har['log']['_sanitized'])

    def test_sanitized_copy_gives_same_result(self):
        har = self.har()
        before = ac.find_uris(json.loads(json.dumps(har)))
        ac.sanitize(har)
        self.assertEqual(ac.find_uris(har), before)


class CliTest(unittest.TestCase):
    def run_cli(self, har, *args):
        d = tempfile.mkdtemp()
        p = Path(d, 'cap.har')
        p.write_text(json.dumps(har))
        r = subprocess.run([sys.executable, str(ROOT / 'antibot_check.py'),
                            str(p), *args], capture_output=True, text=True)
        return r, sorted(f.name for f in Path(d).iterdir())

    def test_found(self):
        r, files = self.run_cli(webforms_har())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ac.report(
            *ac.find_uris(webforms_har())))
        self.assertEqual(files, ['cap.har'])  # no files written by default

    def test_not_recognized(self):
        r, _ = self.run_cli({'log': {'entries': []}})
        self.assertEqual(r.returncode, 2)
        self.assertIn('Could not identify the login', r.stdout)

    def test_sanitize_option(self):
        r, files = self.run_cli(lab_har(), '--sanitize')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(files, ['cap.SANITIZED.har', 'cap.har'])

    def test_invalid_file(self):
        r, _ = self.run_cli({'not': 'a har'})
        self.assertEqual(r.returncode, 1)
        self.assertIn('not a valid HAR', r.stderr)


if __name__ == '__main__':
    unittest.main()
