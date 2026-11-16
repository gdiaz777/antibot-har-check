"""
Record a HAR of the lab login flows with a real browser (Playwright).

    uv run --with playwright python lab/capture_har.py out.har [base_url]

Reads LAB_USER / LAB_PASSWORD from ~/.config/antibot-lab/credentials.
Runs: form login -> /home, SPA login via fetch, and a registration.
"""

import secrets
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def credentials():
    path = Path.home() / '.config/antibot-lab/credentials'
    return dict(line.split('=', 1) for line in path.read_text().split())


# Headless Chromium announces itself as "HeadlessChrome"; use a regular UA
USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36')


def form_login(page, base, creds):
    page.goto(base + '/login')
    page.fill('input[name=username]', creds['LAB_USER'])
    page.fill('input[name=password]', creds['LAB_PASSWORD'])
    page.click('button[type=submit]')
    page.wait_for_url('**/home', timeout=10000)
    page.goto(base + '/logout')


def spa_login(page, base, creds):
    page.goto(base + '/spa/')
    page.fill('#u', creds['LAB_USER'])
    page.fill('#p', creds['LAB_PASSWORD'])
    page.click('button[type=submit]')
    page.wait_for_selector('#out.ok', timeout=10000)


def register(page, base, creds):
    page.goto(base + '/register')
    password = secrets.token_urlsafe(12)
    page.fill('input[name=username]', 'user-' + secrets.token_hex(3))
    page.fill('input[name=email]', 'lab@example.com')
    page.fill('input[name=password]', password)
    page.fill('input[name=confirm_password]', password)
    page.click('button[type=submit]')
    page.wait_for_url('**/login', timeout=10000)


def main():
    out = sys.argv[1]
    base = sys.argv[2] if len(sys.argv) > 2 else \
        'https://test.gdiazcheckpoint.net'
    creds = credentials()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True,
                                  user_agent=USER_AGENT,
                                  record_har_path=out,
                                  record_har_content='embed')
        page = ctx.new_page()
        # A blocked flow must not stop the capture: the HAR is only written
        # when the context is closed, and blocked requests are the point
        for flow in (form_login, spa_login, register):
            try:
                flow(page, base, creds)
                print(f'{flow.__name__}: OK')
            except Exception as exc:  # noqa: BLE001
                print(f'{flow.__name__}: FAILED ({type(exc).__name__}: '
                      f'{str(exc).splitlines()[0]})')
        ctx.close()
        browser.close()
    print('HAR written to', out)


if __name__ == '__main__':
    main()
