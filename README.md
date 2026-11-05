# Anti-Bot HAR Check

A small, dependency-free tool that reads a browser capture (`.har` file) of a **login** to your web application and prints the two lists the Check Point CloudGuard WAF [Anti-Bot practice](https://waf-doc.inext.checkpoint.com/additional-security-engines/anti-bot) needs:

- **Injected URIs**: the login/registration pages, loaded with GET.
- **Validated URIs**: the login/registration submissions, sent with POST.

Both are printed as relative URIs, without the domain, which is the format the practice expects. If the tool cannot recognize the login in the capture, it says why.

```
$ python3 antibot_check.py capture.har
Injected URIs:
  /account/login

Validated URIs:
  /account/login
  /api/auth/token
```

The tool runs **100% locally**. It makes no network connections and, unless you ask for a sanitized copy, writes no files.

---

## Requirements

- **Python 3.8 or newer**, nothing else. No `pip install`, no dependencies.
  - **Windows**: install from [python.org](https://www.python.org/downloads/) or the Microsoft Store (check *"Add Python to PATH"* during installation).
  - **macOS**: `python3` is usually preinstalled. If not: `brew install python3` or [python.org](https://www.python.org/downloads/).
  - **Linux**: preinstalled on nearly every distribution.

> On Windows, if `python3` is not recognized, use `python` or `py` instead throughout this guide.

---

## Step 1 — Capture the login

Record these three steps in a single capture:

1. **Open the login page.**
2. **Log in.**
3. **Land on the authenticated page.**

Start recording **before** opening the login page: the tool needs both the page load and the login submission. If the application has a registration form you want to protect, register a user in the same capture.

### Chrome / Edge / Brave

1. Open a new tab (ideally in an incognito/private window).
2. Press **F12** (or right-click → *Inspect*) and go to the **Network** tab.
3. Enable **Preserve log** (checkbox at the top). Without it, the login redirect erases the earlier requests.
4. Open the login page, log in and wait for the authenticated page to load.
5. Right-click anywhere on the request list → **"Save all as HAR with content"**.

### Firefox

1. Press **F12** → **Network** tab, click the gear icon and enable **Persist Logs**.
2. Open the login page, log in and wait for the authenticated page to load.
3. Right-click on the request list → **"Save All As HAR"**.

### Safari (macOS)

1. Enable the Develop menu: *Safari → Settings → Advanced → Show features for web developers*.
2. *Develop → Show Web Inspector* → **Network** tab, enable **Preserve Log**.
3. Open the login page, log in and wait for the authenticated page to load.
4. Click **Export** (top right) to save the `.har` file.

---

## Step 2 — Run the tool

Download [`antibot_check.py`](./antibot_check.py), place it next to your capture and run:

```bash
python3 antibot_check.py capture.har
```

Copy the URIs into the **Injected URIs** and **Validated URIs** tables of the Anti-Bot practice, then enforce the policy.

### When the login is not recognized

The tool prints `Could not identify the login:` followed by the reason, and exits with code 2:

| Reason | What to do |
|---|---|
| No request in the capture submits a password field | The login submission is missing. Capture again with *Preserve log* enabled and complete the login. |
| The login page itself (GET) is not in the capture | Recording started too late. Start recording before opening the login page. The Validated URIs are still printed. |

---

## How the URIs are identified

- **Validated URI**: a POST that sends a password field, as a form, JSON or multipart body. Password fields are recognized by the `<input type="password">` fields of the captured pages and by common names (`password`, `pwd`, `contraseña`, `senha`…). AJAX callbacks and other POSTs without a password are ignored.
- **Injected URI**: the page loaded with GET whose form posts to the Validated URI. If there is none, it is the page in the POST's `Referer`. For single-page apps, whose login runs on a client-side route, it is the page that loaded the app.

When the login involves more than one host, each URI is printed with its host.

---

## Optional — Share a sanitized copy

If someone else should look at the capture, add `--sanitize`:

```bash
python3 antibot_check.py capture.har --sanitize
```

The tool also writes `capture.SANITIZED.har`, which is safe to share. **Never share the original capture**: it contains session cookies and credentials.

The sanitized copy keeps only what the analysis needs (field names, paths and the structure of the forms), so it gives the same result. It removes:

- all cookies, and authorization, API-key, CSRF, session and other token headers;
- every query-string and URL-fragment value, in URLs, redirects and `Referer`/`Location`/`:path` headers;
- every value submitted in forms, JSON and multipart bodies;
- page text, scripts and hidden-field values from HTML responses, and every other response body;
- WebSocket messages and browser call stacks.

---

## Development

Run the tests (standard library only):

```bash
python3 -m unittest discover tests
```

## License

[MIT](./LICENSE)
