# Anti-Bot HAR Check

A small, dependency-free tool that takes a browser capture (`.har` file) of a **login** to your web application and tells you which **Injected URIs** and **Validated URIs** to configure in the Check Point CloudGuard WAF **Anti-Bot** practice.

It does two things:

1. **Sanitizes** your capture — removes cookies, authentication headers, tokens, passwords and any binary content, so the file is **safe to share** with your security team.
2. **Analyzes** the sanitized capture and produces a report with:
   - The login/registration pages (GET) where the anti-bot JavaScript sensor must be injected (*Injected URIs*)
   - The login/registration submissions (POST) that must be validated (*Validated URIs*)
   - Whether an anti-bot sensor is **already present** in your pages

**Your original capture never leaves your machine.** You only share the sanitized copy and the report.

---

## Requirements

- **Python 3.8 or newer** — nothing else. No `pip install`, no dependencies.
  - **Windows**: install from [python.org](https://www.python.org/downloads/) or the Microsoft Store (check *"Add Python to PATH"* during installation).
  - **macOS**: `python3` is usually preinstalled. If not: `brew install python3` or [python.org](https://www.python.org/downloads/).
  - **Linux**: preinstalled on nearly every distribution.

Verify it works — open a terminal (Windows: *PowerShell*; macOS: *Terminal*) and run:

```
python3 --version
```

> On Windows, if `python3` is not recognized, use `python` or `py` instead throughout this guide.

---

## Step 1 — Capture the `.har` file

A HAR file is a recording of your browser's network traffic. Capture it while reproducing a **normal user journey** on the application (e.g. open the login page, log in, land on the home page).

### Chrome / Edge / Brave

1. Open the application **in a new tab** (ideally in an incognito/private window).
2. Press **F12** (or right-click → *Inspect*) to open Developer Tools.
3. Go to the **Network** tab.
4. Enable **Preserve log** (checkbox at the top) — important, otherwise redirects are lost.
5. Press **Ctrl+R** (Windows/Linux) or **Cmd+R** (macOS) to reload the page with recording active.
6. Perform the user journey: log in, navigate to the main page, submit the form you want to protect, etc.
7. Right-click anywhere on the request list → **"Save all as HAR with content"**.
8. Save the file, e.g. `capture.har`.

### Firefox

1. Open the application, press **F12** → **Network** tab.
2. Click the gear icon and enable **Persist Logs**.
3. Reload the page and perform the user journey.
4. Right-click on the request list → **"Save All As HAR"**.

### Safari (macOS)

1. Enable the Develop menu: *Safari → Settings → Advanced → Show features for web developers*.
2. *Develop → Show Web Inspector* → **Network** tab.
3. Enable **Preserve Log**, reload, perform the journey.
4. Click **Export** (top right) to save the `.har` file.

> **Tip:** the more complete the journey, the better the analysis. At minimum, capture the login page loading and the login submission.

---

## Step 2 — Run the check

Download [`antibot_check.py`](./antibot_check.py) (green **Code** button → *Download ZIP*, or download the raw file), place it in the same folder as your capture, then run:

**macOS / Linux:**

```bash
python3 antibot_check.py capture.har
```

**Windows (PowerShell):**

```powershell
python antibot_check.py capture.har
```

If your capture contains several domains and you want to analyze a specific one:

```bash
python3 antibot_check.py capture.har --host portal.example.com
```

---

## Step 3 — Review and share the results

The tool creates two files next to your capture:

| File | What it is | Share it? |
|---|---|---|
| `capture.SANITIZED.har` | Your capture with all sensitive data redacted | ✅ Yes |
| `capture.REPORT.txt` | Human-readable analysis report | ✅ Yes |
| `capture.har` | Your **original** capture (contains session cookies and credentials) | ❌ **Never** |

Send the **sanitized HAR** and the **report** to your security contact.

### How to read the report

The report starts with the **recommended Anti-Bot practice values**. They are relative URIs (no domain), which is the format the *Injected URIs* and *Validated URIs* tables expect:

- **INJECTED URIs**: the login/registration pages, loaded with GET. The WAF injects the JS sensor into these responses. The tool picks the page whose `<form>` posts to a Validated URI, the page that sent the login (`Referer`), or any page with a password field. For a SPA it picks the document that loads the app.
- **VALIDATED URIs**: the login/registration submissions, sent with POST. The WAF checks the sensor output on these requests. A POST counts as a login when it sends a password field (form, JSON or multipart). The evidence lines show which fields were found, whether it was a form submit or an XHR/fetch call, and the response (for example `302 -> /portal`).
- **NOTES**: warnings to act on. For example: the login was not captured, the login page GET is missing, credentials go to another host, or there is an SSO redirect to an external identity provider, which this WAF asset does not protect.

Each Injected URI also lists any **case variants** and **redirects** that lead to it (for example `/app/default.aspx` → `/app/Default.aspx`). Add those variants as well.

The **DETAILS** section has the rest:

- **HTML DOCUMENTS**: every page that was navigated to.
- **OTHER POST…**: endpoints that are not a login, such as AJAX callbacks and telemetry. They are normally *not* Validated URIs.
- **REDIRECTS**: the redirects seen in the capture.
- **ANTI-BOT SENSOR DETECTION**: script URLs, inline loaders and vendor cookies of known bot-management sensors. The final `RESULT` line tells you whether a sensor is already present. To verify a configuration once it has been applied, capture a new HAR and run the tool again.

Use `--verbose` to also list every script, every posted field name and the XHR GET calls.

## What exactly gets sanitized?

Field and parameter **names** are kept (they are needed for the analysis); **values** are replaced with `[REDACTED]`.

- All **cookies** (request and response)
- **Authorization**, API-key, CSRF/session and any other token/auth/secret **headers**
- **Every query-string and URL-fragment value**, in request URLs, redirects, `Location` and `Referer` headers (e.g. OAuth `code`, `access_token`)
- **Every value** in submitted forms, JSON bodies and multipart uploads (file names included)
- **JSON responses**: keys kept, all values redacted (login responses often contain tokens)
- **HTML responses**: reduced to a skeleton — `<script>` tags, `<form>` tags and input names. Page text, hidden-field values (CSRF, `__VIEWSTATE`) and string literals in inline scripts (except URLs/paths) are removed
- All **binary and other response bodies** (images, fonts, downloads, XML, text). JS/CSS responses are kept because they are required to detect the injected sensor
- WebSocket message contents and browser call stacks (`_initiator`)

The sanitized file is marked internally (`_sanitized: true`) so downstream tooling can verify it went through this process.

---

## Development

Run the tests (standard library only):

```bash
python3 -m unittest discover tests
```

## Privacy

- The tool runs **100% locally**. It makes no network connections and sends nothing anywhere.
- It is a single readable Python file — you are welcome to review the code before running it.

## License

[MIT](./LICENSE)
