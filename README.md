# Anti-Bot HAR Check

A small, dependency-free tool to verify the **Anti-Bot configuration of your web application** (e.g. Check Point CloudGuard WAF) from a browser traffic capture (`.har` file).

It does two things:

1. **Sanitizes** your capture — removes cookies, authentication headers, tokens, passwords and any binary content, so the file is **safe to share** with your security team.
2. **Analyzes** the sanitized capture and produces a report with:
   - The HTML pages where the anti-bot JavaScript sensor should be injected (*Injected URIs*)
   - The endpoints that should be validated (*Validated URIs*), highlighting probable login forms
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

- **HTML DOCUMENTS (candidates for INJECTED URIs)** — full pages your browser navigated to. These are where the WAF should inject the JS sensor. `[!] empty body in HAR` means the browser didn't record that response body — re-capture with *Preserve log* enabled if sensor verification is needed on that page.
- **POST/PUT/DELETE (candidates for VALIDATED URIs)** — endpoints receiving user actions. Lines marked `** possible LOGIN **` are the typical targets of credential-stuffing bots and the priority for validation.
- **HTML FRAGMENTS via XHR** — partial content loaded by JavaScript. These should **not** be configured as Injected URIs.
- **REDIRECTS** — useful to spot lowercase/uppercase URL variants that need separate WAF entries.
- **SCRIPTS REFERENCED IN HTML (sensor detection)** — the final `RESULT` line tells you whether an anti-bot sensor is already being injected into your pages. Use this to verify the configuration *after* it has been applied: capture a new HAR, run the tool again, and the result should change to *sensor IS present*.

---

## What exactly gets sanitized?

- All **cookies** (request and response)
- **Authorization**, API-key and CSRF/session **headers**
- **Passwords, usernames, emails, tokens** and similar values in submitted forms and JSON bodies (field *names* are kept — they are needed for the analysis; field *values* are replaced with `[REDACTED]`)
- Sensitive **query-string parameters**
- All **binary response bodies** (images, fonts, downloads). HTML/JS/CSS/JSON responses are kept because they are required to detect the injected sensor.

The sanitized file is marked internally (`_sanitized: true`) so downstream tooling can verify it went through this process.

---

## Privacy

- The tool runs **100% locally**. It makes no network connections and sends nothing anywhere.
- It is a single readable Python file — you are welcome to review the code before running it.

## License

[MIT](./LICENSE)
