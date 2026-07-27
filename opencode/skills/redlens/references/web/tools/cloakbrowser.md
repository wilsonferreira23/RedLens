# CloakBrowser (CloakHQ/CloakBrowser)

- **Category**: Web / CDN Bypass & Browser Automation
- **Risk Level**: 🟢 Low
- **Install**: `pip install cloakbrowser`

---

## Description

CloakBrowser is a stealth Chromium browser with 58 source-level C++ patches that bypass Cloudflare Turnstile, reCAPTCHA v3, FingerprintJS, BrowserScan, and 30+ bot detection services. It is a drop-in Playwright replacement — same API, same code, just swap the import.

**This is the ONLY browser automation tool that should be used in this skill.** Do not use Puppeteer, Playwright, or regular headless Chromium for CDN bypass or browser-dependent tasks.

## Installation

```bash
# Python (preferred — available in Kali containers)
pip install cloakbrowser
# Binary auto-downloads (~200MB) on first launch to ~/.cloakbrowser/

# JavaScript / Node.js
npm install cloakbrowser playwright-core
```

## Python API Reference

All functions from `cloakbrowser` mirror Playwright's sync API:

| Function / Method | Description |
|-------------------|-------------|
| `launch(headless=True)` | Launch stealth Chromium browser instance |
| `browser.new_page()` | Create a new page/tab |
| `page.goto(url, wait_until="networkidle", timeout=30000)` | Navigate to URL, wait for network idle |
| `page.content()` | Get full HTML content of current page |
| `page.title()` | Get page title |
| `page.url` | Get current URL |
| `page.fill(selector, text)` | Fill an input field |
| `page.click(selector)` | Click an element |
| `page.evaluate(js)` | Execute JavaScript in page context |
| `page.query_selector_all(selector)` | Get all matching elements |
| `page.eval_on_selector_all(selector, js)` | Evaluate JS on matched elements |
| `page.on("request", handler)` | Capture network requests |
| `page.on("response", handler)` | Capture network responses |
| `page.context.cookies()` | Get all browser cookies |
| `page.context.add_cookies(cookies)` | Set cookies for session reuse |
| `page.wait_for_timeout(ms)` | Wait for a fixed duration |
| `browser.close()` | Close browser instance |

## Common Workflows

### 1. CDN Bypass — Fetch Real Page Content

When `curl` returns a JS challenge page, use CloakBrowser to get the real content:

```python
import json, sys
from cloakbrowser import launch

url = sys.argv[1]
browser = launch(headless=True)
page = browser.new_page()
resp = page.goto(url, wait_until="networkidle", timeout=30000)

result = {
    "status": resp.status if resp else None,
    "headers": dict(resp.headers) if resp else {},
    "body": page.content(),
    "cookies": page.context.cookies()
}

with open("/tmp/cloak_output.json", "w") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

browser.close()
print(f"Status: {result['status']}, Body length: {len(result['body'])}")
```

### 2. Login Form Submission + Session Extraction

```python
from cloakbrowser import launch
browser = launch(headless=True)
page = browser.new_page()
page.goto("https://target.com/login", wait_until="networkidle")

page.fill("input#email", "user@test.com")
page.fill("input#password", "password123")
page.click("button[type=submit]")
page.wait_for_timeout(3000)

print(f"Logged in: {'/login' not in page.url}")
cookies = page.context.cookies()
with open("/tmp/cookies.json", "w") as f:
    json.dump(cookies, f, indent=2)
browser.close()
```

### 3. Capture API Calls from SPA

```python
from cloakbrowser import launch
browser = launch(headless=True)
page = browser.new_page()

api_calls = set()
page.on("request", lambda r: api_calls.add(f"{r.method} {r.url}"))
if r.post_data:
    api_calls.add(f"  Body: {r.post_data[:500]}")

page.goto("https://target.com/login", wait_until="networkidle")
for call in sorted(api_calls):
    print(call)
browser.close()
```

### 4. Cookie/Token Reuse with CLI Tools

After extracting cookies with CloakBrowser, pass them to CLI tools:

```bash
# Extract cookies to cookie-jar format
python3 -c "
import json
with open('/tmp/cookies.json') as f:
    cookies = json.load(f)
for c in cookies:
    print(f\"{c['name']}={c['value']}\")
" | paste -sd '; ' > /tmp/cookie_jar.txt

# Use with curl
curl -sk -H "Cookie: $(cat /tmp/cookie_jar.txt)" https://target.com/api/data

# Use with nuclei
nuclei -u https://target.com -H "Cookie: $(cat /tmp/cookie_jar.txt)"
```

## Important Notes

1. **Always use `headless=True`** unless explicitly debugging. Headless mode is undetectable with CloakBrowser.
2. **Script delivery**: write scripts on the host, use `docker cp script.py kali-pentest:/tmp/` to transfer.
3. **First run** auto-downloads ~200MB Chromium binary. Be patient.
4. **CloakBrowser does NOT solve CAPTCHAs** — it prevents them from appearing by passing all bot detection tests.
5. **Session persistence**: use `page.context.add_cookies()` to restore authenticated sessions across runs.
6. **Concurrent pages**: each `new_page()` creates a new tab in the same browser context (shared cookies).

---

## Official References

- [CloakHQ/CloakBrowser GitHub](https://github.com/CloakHQ/CloakBrowser)
- [CloakBrowser Documentation](https://cloakbrowser.dev/)
- [PyPI: cloakbrowser](https://pypi.org/project/cloakbrowser/)
