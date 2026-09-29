import configparser
import contextlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib import parse as urllib_parse

import requests


ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"
DEFAULT_BROWSER_TIMEOUT_SECONDS = 600
WEBDRIVER_STATUS_TIMEOUT_SECONDS = 0.2
WEBDRIVER_COMMAND_TIMEOUT_SECONDS = 10
WEBDRIVER_QUIT_TIMEOUT_SECONDS = 1
WEBDRIVER_PROCESS_EXIT_TIMEOUT_SECONDS = 5
WEBDRIVER_PROCESS_GROUP_GRACE_SECONDS = 1
WEBDRIVER_FORCE_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
GOOGLE_ACCOUNT_CLICK_RETRY_SECONDS = 2
GOOGLE_ACCOUNT_CHOOSER_STALL_SECONDS = 15
GOOGLE_ACCOUNT_CHOOSER_RELOAD_LIMIT = 2
BROWSER_CAPTURE_MINIMUM_FREE_BYTES = 256 * 1024 * 1024
BROWSER_CAPTURE_TEMP_PREFIX = "aws-google-auth-firefox-"
BROWSER_CAPTURE_OWNER_FILE = "owner.pid"
BROWSER_CAPTURE_ORPHAN_AGE_SECONDS = 24 * 60 * 60
GOOGLE_ACCOUNT_CHOOSER_PATH_PATTERN = re.compile(
    r"^/(?:AccountChooser|v\d+/signin/accountchooser)/?$",
    re.IGNORECASE,
)
FIREFOX_AUTH_STORAGE_ORIGIN_PATTERN = re.compile(
    r"^https\+\+\+(?:accounts\.google\.com|"
    r"(?:[a-z0-9-]+\.)?signin\.aws(?:\.amazon\.com)?)(?:\^|$)",
    re.IGNORECASE,
)


class WebDriverError(RuntimeError):
    pass


@dataclass
class BrowserCaptureResult:
    saml_response: str
    account_aliases: dict = field(default_factory=dict)
    aws_roles: list = field(default_factory=list)


def browser_capture_temp_root_candidates():
    configured_root = os.environ.get("AWS_GOOGLE_AUTH_TMPDIR")
    default_root = tempfile.gettempdir()
    home_cache_root = Path.home() / ".cache" / "aws-google-auth" / "tmp"
    xdg_cache_root = Path(
        os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    ) / "aws-google-auth" / "tmp"
    candidates = []
    for candidate in (
        configured_root,
        default_root,
        str(home_cache_root),
        str(xdg_cache_root),
    ):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def select_browser_capture_temp_root():
    checked = []

    for candidate in browser_capture_temp_root_candidates():
        checked.append(candidate)
        path = Path(candidate).expanduser()
        try:
            path.mkdir(parents=True, exist_ok=True)
            free_bytes = shutil.disk_usage(path).free
        except OSError:
            continue
        if free_bytes >= BROWSER_CAPTURE_MINIMUM_FREE_BYTES:
            return str(path)

    raise RuntimeError(
        "Browser SAML capture needs at least {} MiB of free temporary space. "
        "Set AWS_GOOGLE_AUTH_TMPDIR to a writable filesystem. Checked: {}"
        .format(
            BROWSER_CAPTURE_MINIMUM_FREE_BYTES // (1024 * 1024),
            ", ".join(checked),
        )
    )


def process_is_running(process_id):
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def is_orphaned_capture_directory(path):
    try:
        owner_process_id = int((path / BROWSER_CAPTURE_OWNER_FILE).read_text())
    except (OSError, ValueError):
        owner_process_id = None

    # os.kill() cannot probe a process on Windows without terminating it.
    if owner_process_id is not None and owner_process_id > 0 and os.name == "posix":
        return not process_is_running(owner_process_id)

    try:
        age_seconds = time.time() - path.stat().st_mtime
    except OSError:
        return False
    return age_seconds >= BROWSER_CAPTURE_ORPHAN_AGE_SECONDS


# Profile copies hold Google session cookies, so remove any left behind by a
# capture that was killed before it could clean up.
def remove_orphaned_capture_directories(temp_roots=None):
    removed = 0
    for root in temp_roots or browser_capture_temp_root_candidates():
        try:
            entries = list(Path(root).expanduser().iterdir())
        except OSError:
            continue

        for entry in entries:
            if not entry.name.startswith(BROWSER_CAPTURE_TEMP_PREFIX):
                continue
            if entry.is_symlink() or not entry.is_dir():
                continue
            if is_orphaned_capture_directory(entry):
                shutil.rmtree(entry, ignore_errors=True)
                if not entry.exists():
                    removed += 1

    return removed


# SIGTERM and SIGHUP (closing the terminal) would otherwise skip the finally
# blocks that stop Firefox and delete its temporary profile.
@contextlib.contextmanager
def exit_cleanly_on_termination():
    def terminate(signal_number, frame):
        raise SystemExit(128 + signal_number)

    previous_handlers = {}
    for name in ("SIGTERM", "SIGHUP"):
        signal_number = getattr(signal, name, None)
        if signal_number is None:
            continue
        try:
            previous_handlers[signal_number] = signal.signal(signal_number, terminate)
        except ValueError:
            # Signal handlers can only be installed from the main thread.
            pass

    try:
        yield
    finally:
        for signal_number, handler in previous_handlers.items():
            signal.signal(signal_number, handler)


FIREFOX_EXECUTABLE_NAMES = ("firefox", "firefox-esr", "firefox-bin")
FIREFOX_EXECUTABLE_PATHS = (
    "/Applications/Firefox.app/Contents/MacOS/firefox",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
)


def find_firefox_executable():
    for name in FIREFOX_EXECUTABLE_NAMES:
        path = shutil.which(name)
        if path:
            return path

    for path in FIREFOX_EXECUTABLE_PATHS:
        if Path(path).is_file():
            return path

    return None


def firefox_profile_roots():
    home = Path.home()
    if sys.platform == "darwin":
        return [home / "Library" / "Application Support" / "Firefox"]
    if os.name == "nt":
        app_data = os.environ.get("APPDATA") or (home / "AppData" / "Roaming")
        return [Path(app_data) / "Mozilla" / "Firefox"]

    # Firefox keeps using ~/.mozilla when it exists and only falls back to
    # the XDG location for fresh installs.
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME") or (home / ".config")
    return [
        home / ".mozilla" / "firefox",
        Path(xdg_config_home) / "mozilla" / "firefox",
    ]


def read_firefox_ini(path):
    parser = configparser.RawConfigParser(strict=False)
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        pass
    return parser


def default_firefox_profile_candidates(root):
    installs = read_firefox_ini(root / "installs.ini")
    profiles = read_firefox_ini(root / "profiles.ini")
    candidates = []

    # Since Firefox 67 each installation records the profile it opens by
    # default; profiles.ini may carry the same data as [Install<hash>].
    for section in installs.sections():
        candidates.append((installs.get(section, "Default", fallback=None), True))
    for section in profiles.sections():
        if section.startswith("Install"):
            candidates.append((profiles.get(section, "Default", fallback=None), True))

    profile_sections = [
        section for section in profiles.sections() if section.startswith("Profile")
    ]
    for section in profile_sections:
        if profiles.get(section, "Default", fallback=None) == "1":
            candidates.append((
                profiles.get(section, "Path", fallback=None),
                profiles.get(section, "IsRelative", fallback="1") == "1",
            ))
    for name in ("default-release", "default"):
        for section in profile_sections:
            if profiles.get(section, "Name", fallback=None) == name:
                candidates.append((
                    profiles.get(section, "Path", fallback=None),
                    profiles.get(section, "IsRelative", fallback="1") == "1",
                ))

    for path, is_relative in candidates:
        if path:
            yield root / path if is_relative else Path(path)


def find_default_firefox_profile(roots=None):
    for root in roots or firefox_profile_roots():
        for candidate in default_firefox_profile_candidates(Path(root)):
            if candidate.is_dir():
                return str(candidate)

    return None


FIREFOX_PROFILE_CLONE_FILES = {
    "cert9.db",
    "containers.json",
    "content-prefs.sqlite",
    "cookies.sqlite",
    "extension-preferences.json",
    "handlers.json",
    "key4.db",
    "logins.json",
    "permissions.sqlite",
    "pkcs11.txt",
    "prefs.js",
    "storage.sqlite",
    "webappsstore.sqlite",
}

FIREFOX_PROFILE_SQLITE_SUFFIXES = ("-shm", "-wal")


def extract_saml_response_from_post_data(post_data):
    if not post_data or 'SAMLResponse' not in post_data:
        return None

    parsed = urllib_parse.parse_qs(post_data)
    if parsed.get('SAMLResponse'):
        return parsed['SAMLResponse'][0]

    return None


def build_firefox_capture_extension(output_path):
    manifest = {
        "manifest_version": 2,
        "name": "AWS Google Auth SAML Capture",
        "version": "1.0",
        "permissions": [
            "webRequest",
            "webRequestBlocking",
            "storage",
            "<all_urls>",
        ],
        "background": {
            "scripts": ["background.js"],
        },
        "content_scripts": [
            {
                "matches": ["https://signin.aws.amazon.com/*"],
                "js": ["aws_roles.js"],
                "run_at": "document_idle",
            },
        ],
    }

    background_js = """
let fallbackCaptureTabs = {};

function parseFormEncoded(text) {
  const values = new URLSearchParams(text);
  return values.get("SAMLResponse");
}

function decodeRawRequestBody(rawBody) {
  if (!rawBody || !rawBody.length) {
    return null;
  }

  const decoder = new TextDecoder("utf-8");
  let chunks = [];
  for (const item of rawBody) {
    if (item.bytes) {
      chunks.push(decoder.decode(item.bytes, {stream: true}));
    }
  }
  chunks.push(decoder.decode());
  return chunks.join("");
}

function extractSamlResponse(details) {
  if (!details.requestBody) {
    return null;
  }

  if (details.requestBody.formData && details.requestBody.formData.SAMLResponse) {
    const values = details.requestBody.formData.SAMLResponse;
    if (values && values.length) {
      return values[0];
    }
  }

  return parseFormEncoded(decodeRawRequestBody(details.requestBody.raw));
}

// WebDriver cannot read privileged extension pages, so the page URL carries
// the captured values back to the capture loop.
function openCapturedPage(tabId) {
  if (typeof tabId !== "number" || tabId < 0) {
    return;
  }

  browser.storage.local.get(["samlResponse", "awsRoles"]).then((data) => {
    const payload = JSON.stringify({
      samlResponse: data.samlResponse,
      awsRoles: data.awsRoles || []
    });
    browser.tabs.update(tabId, {
      url: browser.runtime.getURL("captured.html") + "#" + encodeURIComponent(payload)
    });
  });
}

function scheduleFallbackCapture(tabId) {
  if (typeof tabId !== "number" || tabId < 0 || fallbackCaptureTabs[tabId]) {
    return;
  }

  fallbackCaptureTabs[tabId] = setTimeout(() => {
    delete fallbackCaptureTabs[tabId];
    openCapturedPage(tabId);
  }, 15000);
}

browser.webRequest.onBeforeRequest.addListener(
  function(details) {
    const samlResponse = extractSamlResponse(details);
    if (!samlResponse) {
      return {};
    }

    browser.storage.local.set({
      samlResponse: samlResponse,
      capturedUrl: details.url
    });

    scheduleFallbackCapture(details.tabId);
    return {};
  },
  {urls: ["<all_urls>"]},
  ["blocking", "requestBody"]
);

browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || (message.type !== "awsRoles" && message.type !== "awsPageReady")) {
    return;
  }

  const tabId = sender.tab && sender.tab.id;
  browser.storage.local.get(["samlResponse"]).then((data) => {
    if (!data.samlResponse) {
      return;
    }

    if (typeof tabId === "number" && tabId >= 0 && fallbackCaptureTabs[tabId]) {
      clearTimeout(fallbackCaptureTabs[tabId]);
      delete fallbackCaptureTabs[tabId];
    }

    return browser.storage.local.set({
      awsRoles: message.roles || []
    }).then(() => openCapturedPage(tabId));
  });
});
"""

    aws_roles_js = """
function cleanLine(line) {
  return line.replace(/^[\\s▸▾▶▼]+/, "").trim();
}

function parseAwsRolePageText(text) {
  const ignored = new Set([
    "Select a role:",
    "Sign In",
    "English",
  ]);
  const roles = [];
  const seen = new Set();
  let accountName = null;
  let accountId = null;

  for (const rawLine of text.split(/\\n+/)) {
    const line = cleanLine(rawLine);
    if (!line) {
      continue;
    }

    const accountMatch = line.match(/^Account:\\s*(.*?)\\s*\\((\\d{12})\\)\\s*$/);
    if (accountMatch) {
      accountName = accountMatch[1].trim();
      accountId = accountMatch[2];
      continue;
    }

    if (!accountName || !accountId || ignored.has(line) || line.startsWith("Terms of Use")) {
      continue;
    }
    if (/^Privacy Policy|^Cookie Notice|^©|^Amazon Web Services/i.test(line)) {
      continue;
    }
    if (line.startsWith("Account:")) {
      continue;
    }

    const key = `${accountId}:${line}`;
    if (!seen.has(key)) {
      seen.add(key);
      roles.push({accountName, accountId, roleName: line});
    }
  }

  return roles;
}

function scrapeAndSendRoles() {
  const text = document.body ? document.body.innerText : "";
  const roles = parseAwsRolePageText(text);
  browser.runtime.sendMessage({
    type: roles.length ? "awsRoles" : "awsPageReady",
    roles
  });
  return true;
}

let attempts = 0;
const timer = setInterval(() => {
  attempts += 1;
  if (scrapeAndSendRoles() || attempts >= 80) {
    clearInterval(timer);
  }
}, 250);
scrapeAndSendRoles();
"""

    captured_html = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>AWS Google Auth SAML Captured</title>
  </head>
  <body>
    <h1>SAMLResponse captured</h1>
    <p>You can return to the terminal.</p>
    <pre id="aws-role-labels"></pre>
    <script src="captured.js"></script>
  </body>
</html>
"""

    captured_js = """
browser.storage.local.get(["awsRoles"]).then((data) => {
  const labels = (data.awsRoles || []).map(
    (role) => `${role.accountName} (${role.accountId}): ${role.roleName}`
  );
  document.getElementById("aws-role-labels").textContent = labels.join("\n");
});
"""

    with zipfile.ZipFile(output_path, 'w') as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("background.js", background_js)
        archive.writestr("aws_roles.js", aws_roles_js)
        archive.writestr("captured.html", captured_html)
        archive.writestr("captured.js", captured_js)


def captured_result_from_url(url):
    parsed_url = urllib_parse.urlsplit(url)
    if parsed_url.scheme != "moz-extension" or parsed_url.path != "/captured.html":
        return None

    try:
        payload = json.loads(urllib_parse.unquote(parsed_url.fragment))
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None

    saml_response = payload.get("samlResponse")
    if not isinstance(saml_response, str) or not saml_response:
        return None

    aws_roles = payload.get("awsRoles")
    if not isinstance(aws_roles, list):
        aws_roles = []
    return BrowserCaptureResult(
        saml_response=saml_response,
        account_aliases=account_aliases_from_browser_roles(aws_roles),
        aws_roles=aws_roles,
    )


def account_aliases_from_browser_roles(aws_roles):
    aliases = {}
    for role in aws_roles or []:
        if not isinstance(role, dict):
            continue

        account_id = str(role.get("accountId") or "").strip()
        account_name = str(role.get("accountName") or "").strip()
        if re.fullmatch(r"\d{12}", account_id) and account_name:
            aliases[account_id] = account_name

    return aliases


def css_string_literal(value):
    return '"{}"'.format(
        str(value).replace("\\", "\\\\").replace('"', '\\"')
    )


def xpath_string_literal(value):
    value = str(value)
    if "'" not in value:
        return "'{}'".format(value)
    if '"' not in value:
        return '"{}"'.format(value)

    parts = value.split("'")
    return "concat({})".format(
        ", \"'\", ".join("'{}'".format(part) for part in parts)
    )


def click_google_account_if_present(driver, google_username):
    if not google_username:
        return False

    username = str(google_username).strip()
    if not username:
        return False

    css_username = css_string_literal(username)
    for selector in (
        "[data-identifier={}]".format(css_username),
        "[data-email={}]".format(css_username),
    ):
        try:
            element_id = driver.find_element(selector)
            driver.click_element(element_id)
            return True
        except WebDriverError:
            pass

    xpath_username = xpath_string_literal(username)
    for xpath in (
        "//*[@data-identifier={}]".format(xpath_username),
        "//*[@data-email={}]".format(xpath_username),
        "//*[normalize-space()={}]/ancestor::*[@role='link' or @role='button'][1]".format(xpath_username),
        "//*[contains(normalize-space(), {})]/ancestor::*[@role='link' or @role='button'][1]".format(xpath_username),
    ):
        try:
            element_id = driver.find_element_by_xpath(xpath)
            driver.click_element(element_id)
            return True
        except WebDriverError:
            pass

    return False


def is_google_account_chooser_url(url):
    parsed_url = urllib_parse.urlsplit(url)
    return all(
        (
            parsed_url.scheme == "https",
            parsed_url.hostname == "accounts.google.com",
            GOOGLE_ACCOUNT_CHOOSER_PATH_PATTERN.fullmatch(parsed_url.path) is not None,
        )
    )


def clone_firefox_profile(source_path, target_path, progress=None):
    source = Path(source_path).expanduser()
    target = Path(target_path)

    if not source.is_dir():
        raise WebDriverError("Firefox profile does not exist: {}".format(source))

    target.mkdir(parents=True)
    copied_items = 0

    def report(message):
        if progress:
            progress(message)

    for source_item in source.iterdir():
        if not source_item.is_file():
            continue

        name = source_item.name
        is_profile_file = name in FIREFOX_PROFILE_CLONE_FILES
        is_sqlite_companion = any(
            name == "{}{}".format(file_name, suffix)
            for file_name in FIREFOX_PROFILE_CLONE_FILES
            for suffix in FIREFOX_PROFILE_SQLITE_SUFFIXES
        )
        if is_profile_file or is_sqlite_companion:
            shutil.copy2(source_item, target / name)
            copied_items += 1
            report("Copied Firefox profile item {}: {}".format(copied_items, name))

    copied_items += copy_firefox_site_storage(source, target, progress=progress)

    compatibility_ini = target / "compatibility.ini"
    if compatibility_ini.exists():
        compatibility_ini.unlink()

    user_js = target / "user.js"
    with user_js.open("a", encoding="utf-8") as prefs:
        prefs.write('\nuser_pref("browser.startup.page", 0);\n')
        prefs.write('user_pref("browser.sessionstore.resume_session_once", false);\n')
        prefs.write('user_pref("browser.sessionstore.resume_from_crash", false);\n')

    report("Firefox profile copy complete: {} item(s).".format(copied_items))
    return str(target)


def copy_firefox_site_storage(source, target, progress=None):
    source_storage = source / "storage"
    if not source_storage.exists():
        return 0

    copied_items = 0

    def report(message):
        if progress:
            progress(message)

    for storage_area in ("default", "permanent"):
        source_area = source_storage / storage_area
        if not source_area.is_dir():
            continue

        target_area = target / "storage" / storage_area
        for origin in source_area.iterdir():
            if origin.is_dir() and should_copy_firefox_storage_origin(origin.name):
                report("Copying Firefox site storage: {}".format(origin.name))
                shutil.copytree(origin, target_area / origin.name)
                copied_items += 1

    return copied_items


def should_copy_firefox_storage_origin(origin_name):
    return FIREFOX_AUTH_STORAGE_ORIGIN_PATTERN.match(origin_name) is not None


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def unwrap_webdriver_response(response):
    try:
        payload = response.json()
    except ValueError as ex:
        raise WebDriverError(response.text) from ex

    value = payload.get("value")
    if response.status_code >= 400:
        if isinstance(value, dict):
            message = value.get("message") or value.get("error") or str(value)
        else:
            message = str(value)
        raise WebDriverError(message)

    return value


class FirefoxWebDriver:
    def __init__(
        self,
        geckodriver_executable="geckodriver",
        request_timeout_seconds=DEFAULT_BROWSER_TIMEOUT_SECONDS,
        temp_directory=None,
    ):
        self.geckodriver_executable = geckodriver_executable
        self.request_timeout_seconds = request_timeout_seconds
        self.temp_directory = temp_directory
        self.port = find_free_port()
        self.base_url = "http://127.0.0.1:{}".format(self.port)
        self.process = None
        self.session_id = None
        self.request_deadline = None
        self.request_failed = False
        self.log_file = None
        self.process_group_id = None

    def start(self):
        self.log_file = tempfile.TemporaryFile(
            mode="w+t",
            encoding="utf-8",
            dir=self.temp_directory,
        )
        popen_kwargs = {
            "stdout": self.log_file,
            "stderr": subprocess.STDOUT,
            "text": True,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        self.process = subprocess.Popen(
            [self.geckodriver_executable, "--port", str(self.port), "--host", "127.0.0.1"],
            **popen_kwargs,
        )
        process_id = getattr(self.process, "pid", None)
        if os.name == "posix" and isinstance(process_id, int) and process_id > 0:
            self.process_group_id = process_id

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log_file.flush()
                self.log_file.seek(0)
                output = self.log_file.read()
                raise WebDriverError(output.strip() or "geckodriver exited before startup")

            try:
                response = requests.get(
                    self.base_url + "/status",
                    timeout=WEBDRIVER_STATUS_TIMEOUT_SECONDS,
                )
                if response.ok:
                    return
            except requests.RequestException:
                pass

            time.sleep(0.1)

        raise WebDriverError("Timed out waiting for geckodriver to start")

    def request(self, method, path, body=None, timeout_seconds=None):
        if timeout_seconds is None:
            timeout_seconds = self.request_timeout_seconds
        request_timeout_seconds = min(
            self.request_timeout_seconds,
            timeout_seconds,
        )
        if self.request_deadline is not None:
            remaining_seconds = self.request_deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise TimeoutError("Browser SAML capture deadline elapsed")
            request_timeout_seconds = min(
                request_timeout_seconds,
                remaining_seconds,
            )

        try:
            response = requests.request(
                method,
                self.base_url + path,
                json=body,
                timeout=request_timeout_seconds,
            )
        except requests.RequestException:
            self.request_failed = True
            raise
        return unwrap_webdriver_response(response)

    def create_session(self, firefox_executable=None, profile_path=None):
        args = ["-new-instance", "-foreground"]
        if profile_path:
            args.extend(["-profile", profile_path])

        firefox_options = {
            "args": args,
            "prefs": {
                "browser.shell.checkDefaultBrowser": False,
                "browser.startup.page": 0,
                "browser.sessionstore.resume_session_once": False,
                "browser.sessionstore.resume_from_crash": False,
            },
        }
        if firefox_executable:
            firefox_options["binary"] = firefox_executable

        value = self.request("POST", "/session", {
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "firefox",
                    "pageLoadStrategy": "none",
                    "moz:firefoxOptions": firefox_options,
                },
            },
        })
        self.session_id = value["sessionId"]

    def install_addon(self, path):
        self.request(
            "POST",
            "/session/{}/moz/addon/install".format(self.session_id),
            {"path": str(path), "temporary": True},
        )

    def set_window_rect(self, x=0, y=0, width=1280, height=900):
        self.request(
            "POST",
            "/session/{}/window/rect".format(self.session_id),
            {"x": x, "y": y, "width": width, "height": height},
        )

    def get(self, url):
        self.request("POST", "/session/{}/url".format(self.session_id), {"url": url})

    @property
    def current_url(self):
        return self.request("GET", "/session/{}/url".format(self.session_id))

    def find_element_by(self, using, value):
        value = self.request(
            "POST",
            "/session/{}/element".format(self.session_id),
            {"using": using, "value": value},
        )
        return value[ELEMENT_KEY]

    def find_element(self, css_selector):
        return self.find_element_by("css selector", css_selector)

    def find_element_by_xpath(self, xpath):
        return self.find_element_by("xpath", xpath)

    def click_element(self, element_id):
        return self.request(
            "POST",
            "/session/{}/element/{}/click".format(self.session_id, element_id),
            {},
        )

    def get_element_attribute(self, element_id, attribute_name):
        return self.request(
            "GET",
            "/session/{}/element/{}/attribute/{}".format(self.session_id, element_id, attribute_name),
        )

    def get_element_property(self, element_id, property_name):
        return self.request(
            "GET",
            "/session/{}/element/{}/property/{}".format(self.session_id, element_id, property_name),
        )

    def title(self):
        return self.request("GET", "/session/{}/title".format(self.session_id))

    def signal_process(self, signal_number, force=False):
        if self.process_group_id is not None and hasattr(os, "killpg"):
            try:
                os.killpg(self.process_group_id, signal_number)
                return
            except OSError:
                pass

        try:
            if force:
                self.process.kill()
            else:
                self.process.terminate()
        except OSError:
            pass

    def stop_process(self):
        if not self.process:
            return

        has_process_group = (
            self.process_group_id is not None and hasattr(os, "killpg")
        )
        self.signal_process(signal.SIGTERM)
        if has_process_group:
            # Keep the group leader unreaped until every child has had a bounded
            # chance to exit, then kill any survivor before the group ID can be
            # reused by an unrelated process.
            time.sleep(WEBDRIVER_PROCESS_GROUP_GRACE_SECONDS)
            self.signal_process(WEBDRIVER_FORCE_KILL_SIGNAL, force=True)
        try:
            self.process.wait(timeout=WEBDRIVER_PROCESS_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self.signal_process(WEBDRIVER_FORCE_KILL_SIGNAL, force=True)
            try:
                self.process.wait(timeout=WEBDRIVER_PROCESS_EXIT_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        self.process = None
        self.process_group_id = None

    def quit(self):
        self.request_deadline = None
        if self.session_id and not self.request_failed:
            try:
                self.request(
                    "DELETE",
                    "/session/{}".format(self.session_id),
                    timeout_seconds=WEBDRIVER_QUIT_TIMEOUT_SECONDS,
                )
            except (requests.RequestException, WebDriverError):
                pass
        self.session_id = None

        self.stop_process()

        if self.log_file:
            self.log_file.close()
            self.log_file = None


def capture_saml_response_with_firefox(
    login_url,
    timeout_seconds=DEFAULT_BROWSER_TIMEOUT_SECONDS,
    executable_path=None,
    profile_path=None,
    geckodriver_executable="geckodriver",
    google_username=None,
):
    removed = remove_orphaned_capture_directories()
    if removed:
        print(
            "Removed {} temporary Firefox profile(s) left by earlier captures.".format(
                removed,
            ),
            flush=True,
        )
    temp_root = select_browser_capture_temp_root()
    if Path(temp_root) != Path(tempfile.gettempdir()):
        print(
            "Default temporary filesystem lacks free space; using {}.".format(
                temp_root,
            ),
            flush=True,
        )
    driver = FirefoxWebDriver(
        geckodriver_executable=geckodriver_executable,
        request_timeout_seconds=min(
            timeout_seconds,
            WEBDRIVER_COMMAND_TIMEOUT_SECONDS,
        ),
        temp_directory=temp_root,
    )

    try:
        with exit_cleanly_on_termination(), tempfile.TemporaryDirectory(
            prefix=BROWSER_CAPTURE_TEMP_PREFIX,
            dir=temp_root,
            # A failed removal is retried by the next capture's sweep.
            ignore_cleanup_errors=True,
        ) as temp_dir:
            (Path(temp_dir) / BROWSER_CAPTURE_OWNER_FILE).write_text(str(os.getpid()))
            # Firefox must exit before its temporary profile is removed.
            try:
                extension_path = Path(temp_dir) / "aws_google_auth_saml_capture.xpi"
                build_firefox_capture_extension(extension_path)
                launch_profile_path = profile_path
                if profile_path:
                    print(
                        "Copying Firefox sign-in state into a temporary profile...",
                        flush=True,
                    )
                    launch_profile_path = clone_firefox_profile(
                        profile_path,
                        Path(temp_dir) / "profile",
                        progress=lambda message: print(message, flush=True),
                    )
                    print(
                        "Using a temporary copy of the Firefox profile for capture.",
                        flush=True,
                    )

                print("Starting geckodriver WebDriver service...", flush=True)
                driver.start()
                print("Creating Firefox WebDriver session...", flush=True)
                driver.create_session(
                    firefox_executable=executable_path,
                    profile_path=launch_profile_path,
                )
                print("Firefox WebDriver session started.", flush=True)
                driver.set_window_rect()
                driver.install_addon(extension_path)
                print("SAML capture extension installed.", flush=True)
                deadline = time.monotonic() + timeout_seconds
                driver.request_deadline = deadline
                driver.get(login_url)
                print("Google SSO page loaded in Firefox.", flush=True)

                next_status_at = 0
                last_url = None
                next_google_account_click_at = 0
                google_account_chooser_since = None
                google_account_click_requested = False
                google_account_chooser_reloads = 0
                while time.monotonic() < deadline:
                    current_url = driver.current_url
                    now = time.monotonic()
                    if current_url != last_url or now >= next_status_at:
                        try:
                            title = driver.title()
                        except WebDriverError:
                            title = ""
                        # The captured page's fragment holds the SAMLResponse.
                        page_url = urllib_parse.urldefrag(current_url).url
                        print("Waiting for SAMLResponse; current page: {} {}".format(title, page_url), flush=True)
                        last_url = current_url
                        next_status_at = now + 10

                    is_google_account_chooser = is_google_account_chooser_url(
                        current_url,
                    )
                    if is_google_account_chooser:
                        if google_account_chooser_since is None:
                            google_account_chooser_since = now
                    else:
                        google_account_chooser_since = None
                        google_account_click_requested = False

                    should_click_google_account = all(
                        (
                            google_username,
                            now >= next_google_account_click_at,
                            is_google_account_chooser,
                        )
                    )
                    if should_click_google_account:
                        clicked_google_account = click_google_account_if_present(
                            driver,
                            google_username,
                        )
                        next_google_account_click_at = (
                            now + GOOGLE_ACCOUNT_CLICK_RETRY_SECONDS
                        )
                        if clicked_google_account:
                            google_account_click_requested = True
                            print(
                                "Requested Google account selection: {}".format(
                                    google_username,
                                ),
                                flush=True,
                            )

                    chooser_wait_seconds = 0
                    if google_account_chooser_since is not None:
                        chooser_wait_seconds = now - google_account_chooser_since
                    chooser_is_stalled = all((
                        google_account_click_requested,
                        chooser_wait_seconds >= GOOGLE_ACCOUNT_CHOOSER_STALL_SECONDS,
                    ))
                    if chooser_is_stalled:
                        reload_limit = GOOGLE_ACCOUNT_CHOOSER_RELOAD_LIMIT
                        if google_account_chooser_reloads >= reload_limit:
                            raise WebDriverError(
                                "Google account chooser did not advance after "
                                "selecting {}. Close the capture window and retry."
                                .format(google_username)
                            )

                        google_account_chooser_reloads += 1
                        print(
                            "Google account chooser did not advance; reloading "
                            "the SSO page (attempt {}/{}).".format(
                                google_account_chooser_reloads,
                                GOOGLE_ACCOUNT_CHOOSER_RELOAD_LIMIT,
                            ),
                            flush=True,
                        )
                        driver.get(login_url)
                        google_account_chooser_since = now
                        google_account_click_requested = False
                        next_google_account_click_at = 0
                        time.sleep(0.25)
                        continue

                    captured_result = captured_result_from_url(current_url)
                    if captured_result:
                        return captured_result

                    time.sleep(0.25)

                raise TimeoutError(
                    "Timed out waiting for a browser SAMLResponse POST. "
                    "Complete Google sign-in in the Firefox window and continue to AWS."
                )
            finally:
                driver.quit()
    except (OSError, requests.RequestException, WebDriverError) as ex:
        raise RuntimeError(
            "Could not launch Firefox through geckodriver WebDriver. Ensure Firefox is installed "
            "and geckodriver is available on PATH. Details: {}".format(ex)
        ) from ex
