import json
import re
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib import parse as urllib_parse

import requests


ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"


class WebDriverError(RuntimeError):
    pass


@dataclass
class BrowserCaptureResult:
    saml_response: str
    account_aliases: dict = field(default_factory=dict)
    aws_roles: list = field(default_factory=list)


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

function openCapturedPage(tabId) {
  if (typeof tabId !== "number" || tabId < 0) {
    return;
  }

  browser.tabs.update(tabId, {url: browser.runtime.getURL("captured.html")});
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
  if (!message || message.type !== "awsRoles") {
    return;
  }

  const tabId = sender.tab && sender.tab.id;
  if (typeof tabId === "number" && tabId >= 0 && fallbackCaptureTabs[tabId]) {
    clearTimeout(fallbackCaptureTabs[tabId]);
    delete fallbackCaptureTabs[tabId];
  }

  browser.storage.local.set({
    awsRoles: message.roles || []
  }).then(() => openCapturedPage(tabId));
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
  if (!text.includes("Select a role:") || !text.includes("Account:")) {
    return false;
  }

  const roles = parseAwsRolePageText(text);
  if (!roles.length) {
    return false;
  }

  browser.runtime.sendMessage({type: "awsRoles", roles});
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
    <textarea id="saml-response" style="width: 100%; height: 12rem;"></textarea>
    <pre id="aws-role-labels"></pre>
    <script src="captured.js"></script>
  </body>
</html>
"""

    captured_js = """
function render() {
  browser.storage.local.get(["samlResponse", "capturedUrl", "awsRoles"]).then((data) => {
    if (data.samlResponse) {
      document.getElementById("saml-response").value = data.samlResponse;
    }
    document.getElementById("aws-role-labels").textContent = JSON.stringify(data.awsRoles || []);
  });
}

render();
setInterval(render, 250);
"""

    with zipfile.ZipFile(output_path, 'w') as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("background.js", background_js)
        archive.writestr("aws_roles.js", aws_roles_js)
        archive.writestr("captured.html", captured_html)
        archive.writestr("captured.js", captured_js)


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
        if (
            name in FIREFOX_PROFILE_CLONE_FILES
            or any(
                name == "{}{}".format(file_name, suffix)
                for file_name in FIREFOX_PROFILE_CLONE_FILES
                for suffix in FIREFOX_PROFILE_SQLITE_SUFFIXES
            )
        ):
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
    normalized = origin_name.lower()
    return (
        "google" in normalized
        or "amazon" in normalized
        or "aws" in normalized
    )


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
    def __init__(self, geckodriver_executable="geckodriver"):
        self.geckodriver_executable = geckodriver_executable
        self.port = find_free_port()
        self.base_url = "http://127.0.0.1:{}".format(self.port)
        self.process = None
        self.session_id = None

    def start(self):
        self.process = subprocess.Popen(
            [self.geckodriver_executable, "--port", str(self.port), "--host", "127.0.0.1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                _, stderr = self.process.communicate()
                raise WebDriverError(stderr.strip() or "geckodriver exited before startup")

            try:
                response = requests.get(self.base_url + "/status", timeout=0.2)
                if response.ok:
                    return
            except requests.RequestException:
                pass

            time.sleep(0.1)

        raise WebDriverError("Timed out waiting for geckodriver to start")

    def request(self, method, path, body=None):
        response = requests.request(method, self.base_url + path, json=body, timeout=30)
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

    def quit(self):
        if self.session_id:
            try:
                self.request("DELETE", "/session/{}".format(self.session_id))
            except (requests.RequestException, WebDriverError):
                pass
            self.session_id = None

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None


def capture_saml_response_with_firefox(
    login_url,
    timeout_seconds=600,
    executable_path=None,
    profile_path=None,
    geckodriver_executable="geckodriver",
    google_username=None,
):
    driver = FirefoxWebDriver(geckodriver_executable=geckodriver_executable)

    try:
        with tempfile.TemporaryDirectory(prefix='aws-google-auth-firefox-') as temp_dir:
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
            driver.get(login_url)
            print("Google SSO page loaded in Firefox.", flush=True)

            deadline = time.monotonic() + timeout_seconds
            next_status_at = 0
            last_url = None
            clicked_google_account = False
            while time.monotonic() < deadline:
                current_url = driver.current_url
                now = time.monotonic()
                if current_url != last_url or now >= next_status_at:
                    try:
                        title = driver.title()
                    except WebDriverError:
                        title = ""
                    print("Waiting for SAMLResponse; current page: {} {}".format(title, current_url), flush=True)
                    last_url = current_url
                    next_status_at = now + 10

                if (
                    google_username
                    and not clicked_google_account
                    and "accounts.google.com" in current_url
                ):
                    clicked_google_account = click_google_account_if_present(
                        driver,
                        google_username,
                    )
                    if clicked_google_account:
                        print(
                            "Selected Google account: {}".format(google_username),
                            flush=True,
                        )

                if current_url.startswith("moz-extension://"):
                    try:
                        element_id = driver.find_element("#saml-response")
                        saml_response = driver.get_element_property(element_id, "value")
                        if not saml_response:
                            saml_response = driver.get_element_attribute(element_id, "value")
                    except WebDriverError:
                        saml_response = None

                    if saml_response:
                        aws_roles = []
                        try:
                            labels_element_id = driver.find_element("#aws-role-labels")
                            labels_json = driver.get_element_property(labels_element_id, "textContent")
                            if labels_json:
                                aws_roles = json.loads(labels_json)
                        except (TypeError, ValueError, WebDriverError):
                            aws_roles = []

                        return BrowserCaptureResult(
                            saml_response=saml_response,
                            account_aliases=account_aliases_from_browser_roles(aws_roles),
                            aws_roles=aws_roles,
                        )

                time.sleep(0.25)

            raise TimeoutError(
                "Timed out waiting for a browser SAMLResponse POST. "
                "Complete Google sign-in in the Firefox window and continue to AWS."
            )
    except (OSError, requests.RequestException, WebDriverError) as ex:
        raise RuntimeError(
            "Could not launch Firefox through geckodriver WebDriver. Ensure Firefox is installed "
            "and geckodriver is available on PATH. Details: {}".format(ex)
        ) from ex
    finally:
        driver.quit()
