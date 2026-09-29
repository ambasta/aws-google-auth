import json
import signal
import subprocess
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import ANY, Mock, PropertyMock, call, patch
from urllib.parse import quote

from aws_google_auth import browser_capture


def captured_url(saml_response, aws_roles=()):
    payload = json.dumps({"samlResponse": saml_response, "awsRoles": list(aws_roles)})
    return "moz-extension://capture/captured.html#" + quote(payload)


class TestBrowserCapture(unittest.TestCase):

    @patch('aws_google_auth.browser_capture.shutil.disk_usage', spec=True)
    @patch('aws_google_auth.browser_capture.tempfile.gettempdir', spec=True)
    def test_browser_capture_temp_root_falls_back_when_default_is_full(
        self,
        mock_gettempdir,
        mock_disk_usage,
    ):
        mock_gettempdir.return_value = "/tmp"
        mock_disk_usage.side_effect = [
            Mock(free=0),
            Mock(free=browser_capture.BROWSER_CAPTURE_MINIMUM_FREE_BYTES),
        ]

        with patch.dict(
            browser_capture.os.environ,
            {"AWS_GOOGLE_AUTH_TMPDIR": ""},
        ):
            selected = browser_capture.select_browser_capture_temp_root()

        self.assertEqual(
            str(Path.home() / ".cache" / "aws-google-auth" / "tmp"),
            selected,
        )

    def make_firefox_root(self, installs=None, profiles=None, profile_dirs=()):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        if installs is not None:
            (root / "installs.ini").write_text(installs)
        if profiles is not None:
            (root / "profiles.ini").write_text(profiles)
        for profile_dir in profile_dirs:
            (root / profile_dir).mkdir()
        return root

    def test_default_firefox_profile_uses_install_default(self):
        root = self.make_firefox_root(
            installs="[11457493C5A56847]\nDefault=new.default-release\nLocked=1\n",
            profiles=(
                "[Profile0]\nName=old\nIsRelative=1\nPath=old.default\nDefault=1\n"
                "[Profile1]\nName=default-release\nIsRelative=1\nPath=new.default-release\n"
            ),
            profile_dirs=("old.default", "new.default-release"),
        )

        self.assertEqual(
            str(root / "new.default-release"),
            browser_capture.find_default_firefox_profile([root]),
        )

    def test_default_firefox_profile_falls_back_to_profiles_ini(self):
        root = self.make_firefox_root(
            installs="[11457493C5A56847]\nDefault=missing.default-release\n",
            profiles=(
                "[General]\nStartWithLastProfile=1\n"
                "[Profile0]\nName=work\nIsRelative=1\nPath=work.profile\nDefault=1\n"
            ),
            profile_dirs=("work.profile",),
        )

        self.assertEqual(
            str(root / "work.profile"),
            browser_capture.find_default_firefox_profile([root]),
        )

    def test_default_firefox_profile_checks_each_root(self):
        empty_root = self.make_firefox_root()
        xdg_root = self.make_firefox_root(
            profiles="[Profile0]\nName=default-release\nIsRelative=1\nPath=x.default-release\n",
            profile_dirs=("x.default-release",),
        )

        self.assertEqual(
            str(xdg_root / "x.default-release"),
            browser_capture.find_default_firefox_profile([empty_root, xdg_root]),
        )
        self.assertIsNone(browser_capture.find_default_firefox_profile([empty_root]))

    @patch('aws_google_auth.browser_capture.shutil.which', spec=True)
    def test_find_firefox_executable_searches_path(self, mock_which):
        mock_which.side_effect = lambda name: "/usr/bin/firefox-esr" if name == "firefox-esr" else None

        self.assertEqual("/usr/bin/firefox-esr", browser_capture.find_firefox_executable())

    def test_firefox_webdriver_defaults_to_browser_capture_timeout(self):
        driver = browser_capture.FirefoxWebDriver()

        self.assertEqual(
            browser_capture.DEFAULT_BROWSER_TIMEOUT_SECONDS,
            driver.request_timeout_seconds,
        )

    def test_firefox_webdriver_uses_non_blocking_page_load_strategy(self):
        driver = browser_capture.FirefoxWebDriver()
        driver.request = Mock(return_value={"sessionId": "session-id"})

        driver.create_session()

        driver.request.assert_called_once_with(
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "firefox",
                        "pageLoadStrategy": "none",
                        "moz:firefoxOptions": {
                            "args": ["-new-instance", "-foreground"],
                            "prefs": {
                                "browser.shell.checkDefaultBrowser": False,
                                "browser.startup.page": 0,
                                "browser.sessionstore.resume_session_once": False,
                                "browser.sessionstore.resume_from_crash": False,
                            },
                        },
                    },
                },
            },
        )

    @patch('aws_google_auth.browser_capture.requests.request', spec=True)
    def test_firefox_webdriver_uses_configured_timeout_for_commands(
        self,
        mock_request,
    ):
        session_response = Mock(status_code=200)
        session_response.json.return_value = {
            "value": {"sessionId": "session-id"},
        }
        navigation_response = Mock(status_code=200)
        navigation_response.json.return_value = {"value": None}
        mock_request.side_effect = [session_response, navigation_response]
        driver = browser_capture.FirefoxWebDriver(request_timeout_seconds=120)

        driver.create_session()
        driver.get("https://accounts.google.com/")

        self.assertEqual(
            [
                call(
                    "POST",
                    driver.base_url + "/session",
                    json=ANY,
                    timeout=120,
                ),
                call(
                    "POST",
                    driver.base_url + "/session/session-id/url",
                    json={"url": "https://accounts.google.com/"},
                    timeout=120,
                ),
            ],
            mock_request.mock_calls,
        )

    @patch('aws_google_auth.browser_capture.requests.request', spec=True)
    def test_firefox_webdriver_limits_command_to_capture_deadline(
        self,
        mock_request,
    ):
        response = Mock(status_code=200)
        response.json.return_value = {"value": None}
        mock_request.return_value = response
        driver = browser_capture.FirefoxWebDriver(request_timeout_seconds=120)
        driver.request_deadline = 100

        with patch(
            'aws_google_auth.browser_capture.time.monotonic',
            return_value=95,
        ):
            driver.get("https://accounts.google.com/")

        mock_request.assert_called_once_with(
            "POST",
            driver.base_url + "/session/None/url",
            json={"url": "https://accounts.google.com/"},
            timeout=5,
        )

    @patch('aws_google_auth.browser_capture.requests.request', spec=True)
    def test_firefox_webdriver_rejects_command_after_capture_deadline(
        self,
        mock_request,
    ):
        driver = browser_capture.FirefoxWebDriver(request_timeout_seconds=120)
        driver.request_deadline = 100

        with (
            patch(
                'aws_google_auth.browser_capture.time.monotonic',
                return_value=101,
            ),
            self.assertRaisesRegex(TimeoutError, "capture deadline elapsed"),
        ):
            driver.get("https://accounts.google.com/")

        mock_request.assert_not_called()

    @patch('aws_google_auth.browser_capture.subprocess.Popen', spec=True)
    @patch('aws_google_auth.browser_capture.requests.get', spec=True)
    def test_firefox_webdriver_keeps_status_poll_timeout_short(
        self,
        mock_get,
        mock_popen,
    ):
        mock_popen.return_value.poll.return_value = None
        mock_get.return_value.ok = True
        driver = browser_capture.FirefoxWebDriver(request_timeout_seconds=120)

        driver.start()

        mock_get.assert_called_once_with(
            driver.base_url + "/status",
            timeout=browser_capture.WEBDRIVER_STATUS_TIMEOUT_SECONDS,
        )
        popen_kwargs = mock_popen.call_args.kwargs
        self.assertIsNot(subprocess.PIPE, popen_kwargs["stdout"])
        self.assertEqual(subprocess.STDOUT, popen_kwargs["stderr"])
        if browser_capture.os.name == "posix":
            self.assertTrue(popen_kwargs["start_new_session"])
        else:
            self.assertNotIn("start_new_session", popen_kwargs)
        driver.quit()

    def test_firefox_webdriver_skips_session_delete_after_failed_request(self):
        driver = browser_capture.FirefoxWebDriver()
        driver.session_id = "session-id"
        driver.request_failed = True
        driver.request = Mock()
        process = Mock()
        driver.process = process

        driver.quit()

        driver.request.assert_not_called()
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(
            timeout=browser_capture.WEBDRIVER_PROCESS_EXIT_TIMEOUT_SECONDS,
        )

    @patch('aws_google_auth.browser_capture.time.sleep', spec=True)
    @patch('aws_google_auth.browser_capture.os.killpg', spec=True)
    def test_firefox_webdriver_finally_kills_group_after_parent_exits(
        self,
        mock_killpg,
        mock_sleep,
    ):
        driver = browser_capture.FirefoxWebDriver()
        process = Mock()
        driver.process = process
        driver.process_group_id = 4321

        driver.quit()

        self.assertEqual(
            [
                call(4321, signal.SIGTERM),
                call(4321, browser_capture.WEBDRIVER_FORCE_KILL_SIGNAL),
            ],
            mock_killpg.mock_calls,
        )
        mock_sleep.assert_called_once_with(
            browser_capture.WEBDRIVER_PROCESS_GROUP_GRACE_SECONDS,
        )
        process.wait.assert_called_once_with(
            timeout=browser_capture.WEBDRIVER_PROCESS_EXIT_TIMEOUT_SECONDS,
        )

    def test_firefox_webdriver_kills_and_reaps_without_process_group(self):
        driver = browser_capture.FirefoxWebDriver()
        process = Mock()
        driver.process = process
        process.wait.side_effect = [
            subprocess.TimeoutExpired("geckodriver", 5),
            0,
        ]

        driver.quit()

        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(
            [
                call(timeout=browser_capture.WEBDRIVER_PROCESS_EXIT_TIMEOUT_SECONDS),
                call(timeout=browser_capture.WEBDRIVER_PROCESS_EXIT_TIMEOUT_SECONDS),
            ],
            process.wait.mock_calls,
        )

    def test_extract_saml_response_from_post_data(self):
        self.assertEqual(
            "YWJjZA==",
            browser_capture.extract_saml_response_from_post_data("RelayState=foo&SAMLResponse=YWJjZA%3D%3D"),
        )

    def test_extract_saml_response_from_post_data_without_saml(self):
        self.assertIsNone(browser_capture.extract_saml_response_from_post_data("RelayState=foo"))
        self.assertIsNone(browser_capture.extract_saml_response_from_post_data(None))

    def test_account_aliases_from_browser_roles(self):
        self.assertEqual(
            {
                "111111111111": "example-prod",
                "222222222222": "example-dev",
            },
            browser_capture.account_aliases_from_browser_roles([
                {"accountName": "example-prod", "accountId": "111111111111", "roleName": "Admin"},
                {"accountName": "example-dev", "accountId": "222222222222", "roleName": "PowerUser"},
                {"accountName": "bad", "accountId": "not-an-id", "roleName": "ignored"},
                "ignored",
            ]),
        )

    def test_click_google_account_if_present_clicks_data_identifier(self):
        driver = Mock()
        driver.find_element.return_value = "account-element"

        self.assertTrue(
            browser_capture.click_google_account_if_present(
                driver,
                "user@example.com",
            )
        )

        driver.find_element.assert_called_once_with(
            '[data-identifier="user@example.com"]',
        )
        driver.click_element.assert_called_once_with("account-element")

    def test_click_google_account_if_present_uses_text_fallback(self):
        driver = Mock()
        driver.find_element.side_effect = browser_capture.WebDriverError("missing")
        driver.find_element_by_xpath.return_value = "account-element"

        self.assertTrue(
            browser_capture.click_google_account_if_present(
                driver,
                "user@example.com",
            )
        )

        self.assertTrue(driver.find_element_by_xpath.called)
        driver.click_element.assert_called_once_with("account-element")

    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    @patch('aws_google_auth.browser_capture.build_firefox_capture_extension', spec=True)
    def test_capture_retries_account_click_only_while_on_account_chooser(
        self,
        mock_build_extension,
        mock_webdriver,
    ):
        chooser_url = (
            "https://accounts.google.com/v3/signin/accountchooser?continue=aws"
        )
        driver = Mock()
        current_url = PropertyMock(side_effect=[
            chooser_url,
            chooser_url,
            chooser_url,
            "https://accounts.google.com/v3/signin/challenge/pwd?continue=aws",
            captured_url("YWJjZA=="),
        ])
        type(driver).current_url = current_url
        mock_webdriver.return_value = driver

        clock_values = [index * 0.5 for index in range(11)]
        with (
            patch(
                'aws_google_auth.browser_capture.time.monotonic',
                side_effect=clock_values,
            ),
            patch('aws_google_auth.browser_capture.time.sleep', spec=True),
            patch(
                'aws_google_auth.browser_capture.click_google_account_if_present',
                return_value=True,
            ) as mock_click_google_account,
        ):
            result = browser_capture.capture_saml_response_with_firefox(
                "https://accounts.google.com/o/saml2/initsso",
                timeout_seconds=120,
                google_username="user@example.com",
            )

        self.assertEqual("YWJjZA==", result.saml_response)
        self.assertEqual(
            [
                call(driver, "user@example.com"),
                call(driver, "user@example.com"),
            ],
            mock_click_google_account.mock_calls,
        )
        self.assertEqual(5, current_url.call_count)

    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    @patch('aws_google_auth.browser_capture.build_firefox_capture_extension', spec=True)
    def test_capture_reloads_a_stalled_account_chooser(
        self,
        mock_build_extension,
        mock_webdriver,
    ):
        login_url = "https://accounts.google.com/o/saml2/initsso"
        chooser_url = (
            "https://accounts.google.com/v3/signin/accountchooser?continue=aws"
        )
        driver = Mock()
        current_url = PropertyMock(side_effect=[
            chooser_url,
            captured_url("YWJjZA=="),
        ])
        type(driver).current_url = current_url
        mock_webdriver.return_value = driver

        with (
            patch(
                'aws_google_auth.browser_capture.GOOGLE_ACCOUNT_CHOOSER_STALL_SECONDS',
                0,
            ),
            patch(
                'aws_google_auth.browser_capture.time.monotonic',
                return_value=0,
            ),
            patch('aws_google_auth.browser_capture.time.sleep', spec=True),
            patch(
                'aws_google_auth.browser_capture.click_google_account_if_present',
                return_value=True,
            ),
        ):
            result = browser_capture.capture_saml_response_with_firefox(
                login_url,
                timeout_seconds=120,
                google_username="user@example.com",
            )

        self.assertEqual("YWJjZA==", result.saml_response)
        self.assertEqual(
            [call(login_url), call(login_url)],
            driver.get.mock_calls,
        )

    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    @patch('aws_google_auth.browser_capture.build_firefox_capture_extension', spec=True)
    def test_capture_stops_after_stalled_account_chooser_retry_limit(
        self,
        mock_build_extension,
        mock_webdriver,
    ):
        login_url = "https://accounts.google.com/o/saml2/initsso"
        chooser_url = (
            "https://accounts.google.com/v3/signin/accountchooser?continue=aws"
        )
        driver = Mock()
        type(driver).current_url = PropertyMock(side_effect=[
            chooser_url,
            chooser_url,
            chooser_url,
        ])
        mock_webdriver.return_value = driver

        with (
            patch(
                'aws_google_auth.browser_capture.GOOGLE_ACCOUNT_CHOOSER_STALL_SECONDS',
                0,
            ),
            patch(
                'aws_google_auth.browser_capture.time.monotonic',
                return_value=0,
            ),
            patch('aws_google_auth.browser_capture.time.sleep', spec=True),
            patch(
                'aws_google_auth.browser_capture.click_google_account_if_present',
                return_value=True,
            ),
            self.assertRaisesRegex(RuntimeError, "did not advance"),
        ):
            browser_capture.capture_saml_response_with_firefox(
                login_url,
                timeout_seconds=120,
                google_username="user@example.com",
            )

        self.assertEqual(
            [call(login_url), call(login_url), call(login_url)],
            driver.get.mock_calls,
        )
        driver.quit.assert_called_once_with()

    def test_captured_result_from_url_reads_the_capture_page_fragment(self):
        result = browser_capture.captured_result_from_url(captured_url("YWJjZA==", [
            {"accountName": "example-prod", "accountId": "111111111111", "roleName": "Admin"},
        ]))

        self.assertEqual("YWJjZA==", result.saml_response)
        self.assertEqual({"111111111111": "example-prod"}, result.account_aliases)

    def test_captured_result_from_url_ignores_pages_without_a_capture(self):
        for url in (
            "https://signin.aws.amazon.com/saml",
            "https://example.com/captured.html#" + quote(json.dumps({"samlResponse": "YWJjZA=="})),
            "moz-extension://capture/captured.html",
            "moz-extension://capture/captured.html#not-json",
            "moz-extension://capture/captured.html#" + quote(json.dumps(["YWJjZA=="])),
            captured_url(""),
        ):
            with self.subTest(url=url):
                self.assertIsNone(browser_capture.captured_result_from_url(url))

    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    @patch('aws_google_auth.browser_capture.build_firefox_capture_extension', spec=True)
    def test_capture_progress_does_not_print_the_saml_response(
        self,
        mock_build_extension,
        mock_webdriver,
    ):
        driver = Mock()
        driver.current_url = captured_url("c2VjcmV0LWFzc2VydGlvbg==")
        driver.title.side_effect = browser_capture.WebDriverError("privileged scope")
        mock_webdriver.return_value = driver

        with patch('builtins.print') as mock_print:
            result = browser_capture.capture_saml_response_with_firefox(
                "https://accounts.google.com/o/saml2/initsso",
                timeout_seconds=120,
            )

        self.assertEqual("c2VjcmV0LWFzc2VydGlvbg==", result.saml_response)
        printed = " ".join(str(item) for entry in mock_print.call_args_list for item in entry.args)
        self.assertIn("moz-extension://capture/captured.html", printed)
        self.assertNotIn("c2VjcmV0LWFzc2VydGlvbg", printed)

    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    def test_capture_quits_firefox_before_removing_its_temporary_profile(
        self,
        mock_webdriver,
    ):
        driver = Mock()
        driver.current_url = captured_url("YWJjZA==")
        mock_webdriver.return_value = driver
        extension_paths = []
        profile_existed_at_quit = []
        driver.install_addon.side_effect = extension_paths.append
        driver.quit.side_effect = lambda: profile_existed_at_quit.append(
            extension_paths[0].parent.exists()
        )

        browser_capture.capture_saml_response_with_firefox(
            "https://accounts.google.com/o/saml2/initsso",
            timeout_seconds=120,
        )

        self.assertEqual([True], profile_existed_at_quit)
        self.assertFalse(extension_paths[0].parent.exists())

    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    @patch('aws_google_auth.browser_capture.build_firefox_capture_extension', spec=True)
    def test_capture_marks_its_temporary_directory_with_owner(
        self,
        mock_build_extension,
        mock_webdriver,
    ):
        driver = Mock()
        driver.current_url = captured_url("YWJjZA==")
        mock_webdriver.return_value = driver
        owners = []
        driver.install_addon.side_effect = lambda path: owners.append(
            (Path(path).parent / browser_capture.BROWSER_CAPTURE_OWNER_FILE).read_text()
        )

        browser_capture.capture_saml_response_with_firefox(
            "https://accounts.google.com/o/saml2/initsso",
            timeout_seconds=120,
        )

        self.assertEqual([str(browser_capture.os.getpid())], owners)

    @unittest.skipUnless(hasattr(signal, "SIGHUP"), "requires POSIX signals")
    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    @patch('aws_google_auth.browser_capture.build_firefox_capture_extension', spec=True)
    def test_capture_cleans_up_when_terminal_is_closed(
        self,
        mock_build_extension,
        mock_webdriver,
    ):
        driver = Mock()
        mock_webdriver.return_value = driver
        extension_paths = []
        driver.install_addon.side_effect = extension_paths.append
        driver.get.side_effect = lambda url: browser_capture.os.kill(
            browser_capture.os.getpid(),
            signal.SIGHUP,
        )
        previous_handler = signal.getsignal(signal.SIGHUP)

        with self.assertRaises(SystemExit):
            browser_capture.capture_saml_response_with_firefox(
                "https://accounts.google.com/o/saml2/initsso",
                timeout_seconds=120,
            )

        driver.quit.assert_called_once_with()
        self.assertFalse(extension_paths[0].parent.exists())
        self.assertIs(previous_handler, signal.getsignal(signal.SIGHUP))

    def make_capture_directory(self, root, name, owner=None, age_seconds=0):
        path = Path(root) / name
        path.mkdir()
        (path / "cookies.sqlite").write_text("cookie", encoding="utf-8")
        if owner is not None:
            (path / browser_capture.BROWSER_CAPTURE_OWNER_FILE).write_text(str(owner))
        modified = time.time() - age_seconds
        browser_capture.os.utime(path, (modified, modified))
        return path

    @unittest.skipUnless(browser_capture.os.name == "posix", "owner check is POSIX only")
    @patch('aws_google_auth.browser_capture.process_is_running', spec=True)
    def test_orphaned_capture_directories_are_removed(self, mock_is_running):
        live_process_id = 1234
        mock_is_running.side_effect = lambda process_id: process_id == live_process_id
        old = browser_capture.BROWSER_CAPTURE_ORPHAN_AGE_SECONDS + 60
        prefix = browser_capture.BROWSER_CAPTURE_TEMP_PREFIX

        with tempfile.TemporaryDirectory() as root:
            dead_owner = self.make_capture_directory(root, prefix + "dead", owner=4321)
            live_owner = self.make_capture_directory(root, prefix + "live", owner=live_process_id, age_seconds=old)
            old_unowned = self.make_capture_directory(root, prefix + "old", age_seconds=old)
            new_unowned = self.make_capture_directory(root, prefix + "new")
            unrelated = self.make_capture_directory(root, "unrelated", owner=4321, age_seconds=old)

            removed = browser_capture.remove_orphaned_capture_directories([root])

            self.assertEqual(2, removed)
            self.assertFalse(dead_owner.exists())
            self.assertFalse(old_unowned.exists())
            self.assertTrue(live_owner.exists())
            self.assertTrue(new_unowned.exists())
            self.assertTrue(unrelated.exists())

    def test_orphan_sweep_skips_missing_temp_roots(self):
        self.assertEqual(
            0,
            browser_capture.remove_orphaned_capture_directories(["/nonexistent/aws-google-auth"]),
        )

    def test_firefox_profile_storage_copy_is_limited_to_auth_origins(self):
        self.assertTrue(
            browser_capture.should_copy_firefox_storage_origin(
                "https+++accounts.google.com",
            )
        )
        self.assertTrue(
            browser_capture.should_copy_firefox_storage_origin(
                "https+++accounts.google.com^partitionKey=%28https%2Cexample.com%29",
            )
        )
        self.assertTrue(
            browser_capture.should_copy_firefox_storage_origin(
                "https+++ap-south-1.signin.aws.amazon.com",
            )
        )
        self.assertFalse(
            browser_capture.should_copy_firefox_storage_origin(
                "https+++www.google.com^partitionKey=%28https%2Cexample.com%29",
            )
        )
        self.assertFalse(
            browser_capture.should_copy_firefox_storage_origin(
                "https+++ap-south-1.console.aws.amazon.com",
            )
        )

    def test_firefox_capture_extension_includes_aws_role_scraper(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            extension_path = Path(temp_dir) / "capture.xpi"
            browser_capture.build_firefox_capture_extension(extension_path)

            with zipfile.ZipFile(extension_path) as archive:
                self.assertIn("aws_roles.js", archive.namelist())
                manifest = archive.read("manifest.json").decode("utf-8")
                self.assertIn("https://signin.aws.amazon.com/*", manifest)
                background = archive.read("background.js").decode("utf-8")
                role_scraper = archive.read("aws_roles.js").decode("utf-8")
                self.assertIn('message.type !== "awsPageReady"', background)
                self.assertIn('browser.storage.local.get(["samlResponse"])', background)
                self.assertIn('type: roles.length ? "awsRoles" : "awsPageReady"', role_scraper)
                self.assertIn('"#" + encodeURIComponent(payload)', background)
                captured_page = archive.read("captured.html").decode("utf-8")
                self.assertNotIn("saml-response", captured_page)

    def test_clone_firefox_profile_keeps_storage_but_skips_live_session(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            target = Path(temp_dir) / "target"
            source.mkdir()
            (source / "cookies.sqlite").write_text("cookie", encoding="utf-8")
            (source / ".parentlock").write_text("locked", encoding="utf-8")
            (source / "sessionstore.jsonlz4").write_text("tabs", encoding="utf-8")
            (source / "sessionstore-backups").mkdir()
            google_storage = source / "storage" / "default" / "https+++accounts.google.com"
            google_storage.mkdir(parents=True)
            (google_storage / "ls").write_text("state", encoding="utf-8")
            unrelated_storage = source / "storage" / "default" / "https+++example.com"
            unrelated_storage.mkdir()
            (unrelated_storage / "ls").write_text("skip", encoding="utf-8")
            progress = []

            result = browser_capture.clone_firefox_profile(
                source,
                target,
                progress=progress.append,
            )

            self.assertEqual(str(target), result)
            self.assertEqual("cookie", (target / "cookies.sqlite").read_text())
            self.assertFalse((target / ".parentlock").exists())
            self.assertFalse((target / "sessionstore.jsonlz4").exists())
            self.assertFalse((target / "sessionstore-backups").exists())
            self.assertTrue((target / "storage" / "default" / "https+++accounts.google.com").exists())
            self.assertFalse((target / "storage" / "default" / "https+++example.com").exists())
            self.assertIn("Firefox profile copy complete: 2 item(s).", progress)
            self.assertIn(
                'browser.sessionstore.resume_from_crash", false',
                (target / "user.js").read_text(encoding="utf-8"),
            )

    @patch('aws_google_auth.browser_capture.FirefoxWebDriver')
    @patch('aws_google_auth.browser_capture.build_firefox_capture_extension', spec=True)
    def test_capture_saml_response_uses_firefox_profile_and_timeout(
        self,
        mock_build_extension,
        mock_webdriver,
    ):
        driver = Mock()
        driver.current_url = captured_url("YWJjZA==", [
            {"accountName": "example-prod", "accountId": "111111111111", "roleName": "Admin"},
        ])
        mock_webdriver.return_value = driver

        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir) / "profile"
            profile_path.mkdir()
            (profile_path / "cookies.sqlite").write_text("cookie", encoding="utf-8")

            result = browser_capture.capture_saml_response_with_firefox(
                "https://accounts.google.com/o/saml2/initsso?idpid=idp&spid=sp&forceauthn=false",
                timeout_seconds=120,
                executable_path="/usr/bin/firefox",
                profile_path=str(profile_path),
                geckodriver_executable="/usr/bin/geckodriver",
            )

        self.assertEqual("YWJjZA==", result.saml_response)
        self.assertEqual({"111111111111": "example-prod"}, result.account_aliases)
        mock_webdriver.assert_called_once_with(
            geckodriver_executable="/usr/bin/geckodriver",
            request_timeout_seconds=browser_capture.WEBDRIVER_COMMAND_TIMEOUT_SECONDS,
            temp_directory=browser_capture.select_browser_capture_temp_root(),
        )
        session_kwargs = driver.create_session.call_args.kwargs
        self.assertEqual("/usr/bin/firefox", session_kwargs["firefox_executable"])
        self.assertNotEqual(str(profile_path), session_kwargs["profile_path"])
        driver.find_element.assert_not_called()
