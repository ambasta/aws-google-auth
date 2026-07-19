import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import ANY, Mock, PropertyMock, call, patch

from aws_google_auth import browser_capture


class TestBrowserCapture(unittest.TestCase):

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
        driver.quit()

    def test_firefox_webdriver_skips_session_delete_after_failed_request(self):
        driver = browser_capture.FirefoxWebDriver()
        driver.session_id = "session-id"
        driver.request_failed = True
        driver.request = Mock()
        driver.process = Mock()

        driver.quit()

        driver.request.assert_not_called()

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
            "moz-extension://capture/captured.html",
        ])
        type(driver).current_url = current_url
        driver.find_element.side_effect = ["saml-element-id", "labels-element-id"]
        driver.get_element_property.side_effect = ["YWJjZA==", "[]"]
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
            "moz-extension://capture/captured.html",
        ])
        type(driver).current_url = current_url
        driver.find_element.side_effect = ["saml-element-id", "labels-element-id"]
        driver.get_element_property.side_effect = ["YWJjZA==", "[]"]
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
        driver.current_url = "moz-extension://capture/captured.html"
        driver.find_element.side_effect = ["saml-element-id", "labels-element-id"]
        driver.get_element_property.side_effect = [
            "YWJjZA==",
            '[{"accountName":"example-prod","accountId":"111111111111","roleName":"Admin"}]',
        ]
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
        )
        session_kwargs = driver.create_session.call_args.kwargs
        self.assertEqual("/usr/bin/firefox", session_kwargs["firefox_executable"])
        self.assertNotEqual(str(profile_path), session_kwargs["profile_path"])
        self.assertEqual([
            call("saml-element-id", "value"),
            call("labels-element-id", "textContent"),
        ], driver.get_element_property.mock_calls)
