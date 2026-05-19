import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, call, patch

from aws_google_auth import browser_capture


class TestBrowserCapture(unittest.TestCase):

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
                "190020191201": "delhivery",
                "551870907775": "delhivery-ba",
            },
            browser_capture.account_aliases_from_browser_roles([
                {"accountName": "delhivery", "accountId": "190020191201", "roleName": "SSOAdmin"},
                {"accountName": "delhivery-ba", "accountId": "551870907775", "roleName": "SAML_SUPERADMIN"},
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
    def test_capture_saml_response_uses_firefox_profile(self, mock_build_extension, mock_webdriver):
        driver = Mock()
        driver.current_url = "moz-extension://capture/captured.html"
        driver.find_element.side_effect = ["saml-element-id", "labels-element-id"]
        driver.get_element_property.side_effect = [
            "YWJjZA==",
            '[{"accountName":"delhivery","accountId":"190020191201","roleName":"SSOAdmin"}]',
        ]
        mock_webdriver.return_value = driver

        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir) / "profile"
            profile_path.mkdir()
            (profile_path / "cookies.sqlite").write_text("cookie", encoding="utf-8")

            result = browser_capture.capture_saml_response_with_firefox(
                "https://accounts.google.com/o/saml2/initsso?idpid=idp&spid=sp&forceauthn=false",
                timeout_seconds=1,
                executable_path="/usr/bin/firefox",
                profile_path=str(profile_path),
                geckodriver_executable="/usr/bin/geckodriver",
            )

        self.assertEqual("YWJjZA==", result.saml_response)
        self.assertEqual({"190020191201": "delhivery"}, result.account_aliases)
        mock_webdriver.assert_called_once_with(geckodriver_executable="/usr/bin/geckodriver")
        session_kwargs = driver.create_session.call_args.kwargs
        self.assertEqual("/usr/bin/firefox", session_kwargs["firefox_executable"])
        self.assertNotEqual(str(profile_path), session_kwargs["profile_path"])
        self.assertEqual([
            call("saml-element-id", "value"),
            call("labels-element-id", "textContent"),
        ], driver.get_element_property.mock_calls)
