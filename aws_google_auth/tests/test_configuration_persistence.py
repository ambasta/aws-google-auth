#!/usr/bin/env python

import configparser
import os
import tempfile
import unittest
from random import randint
from unittest import mock

from aws_google_auth import configuration

# Write to a throwaway config instead of the developer's own ~/.aws files.
_aws_files: tuple[tempfile.TemporaryDirectory[str], mock._patch_dict] | None = None


def setUpModule():
    global _aws_files
    temp_dir = tempfile.TemporaryDirectory()
    patcher = mock.patch.dict(
        os.environ,
        {
            "AWS_CONFIG_FILE": os.path.join(temp_dir.name, "config"),
            "AWS_SHARED_CREDENTIALS_FILE": os.path.join(temp_dir.name, "credentials"),
        },
    )
    patcher.start()
    _aws_files = (temp_dir, patcher)


def tearDownModule():
    assert _aws_files is not None
    temp_dir, patcher = _aws_files
    patcher.stop()
    temp_dir.cleanup()


class TestConfigurationPersistence(unittest.TestCase):
    def setUp(self):
        self.c = configuration.Configuration()

        # Pick a profile name that is clear it's for testing. We'll delete it
        # after, but in case something goes wrong we don't want to use
        # something that could clobber user input.
        self.c.profile = f"aws_google_auth_test_{randint(100, 999)}"

        # Pick a string to do password leakage tests.
        self.c.password = f"aws_google_auth_test_password_{randint(100, 999)}"

        self.c.region = "us-east-1"
        self.c.ask_role = False
        self.c.keyring = False
        self.c.duration = 1234
        self.c.idp_id = "sample_idp_id"
        self.c.role_arn = "arn:aws:iam::sample_arn"
        self.c.sp_id = "sample_sp_id"
        self.c.u2f_disabled = False
        self.c.username = "sample_username"
        self.c.bg_response = "foo"
        self.c.firefox_profile = "/home/test/.mozilla/firefox/default"
        self.c.raise_if_invalid()
        assert self.c.config_file.startswith(tempfile.gettempdir())
        self.c.write(None)
        self.c.account = "123456789012"

        self.config_parser = configparser.RawConfigParser()
        self.config_parser.read(self.c.config_file)

    def tearDown(self):
        section_name = configuration.Configuration.config_profile(self.c.profile)
        self.config_parser.remove_section(section_name)
        with open(self.c.config_file, "w") as config_file:
            self.config_parser.write(config_file)

    def test_creating_new_profile(self):
        profile_string = configuration.Configuration.config_profile(self.c.profile)
        self.assertTrue(self.config_parser.has_section(profile_string))
        self.assertEqual(self.config_parser[profile_string].get("google_config.google_idp_id"), self.c.idp_id)
        self.assertEqual(self.config_parser[profile_string].get("google_config.role_arn"), self.c.role_arn)
        self.assertEqual(self.config_parser[profile_string].get("google_config.google_sp_id"), self.c.sp_id)
        self.assertEqual(self.config_parser[profile_string].get("google_config.google_username"), self.c.username)
        self.assertEqual(self.config_parser[profile_string].get("region"), self.c.region)
        self.assertEqual(self.config_parser[profile_string].getboolean("google_config.ask_role"), self.c.ask_role)
        self.assertEqual(self.config_parser[profile_string].getboolean("google_config.keyring"), self.c.keyring)
        self.assertEqual(
            self.config_parser[profile_string].getboolean("google_config.u2f_disabled"), self.c.u2f_disabled
        )
        self.assertEqual(self.config_parser[profile_string].getint("google_config.duration"), self.c.duration)
        self.assertEqual(self.config_parser[profile_string].get("google_config.bg_response"), self.c.bg_response)
        self.assertEqual(
            self.config_parser[profile_string].get("google_config.firefox_profile"), self.c.firefox_profile
        )

    def test_unset_firefox_profile_is_removed(self):
        self.c.firefox_profile = None
        assert self.c.config_file.startswith(tempfile.gettempdir())
        self.c.write(None)

        config_parser = configparser.RawConfigParser()
        config_parser.read(self.c.config_file)
        profile_string = configuration.Configuration.config_profile(self.c.profile)
        self.assertFalse(config_parser.has_option(profile_string, "google_config.firefox_profile"))

    def test_password_not_written(self):
        profile_string = configuration.Configuration.config_profile(self.c.profile)
        self.assertIsNone(self.config_parser[profile_string].get("google_config.password", None))
        self.assertIsNone(self.config_parser[profile_string].get("password", None))

        # Check for password leakage (It didn't get written in an odd way)
        with open(self.c.config_file) as config_file:
            for line in config_file:
                self.assertNotIn(self.c.password, line)

    def test_can_read_all_values(self):
        test_configuration = configuration.Configuration()
        test_configuration.read(self.c.profile)

        # Reading won't get password, so we need to set for the configuration
        # to be considered valid
        test_configuration.password = "test_password"

        test_configuration.raise_if_invalid()

        self.assertEqual(test_configuration.profile, self.c.profile)
        self.assertEqual(test_configuration.idp_id, self.c.idp_id)
        self.assertEqual(test_configuration.role_arn, self.c.role_arn)
        self.assertEqual(test_configuration.sp_id, self.c.sp_id)
        self.assertEqual(test_configuration.username, self.c.username)
        self.assertEqual(test_configuration.region, self.c.region)
        self.assertEqual(test_configuration.ask_role, self.c.ask_role)
        self.assertEqual(test_configuration.u2f_disabled, self.c.u2f_disabled)
        self.assertEqual(test_configuration.duration, self.c.duration)
        self.assertEqual(test_configuration.keyring, self.c.keyring)
        self.assertEqual(test_configuration.bg_response, self.c.bg_response)
        self.assertEqual(test_configuration.firefox_profile, self.c.firefox_profile)
