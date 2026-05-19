#!/usr/bin/env python

import unittest

from unittest.mock import patch, MagicMock

from aws_google_auth import util


class TestUtilMethods(unittest.TestCase):

    def test_coalesce_no_arguments(self):
        self.assertEqual(util.Util.coalesce(), None)

    def test_coalesce_one_argument(self):
        value = "non_none_value"
        self.assertEqual(util.Util.coalesce(value), value)
        self.assertEqual(util.Util.coalesce(None), None)

    def test_coalesce_two_arguments(self):
        value = "non_none_value"
        self.assertEqual(util.Util.coalesce(value, None), value)
        self.assertEqual(util.Util.coalesce(value, value), value)
        self.assertEqual(util.Util.coalesce(None, value), value)
        self.assertEqual(util.Util.coalesce(None, None), None)

    def test_coalesce_many_arguments(self):
        self.assertEqual(util.Util.coalesce(None, "test-01", None, "test-02", None, "test-03"), "test-01")
        self.assertEqual(util.Util.coalesce("test-01", None, "test-02", None, "test-03", None), "test-01")
        self.assertEqual(util.Util.coalesce(None, None, None, None, None, None, None, None, None, None, "test-01"), "test-01")

    def test_unicode_to_string_if_needed_python_3(self):
        value_string = "Test String!"
        self.assertIn("str", str(value_string.__class__))
        self.assertEqual(util.Util.unicode_to_string_if_needed(value_string), value_string)

    def test_unicode_to_string_if_needed(self):
        self.assertEqual(util.Util.unicode_to_string_if_needed(None), None)
        self.assertEqual(util.Util.unicode_to_string_if_needed(1234), 1234)
        self.assertEqual(util.Util.unicode_to_string_if_needed("nop"), "nop")

    @patch('builtins.input', spec=True)
    def test_get_input_strips_whitespace(self, mock_input):
        mock_input.return_value = " C03023tpd "

        self.assertEqual(util.Util.get_input("Google IDP ID: "), "C03023tpd")

    def test_strip_if_string(self):
        self.assertEqual(util.Util.strip_if_string(" ap-south-1 "), "ap-south-1")
        self.assertEqual(util.Util.strip_if_string(None), None)
        self.assertEqual(util.Util.strip_if_string(1234), 1234)

    @patch('getpass.getpass', spec=True)
    @patch('sys.stdin', spec=True)
    def test_get_password_when_tty(self, mock_stdin, mock_getpass):
        mock_stdin.isatty = MagicMock(return_value=True)

        mock_getpass.return_value = "pass"

        self.assertEqual(util.Util.get_password("Test: "), "pass")

    @patch('sys.stdin', spec=True)
    def test_get_password_when_not_tty(self, mock_stdin):
        mock_stdin.isatty = MagicMock(return_value=False)
        mock_stdin.readline = MagicMock(return_value="pass")

        self.assertEqual(util.Util.get_password("Test: "), "pass")
