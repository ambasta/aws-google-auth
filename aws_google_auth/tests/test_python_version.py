from aws_google_auth import exit_if_unsupported_python

import unittest
import sys
from unittest import mock


class TestPythonFailOnVersion(unittest.TestCase):

    def test_python313(self):

        with mock.patch.object(sys, 'version_info') as v_info:
            v_info.__lt__.return_value = True

            with self.assertRaises(SystemExit) as cm:
                exit_if_unsupported_python()

            self.assertEqual(cm.exception.code, 1)

    def test_python314(self):
        with mock.patch.object(sys, 'version_info') as v_info:
            v_info.__lt__.return_value = False

            try:
                exit_if_unsupported_python()
            except SystemExit:
                self.fail("exit_if_unsupported_python() raised SystemExit unexpectedly!")
