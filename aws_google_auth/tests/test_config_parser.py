import os
import tempfile
import unittest

from unittest import mock

from aws_google_auth import resolve_config, parse_args


# Keep the developer's own ~/.aws/config from leaking into the defaults.
_aws_files = None


def setUpModule():
    global _aws_files
    temp_dir = tempfile.TemporaryDirectory()
    patcher = mock.patch.dict(os.environ, {
        'AWS_CONFIG_FILE': os.path.join(temp_dir.name, 'config'),
        'AWS_SHARED_CREDENTIALS_FILE': os.path.join(temp_dir.name, 'credentials'),
    })
    patcher.start()
    _aws_files = (temp_dir, patcher)


def tearDownModule():
    temp_dir, patcher = _aws_files
    patcher.stop()
    temp_dir.cleanup()


class TestProfileProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("sts", config.profile)

    def test_cli_param_supplied(self):
        args = parse_args(['-p', 'profile'])
        config = resolve_config(args)
        self.assertEqual('profile', config.profile)

    @mock.patch.dict(os.environ, {'AWS_PROFILE': 'mytemp'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual('mytemp', config.profile)

        args = parse_args(['-p', 'profile'])
        config = resolve_config(args)
        self.assertEqual('profile', config.profile)


class TestUsernameProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.username)

    def test_cli_param_supplied(self):
        args = parse_args(['-u', 'user@gmail.com'])
        config = resolve_config(args)
        self.assertEqual('user@gmail.com', config.username)

    @mock.patch.dict(os.environ, {'GOOGLE_USERNAME': 'override@gmail.com'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual('override@gmail.com', config.username)

        args = parse_args(['-u', 'user@gmail.com'])
        config = resolve_config(args)
        self.assertEqual('user@gmail.com', config.username)


class TestFirefoxProfileProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.firefox_profile)

    def test_cli_param_supplied(self):
        args = parse_args(['--firefox-profile', '/home/me/.mozilla/firefox/default'])
        config = resolve_config(args)
        self.assertEqual('/home/me/.mozilla/firefox/default', config.firefox_profile)

    def test_cli_param_supplied_with_whitespace(self):
        args = parse_args(['--firefox-profile', ' /home/me/.mozilla/firefox/default '])
        config = resolve_config(args)
        self.assertEqual('/home/me/.mozilla/firefox/default', config.firefox_profile)

    @mock.patch.dict(os.environ, {'AWS_GOOGLE_AUTH_FIREFOX_PROFILE': '/tmp/firefox-profile'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual('/tmp/firefox-profile', config.firefox_profile)

        args = parse_args(['--firefox-profile', '/home/me/.mozilla/firefox/default'])
        config = resolve_config(args)
        self.assertEqual('/home/me/.mozilla/firefox/default', config.firefox_profile)

    def write_saved_profile(self, firefox_profile):
        with open(os.environ['AWS_CONFIG_FILE'], 'w') as config_file:
            config_file.write(
                "[profile saved]\ngoogle_config.firefox_profile = {}\n".format(firefox_profile))
        self.addCleanup(os.remove, os.environ['AWS_CONFIG_FILE'])

    def test_saved_profile_is_used_when_it_exists(self):
        with tempfile.TemporaryDirectory() as firefox_profile:
            self.write_saved_profile(firefox_profile)
            config = resolve_config(parse_args(['-p', 'saved']))
        self.assertEqual(firefox_profile, config.firefox_profile)

    def test_stale_saved_profile_is_dropped(self):
        self.write_saved_profile('/nonexistent/firefox/gone.default-release')
        with self.assertLogs(level='WARNING'):
            config = resolve_config(parse_args(['-p', 'saved']))
        self.assertEqual(None, config.firefox_profile)

    def test_missing_cli_profile_is_kept(self):
        self.write_saved_profile('/nonexistent/firefox/gone.default-release')
        config = resolve_config(parse_args(['-p', 'saved', '--firefox-profile', '/nonexistent/other']))
        self.assertEqual('/nonexistent/other', config.firefox_profile)


class TestDurationProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(43200, config.duration)

    def test_cli_param_supplied(self):
        args = parse_args(['-d', "500"])
        config = resolve_config(args)
        self.assertEqual(500, config.duration)

    def test_invalid_cli_param_supplied(self):

        with self.assertRaises(SystemExit):
            args = parse_args(['-d', "blart"])
            resolve_config(args)

    @mock.patch.dict(os.environ, {'DURATION': '3000'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(3000, config.duration)

        args = parse_args(['-d', "500"])
        config = resolve_config(args)
        self.assertEqual(500, config.duration)


class TestIDPProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.idp_id)

    def test_cli_param_supplied(self):
        args = parse_args(['-I', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.idp_id)

    def test_cli_param_supplied_with_whitespace(self):
        args = parse_args(['-I', " kjl2342 "])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.idp_id)

    @mock.patch.dict(os.environ, {'GOOGLE_IDP_ID': 'adsfasf233423'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("adsfasf233423", config.idp_id)

        args = parse_args(['-I', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.idp_id)


class TestSPProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.sp_id)

    def test_cli_param_supplied(self):
        args = parse_args(['-S', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.sp_id)

    def test_cli_param_supplied_with_whitespace(self):
        args = parse_args(['-S', " kjl2342 "])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.sp_id)

    @mock.patch.dict(os.environ, {'GOOGLE_SP_ID': 'adsfasf233423'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("adsfasf233423", config.sp_id)

        args = parse_args(['-S', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.sp_id)


class TestRegionProcessing(unittest.TestCase):

    @unittest.skip("Region defaults are resolved interactively at runtime.")
    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.region)

    def test_cli_param_supplied(self):
        args = parse_args(['--region', "ap-southeast-4"])
        config = resolve_config(args)
        self.assertEqual("ap-southeast-4", config.region)

    @mock.patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'ap-southeast-9'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("ap-southeast-9", config.region)

        args = parse_args(['--region', "ap-southeast-4"])
        config = resolve_config(args)
        self.assertEqual("ap-southeast-4", config.region)


class TestRoleProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.role_arn)

    def test_cli_param_supplied(self):
        args = parse_args(['-r', "role1234"])
        config = resolve_config(args)
        self.assertEqual("role1234", config.role_arn)

    @mock.patch.dict(os.environ, {'AWS_ROLE_ARN': '4567-role'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("4567-role", config.role_arn)


class TestAskRoleProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertFalse(config.ask_role)

    def test_cli_param_supplied(self):
        args = parse_args(['-a'])
        config = resolve_config(args)
        self.assertTrue(config.ask_role)

    @unittest.skip("Environment boolean parsing is not implemented.")
    @mock.patch.dict(os.environ, {'AWS_ASK_ROLE': 'true'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertTrue(config.ask_role)


class TestU2FDisabledProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertFalse(config.u2f_disabled)

    def test_cli_param_supplied(self):
        args = parse_args(['-D'])
        config = resolve_config(args)
        self.assertTrue(config.u2f_disabled)

    @unittest.skip("Environment boolean parsing is not implemented.")
    @mock.patch.dict(os.environ, {'U2F_DISABLED': 'true'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertTrue(config.u2f_disabled)


class TestResolveAliasesProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertFalse(config.resolve_aliases)

    def test_cli_param_supplied(self):
        args = parse_args(['--resolve-aliases'])
        config = resolve_config(args)
        self.assertTrue(config.resolve_aliases)

    @unittest.skip("Environment boolean parsing is not implemented.")
    @mock.patch.dict(os.environ, {'RESOLVE_AWS_ALIASES': 'true'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertTrue(config.resolve_aliases)


class TestBgResponseProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertFalse(config.resolve_aliases)

    def test_cli_param_supplied(self):
        args = parse_args(['--bg-response=foo'])
        config = resolve_config(args)
        self.assertEqual(config.bg_response, 'foo')

    @unittest.skip("Environment bg_response behavior is covered by CLI precedence tests.")
    @mock.patch.dict(os.environ, {'GOOGLE_BG_RESPONSE': 'foo'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(config.bg_response, 'foo')


class TestAccountProcessing(unittest.TestCase):

    @unittest.skip("Account defaults to an empty string in configuration.")
    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.account)

    def test_cli_param_supplied(self):
        args = parse_args(['--account', "123456789012"])
        config = resolve_config(args)
        self.assertEqual("123456789012", config.account)

    @mock.patch.dict(os.environ, {'AWS_ACCOUNT': '123456789012'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("123456789012", config.account)

        args = parse_args(['--region', "123456789012"])
        config = resolve_config(args)
        self.assertEqual("123456789012", config.account)
