import argparse
import base64
import binascii
import os
import re
import sys
import logging
import webbrowser
from urllib import parse as urllib_parse

import keyring
from bs4 import BeautifulSoup
from tzlocal import get_localzone

from aws_google_auth import _version
from aws_google_auth import amazon
from aws_google_auth import configuration
from aws_google_auth import google
from aws_google_auth import util


def parse_args(args):
    parser = argparse.ArgumentParser(
        prog="aws-google-auth",
        description="Acquire temporary AWS credentials via Google SSO",
    )

    parser.add_argument('-u', '--username', help='Google Apps username ($GOOGLE_USERNAME)')
    parser.add_argument('-I', '--idp-id', help='Google SSO IDP identifier ($GOOGLE_IDP_ID)')
    parser.add_argument('-S', '--sp-id', help='Google SSO SP identifier ($GOOGLE_SP_ID)')
    parser.add_argument('-R', '--region', help='AWS region endpoint ($AWS_DEFAULT_REGION)')
    duration_group = parser.add_mutually_exclusive_group()
    duration_group.add_argument('-d', '--duration', type=int, help='Credential duration in seconds (defaults to value of $DURATION, then falls back to 43200)')
    duration_group.add_argument('--auto-duration', action='store_true', help='Tries to use the longest allowed duration ($AUTO_DURATION)')
    parser.add_argument('-p', '--profile', help='AWS profile (defaults to value of $AWS_PROFILE, then falls back to \'sts\')')
    parser.add_argument('-A', '--account', help='Filter for specific AWS account.')
    parser.add_argument('-D', '--disable-u2f', action='store_true', help='Disable U2F functionality.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet output')
    parser.add_argument('--bg-response', help='Override default bgresponse challenge token.')
    parser.add_argument('--saml-assertion', dest="saml_assertion", help='Base64 encoded SAML assertion to use.')
    browser_group = parser.add_mutually_exclusive_group()
    browser_group.add_argument('--browser', action='store_true', help='Open Google SSO in a browser and prompt for a copied SAMLResponse.')
    browser_group.add_argument('--browser-capture', action='store_true', help='Use Firefox to capture the browser SAMLResponse automatically.')
    parser.add_argument('--browser-timeout', type=int, default=600, help='Seconds to wait for browser SAML capture.')
    parser.add_argument('--firefox-executable', help='Path to a Firefox executable for --browser-capture.')
    parser.add_argument('--firefox-profile', help='Path to a Firefox profile directory to copy for --browser-capture.')
    parser.add_argument('--geckodriver-executable', default='geckodriver', help='Path to geckodriver for --browser-capture.')
    parser.add_argument('--no-cache', dest="saml_cache", action='store_false', help='Do not cache the SAML Assertion.')
    parser.add_argument('--print-creds', action='store_true', help='Print Credentials.')
    parser.add_argument('--resolve-aliases', action='store_true', help='Resolve AWS account aliases.')
    parser.add_argument('--save-failure-html', action='store_true', help='Write HTML failure responses to file for troubleshooting.')
    parser.add_argument('--save-saml-flow', action='store_true', help='Write all GET and PUT requests and HTML responses to/from Google to files for troubleshooting.')

    role_group = parser.add_mutually_exclusive_group()
    role_group.add_argument('-a', '--ask-role', action='store_true', help='Set true to always pick the role')
    role_group.add_argument('-r', '--role-arn', help='The ARN of the role to assume')
    parser.add_argument('-k', '--keyring', action='store_true', help='Use keyring for storing the password.')
    parser.add_argument('-l', '--log', dest='log_level', choices=['debug',
                        'info', 'warn'], default='warn', help='Select log level (default: %(default)s)')
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s {version}'.format(version=_version.__version__))

    return parser.parse_args(args)


def exit_if_unsupported_python():
    if sys.version_info < (3, 14):
        logging.critical("%s requires Python 3.14 or higher.", __name__)
        logging.critical("For debugging, it appears you're running: %s",
                         sys.version_info)
        sys.exit(1)


def extract_saml_assertion(assertion):
    value = assertion.strip()

    if '<' in value and 'SAMLResponse' in value:
        parsed = BeautifulSoup(value, 'html.parser')
        saml_input = parsed.find(attrs={'name': 'SAMLResponse'})
        if saml_input and saml_input.get('value'):
            value = saml_input.get('value').strip()
    elif 'SAMLResponse' in value:
        parsed_query = urllib_parse.parse_qs(urllib_parse.urlsplit(value).query)
        if 'SAMLResponse' not in parsed_query:
            parsed_query = urllib_parse.parse_qs(value)

        if parsed_query.get('SAMLResponse'):
            value = parsed_query['SAMLResponse'][0].strip()
        else:
            match = re.search(r'SAMLResponse=([^&\s]+)', value)
            if match:
                value = urllib_parse.unquote_plus(match.group(1)).strip()

    return value.replace(' ', '+').replace('\n', '').replace('\r', '')


def decode_saml_assertion(assertion):
    try:
        return base64.b64decode(extract_saml_assertion(assertion))
    except (binascii.Error, ValueError) as ex:
        raise google.ExpectedGoogleException(
            "Could not decode SAMLResponse. Paste the base64 SAMLResponse value "
            "from the browser form or network request."
        ) from ex


def get_browser_saml_assertion(config):
    login_url = google.Google(config, save_failure=False).login_url

    print("Opening Google SSO in your browser:")
    print(login_url)
    webbrowser.open(login_url)
    print("After login, copy the SAMLResponse value from the browser form or network request.")
    print("The assertion is a bearer credential; only paste it into this terminal.")

    return decode_saml_assertion(util.Util.get_input("SAMLResponse: "))


def capture_browser_saml_assertion(
    config,
    timeout_seconds,
    firefox_executable=None,
    firefox_profile=None,
    geckodriver_executable='geckodriver',
):
    from aws_google_auth import browser_capture

    login_url = google.Google(config, save_failure=False).login_url

    print("Opening Firefox for Google SSO:")
    print(login_url)
    print("Complete Google sign-in in the Firefox window. Waiting for the AWS SAMLResponse POST...")

    try:
        capture_result = browser_capture.capture_saml_response_with_firefox(
            login_url,
            timeout_seconds=timeout_seconds,
            executable_path=firefox_executable,
            profile_path=firefox_profile,
            geckodriver_executable=geckodriver_executable,
            google_username=config.username,
        )
    except (RuntimeError, TimeoutError) as ex:
        raise google.ExpectedGoogleException(str(ex)) from ex

    account_aliases = {}
    if isinstance(capture_result, dict):
        assertion = capture_result["saml_response"]
        account_aliases = capture_result.get("account_aliases") or {}
    elif hasattr(capture_result, "saml_response"):
        assertion = capture_result.saml_response
        account_aliases = capture_result.account_aliases or {}
    else:
        assertion = capture_result

    return decode_saml_assertion(assertion), account_aliases


def cli(cli_args):
    try:
        exit_if_unsupported_python()

        args = parse_args(args=cli_args)

        config = resolve_config(args)
        process_auth(args, config)
    except google.ExpectedGoogleException as ex:
        print(ex)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        logging.exception(ex)


def resolve_config(args):

    # Shortening Convenience functions
    coalesce = util.Util.coalesce
    strip_if_string = util.Util.strip_if_string

    # Create a blank configuration object (has the defaults pre-filled)
    config = configuration.Configuration()

    # Have the configuration update itself via the ~/.aws/config on disk.
    # Profile (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.profile = strip_if_string(coalesce(
        args.profile,
        os.getenv('AWS_PROFILE'),
        config.profile))

    # Now that we've established the profile, we can read the configuration and
    # fill in all the other variables.
    config.read(config.profile)

    # Ask Role (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.ask_role = bool(coalesce(
        args.ask_role,
        os.getenv('AWS_ASK_ROLE'),
        config.ask_role))

    # Duration (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.duration = int(coalesce(
        args.duration,
        os.getenv('DURATION'),
        config.duration))

    # Automatic duration (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.auto_duration = coalesce(
        args.auto_duration,
        os.getenv('AUTO_DURATION'),
        config.auto_duration
    )

    # IDP ID (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.idp_id = strip_if_string(coalesce(
        args.idp_id,
        os.getenv('GOOGLE_IDP_ID'),
        config.idp_id))

    # Region (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.region = strip_if_string(coalesce(
        args.region,
        os.getenv('AWS_DEFAULT_REGION'),
        config.region))

    # ROLE ARN (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.role_arn = strip_if_string(coalesce(
        args.role_arn,
        os.getenv('AWS_ROLE_ARN'),
        config.role_arn))

    # SP ID (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.sp_id = strip_if_string(coalesce(
        args.sp_id,
        os.getenv('GOOGLE_SP_ID'),
        config.sp_id))

    # U2F Disabled (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.u2f_disabled = coalesce(
        args.disable_u2f,
        os.getenv('U2F_DISABLED'),
        config.u2f_disabled)

    # Resolve AWS aliases enabled (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.resolve_aliases = coalesce(
        args.resolve_aliases,
        os.getenv('RESOLVE_AWS_ALIASES'),
        config.resolve_aliases)

    # Username (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.username = strip_if_string(coalesce(
        args.username,
        os.getenv('GOOGLE_USERNAME'),
        config.username))

    # Account (Option priority = ARGS, ENV_VAR, DEFAULT)
    config.account = strip_if_string(coalesce(
        args.account,
        os.getenv('AWS_ACCOUNT'),
        config.account))

    config.firefox_profile = strip_if_string(coalesce(
        args.firefox_profile,
        os.getenv('AWS_GOOGLE_AUTH_FIREFOX_PROFILE'),
        config.firefox_profile))

    config.keyring = coalesce(
        args.keyring,
        config.keyring)

    config.print_creds = coalesce(
        args.print_creds,
        config.print_creds)

    # Quiet
    config.quiet = coalesce(
        args.quiet,
        config.quiet)

    config.bg_response = strip_if_string(coalesce(
        args.bg_response,
        os.getenv('GOOGLE_BG_RESPONSE'),
        config.bg_response))

    return config


def process_auth(args, config):
    # Set up logging
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), None))
    browser_account_aliases = {}

    if config.region is None:
        config.region = util.Util.get_input("AWS Region: ")
        logging.debug('%s: region is: %s', __name__, config.region)

    # If there is a valid cache and the user opted to use it, use that instead
    # of prompting the user for input (it will also ignroe any set variables
    # such as username or sp_id and idp_id, as those are built into the SAML
    # response). The user does not need to be prompted for a password if the
    # SAML cache is used.
    if args.saml_assertion:
        saml_xml = decode_saml_assertion(args.saml_assertion)
    elif args.browser_capture:
        if config.idp_id is None:
            config.idp_id = util.Util.get_input("Google IDP ID: ")
            logging.debug('%s: idp is: %s', __name__, config.idp_id)
        if config.sp_id is None:
            config.sp_id = util.Util.get_input("Google SP ID: ")
            logging.debug('%s: sp is: %s', __name__, config.sp_id)

        saml_xml, browser_account_aliases = capture_browser_saml_assertion(
            config,
            timeout_seconds=args.browser_timeout,
            firefox_executable=args.firefox_executable,
            firefox_profile=config.firefox_profile,
            geckodriver_executable=args.geckodriver_executable,
        )
    elif args.browser:
        if config.idp_id is None:
            config.idp_id = util.Util.get_input("Google IDP ID: ")
            logging.debug('%s: idp is: %s', __name__, config.idp_id)
        if config.sp_id is None:
            config.sp_id = util.Util.get_input("Google SP ID: ")
            logging.debug('%s: sp is: %s', __name__, config.sp_id)

        saml_xml = get_browser_saml_assertion(config)
    elif args.saml_cache and config.saml_cache:
        saml_xml = config.saml_cache
        logging.info('%s: SAML cache found', __name__)
    else:
        # No cache, continue without.
        logging.info('%s: SAML cache not found', __name__)
        if config.username is None:
            config.username = util.Util.get_input("Google username: ")
            logging.debug('%s: username is: %s', __name__, config.username)
        if config.idp_id is None:
            config.idp_id = util.Util.get_input("Google IDP ID: ")
            logging.debug('%s: idp is: %s', __name__, config.idp_id)
        if config.sp_id is None:
            config.sp_id = util.Util.get_input("Google SP ID: ")
            logging.debug('%s: sp is: %s', __name__, config.sp_id)

        # There is no way (intentional) to pass in the password via the command
        # line nor environment variables. This prevents password leakage.
        keyring_password = None
        if config.keyring:
            keyring_password = keyring.get_password("aws-google-auth", config.username)
            if keyring_password:
                config.password = keyring_password
            else:
                config.password = util.Util.get_password("Google Password: ")
        else:
            config.password = util.Util.get_password("Google Password: ")

        # Validate Options
        config.raise_if_invalid()

        google_client = google.Google(config, save_failure=args.save_failure_html, save_flow=args.save_saml_flow)
        google_client.do_login()
        saml_xml = google_client.parse_saml()
        logging.debug('%s: saml assertion is: %s', __name__, saml_xml)

        # If we logged in correctly and we are using keyring then store the password
        if config.keyring and keyring_password is None:
            keyring.set_password(
                "aws-google-auth", config.username, config.password)

    # We now have a new SAML value that can get cached (If the user asked
    # for it to be)
    if args.saml_cache:
        config.saml_cache = saml_xml

    # The amazon_client now has the SAML assertion it needed (Either via the
    # cache or freshly generated). From here, we can get the roles and continue
    # the rest of the workflow regardless of cache.
    amazon_client = amazon.Amazon(config, saml_xml)
    roles = amazon_client.roles

    # Determine the provider and the role arn (if the the user provided isn't an option)
    if config.role_arn in roles and not config.ask_role:
        config.provider = roles[config.role_arn]
    else:
        if config.account and config.resolve_aliases:
            aliases = amazon_client.resolve_aws_aliases(roles)
            config.role_arn, config.provider = util.Util.pick_a_role(roles, aliases, config.account)
        elif config.account and browser_account_aliases:
            config.role_arn, config.provider = util.Util.pick_a_role(roles, browser_account_aliases, config.account)
        elif config.account:
            config.role_arn, config.provider = util.Util.pick_a_role(roles, account=config.account)
        elif config.resolve_aliases:
            aliases = amazon_client.resolve_aws_aliases(roles)
            config.role_arn, config.provider = util.Util.pick_a_role(roles, aliases)
        elif browser_account_aliases:
            config.role_arn, config.provider = util.Util.pick_a_role(roles, browser_account_aliases)
        else:
            config.role_arn, config.provider = util.Util.pick_a_role(roles)
    if not config.quiet:
        print("Assuming " + config.role_arn)
        print("Credentials Expiration: " + format(amazon_client.expiration.astimezone(get_localzone())))

    if config.print_creds:
        amazon_client.print_export_line()

    if config.profile:
        config.write(amazon_client)


def main():
    cli_args = sys.argv[1:]
    cli(cli_args)


if __name__ == '__main__':
    main()
