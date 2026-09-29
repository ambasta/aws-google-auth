aws-google-auth
===============

|ci-badge|

.. |ci-badge| image:: https://github.com/ambasta/aws-google-auth/actions/workflows/ci.yml/badge.svg?branch=main
   :target: https://github.com/ambasta/aws-google-auth/actions/workflows/ci.yml
   :alt: CI status

Get temporary AWS credentials by signing in with your Google account.

If your company signs in to the AWS console through Google (SAML SSO), this
tool does the same thing from the terminal: you sign in to Google, pick a
role, and it writes short-lived keys into ``~/.aws/credentials`` for the AWS
CLI, SDKs and Terraform to use.

This is a fork of `cevoaustralia/aws-google-auth
<https://github.com/cevoaustralia/aws-google-auth>`__. The main addition is
``--browser-capture``, which signs in through a real Firefox window, so it
keeps working with Google's current JavaScript sign-in page, passkeys and
security keys.

.. contents:: On this page
   :local:
   :depth: 1

Quick start
-----------

1. Install the prerequisites:

   - `uv <https://docs.astral.sh/uv/getting-started/installation/>`__
   - Firefox
   - `geckodriver <https://github.com/mozilla/geckodriver/releases>`__,
     somewhere on your ``PATH`` (many distributions package it, e.g.
     ``brew install geckodriver`` or ``apt install firefox-geckodriver``)

2. Install the tool:

   .. code:: shell

       uv tool install --python 3.14 git+https://github.com/ambasta/aws-google-auth

   To try it without installing, replace ``aws-google-auth`` with
   ``uvx --python 3.14 --from git+https://github.com/ambasta/aws-google-auth aws-google-auth``
   in the commands below.

3. Ask your Google Workspace admin for the **IdP ID** and **SP ID** of the
   AWS app (or find them yourself; see `Finding your IdP and SP IDs`_).

4. Sign in. Pick any name you like for the AWS profile; ``work`` is used
   here:

   .. code:: shell

       aws-google-auth -p work -I C01abc234 -S 123456789012 -R us-east-1 --browser-capture

   A Firefox window opens on the Google sign-in page. Sign in as usual.
   When Google hands you over to AWS, the window closes by itself, and if
   you can use more than one role you are asked to pick one in the
   terminal.

5. Use the credentials:

   .. code:: shell

       export AWS_PROFILE=work
       aws sts get-caller-identity

When the credentials expire, sign in again with just the profile name. The
IdP ID, SP ID and region were saved the first time:

.. code:: shell

    aws-google-auth -p work --browser-capture

Setting up another profile
--------------------------

Most people have several AWS profiles behind the same Google sign-in. A new
profile inherits the IdP ID, SP ID, username, duration and region from
``[default]`` in ``~/.aws/config``, or from your other Google profiles when
they all use the same value. So once one profile works, the next one only
needs a name:

.. code:: shell

    aws-google-auth -p sandbox --browser-capture

Anything you pass on the command line wins over the saved values, so use
``-R`` or ``-d`` to give a profile its own region or duration.

To skip the role menu, save the role on the profile:

.. code:: shell

    aws-google-auth -p sandbox --browser-capture -r arn:aws:iam::111111111111:role/PowerUser

Or add a shell alias so signing in is one word:

.. code:: shell

    alias aws-sandbox='aws-google-auth -p sandbox --browser-capture && export AWS_PROFILE=sandbox'

How browser capture works
-------------------------

- The Firefox on your ``PATH`` (or in the usual install location on macOS and
  Windows) is used. Pass ``--firefox-executable`` to use another one.
- Your default Firefox profile is found automatically and copied into a
  temporary profile, so saved Google sessions and passkeys carry over but
  your running Firefox and its tabs are left alone. Pass
  ``--firefox-profile /path/to/profile`` to copy a different profile.
- The temporary copy is deleted when sign-in finishes, fails, or is
  interrupted with Ctrl-C. If the process is killed outright, the next run
  cleans up the leftover copy.
- The tool waits up to 10 minutes for you to finish signing in
  (``--browser-timeout`` changes that).

Finding your IdP and SP IDs
---------------------------

Both come from the Google Admin console, so you may need to ask an admin.

- **IdP ID** (``-I``): under *Security > Authentication > SSO with SAML
  applications*, the *SSO URL* looks like
  ``https://accounts.google.com/o/saml2/idp?idpid=C01abc234``. The part after
  ``idpid=`` is the IdP ID.
- **SP ID** (``-S``): open *Apps > Web and mobile apps* and select the AWS
  app. The page URL contains ``...AppDetails:service=123456789012``; that
  number is the SP ID.

If Google SSO to AWS isn't set up at all yet, these guides cover both the
Google and the AWS side:

- `How to Set Up Federated Single Sign-On to AWS Using Google Apps
  <https://aws.amazon.com/blogs/security/how-to-set-up-federated-single-sign-on-to-aws-using-google-apps/>`__
- `Using Google Apps SAML SSO to do one-click login to AWS
  <https://blog.faisalmisle.com/2015/11/using-google-apps-saml-sso-to-do-one-click-login-to-aws/>`__

What gets saved where
---------------------

``~/.aws/config``
    One ``[profile NAME]`` section per profile, holding the region and the
    ``google_config.*`` settings (IdP ID, SP ID, username, duration, role
    ARN, Firefox profile). Nothing secret is stored here.

``~/.aws/credentials``
    The temporary access key, secret key and session token for each profile,
    plus when they expire. They stop working on their own after the chosen
    duration.

``~/.aws/saml_cache_<IdP ID>.xml``
    The last Google SAML response, reused by password sign-in until it
    expires so you aren't asked to sign in again. ``--no-cache`` turns this
    off. Browser capture always signs in fresh.

Your Google password is never written to disk. With ``-k`` it is kept in the
system keyring instead, which needs the ``keyring`` extra (see below).

The ``AWS_CONFIG_FILE`` and ``AWS_SHARED_CREDENTIALS_FILE`` environment
variables move these files, as they do for the AWS CLI.

Troubleshooting
---------------

``geckodriver`` not found
    Install geckodriver and make sure ``geckodriver --version`` works in the
    same terminal, or pass ``--geckodriver-executable /path/to/geckodriver``.

Firefox is not found, or the wrong one opens
    Pass ``--firefox-executable /path/to/firefox``.

Firefox opens with no saved logins
    The tool couldn't find your default profile, or picked a different one.
    Open ``about:profiles`` in Firefox, copy the *Root Directory* of the
    profile you use, and pass it with ``--firefox-profile``. It is saved for
    that AWS profile, so you only need to do this once.

"Saved Firefox profile ... no longer exists"
    The profile saved for this AWS profile was deleted or renamed, so the
    default profile is used instead. Nothing to do unless you want a
    different profile.

The session is shorter or longer than expected
    The default duration is 12 hours (``-d 43200``), but AWS caps it at the
    role's *maximum session duration*, which is 1 hour unless an admin raised
    it. Use ``--auto-duration`` to ask for the longest the role allows. See
    the `AWS documentation
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html>`__.

Something else went wrong
    Run again with ``-l debug`` and include the output (with account IDs and
    emails removed) when you open an issue.

Other ways to sign in
---------------------

``--browser-capture`` is the recommended mode. The others are still here if
it doesn't suit you.

Username and password
    Leave out ``--browser-capture`` and the tool signs in to Google directly
    and prompts for your password and second factor. Google's sign-in page
    changes often and blocks this more and more, so it may not work for your
    account, and if Google asks for a CAPTCHA you have to use
    ``--browser-capture`` instead.

    Two extras add to this mode: ``u2f`` for USB security keys, and
    ``keyring`` to remember your password in the system keyring with ``-k``:

    .. code:: shell

        uv tool install --python 3.14 "aws-google-auth[u2f,keyring] @ git+https://github.com/ambasta/aws-google-auth"

    To read the password from a password manager, pipe it in; the password
    prompt then reads from stdin instead of the terminal:

    .. code:: shell

        password-manager show google | aws-google-auth -p work

    Avoid typing the password into the command line itself, where it ends up
    in your shell history.

Any browser, copy and paste (``--browser``)
    Opens the sign-in page in your default browser and asks you to paste the
    ``SAMLResponse`` from the browser's developer tools. Works with any
    browser but is fiddly.

Existing assertion (``--saml-assertion``)
    Pass a base64-encoded SAML assertion you already have.

Docker
    Build the image with ``docker build -t aws-google-auth .`` and run it
    with your AWS directory mounted:

    .. code:: shell

        docker run -it -e GOOGLE_USERNAME -e GOOGLE_IDP_ID -e GOOGLE_SP_ID -e AWS_PROFILE \
            -v ~/.aws:/root/.aws aws-google-auth

    The image has no Firefox and can't reach USB security keys, so only
    username and password sign-in works inside it.

Environment variables
    Most options can also be set through the environment:
    ``GOOGLE_USERNAME``, ``GOOGLE_IDP_ID``, ``GOOGLE_SP_ID``,
    ``AWS_DEFAULT_REGION``, ``AWS_PROFILE``, ``AWS_ROLE_ARN``, ``DURATION``,
    ``AUTO_DURATION``, ``AWS_ACCOUNT`` and
    ``AWS_GOOGLE_AUTH_FIREFOX_PROFILE``.

All options
-----------

.. code:: text

    $ aws-google-auth --help
    usage: aws-google-auth [-h] [-u USERNAME] [-I IDP_ID] [-S SP_ID] [-R REGION] [-d DURATION | --auto-duration] [-p PROFILE]
                           [-A ACCOUNT] [-D] [-q] [--bg-response BG_RESPONSE] [--saml-assertion SAML_ASSERTION] [--browser |
                           --browser-capture] [--browser-timeout BROWSER_TIMEOUT] [--firefox-executable FIREFOX_EXECUTABLE]
                           [--firefox-profile FIREFOX_PROFILE] [--geckodriver-executable GECKODRIVER_EXECUTABLE] [--no-cache]
                           [--print-creds] [--resolve-aliases] [--save-failure-html] [--save-saml-flow] [-a | -r ROLE_ARN] [-k]
                           [-l {debug,info,warn}] [-V]

    Acquire temporary AWS credentials via Google SSO

    options:
      -h, --help            show this help message and exit
      -u, --username USERNAME
                            Google Apps username ($GOOGLE_USERNAME)
      -I, --idp-id IDP_ID   Google SSO IDP identifier ($GOOGLE_IDP_ID)
      -S, --sp-id SP_ID     Google SSO SP identifier ($GOOGLE_SP_ID)
      -R, --region REGION   AWS region endpoint ($AWS_DEFAULT_REGION)
      -d, --duration DURATION
                            Credential duration in seconds (defaults to value of $DURATION, then falls back to 43200)
      --auto-duration       Tries to use the longest allowed duration ($AUTO_DURATION)
      -p, --profile PROFILE
                            AWS profile (defaults to value of $AWS_PROFILE, then falls back to 'sts')
      -A, --account ACCOUNT
                            Filter for specific AWS account.
      -D, --disable-u2f     Disable U2F functionality.
      -q, --quiet           Quiet output
      --bg-response BG_RESPONSE
                            Override default bgresponse challenge token.
      --saml-assertion SAML_ASSERTION
                            Base64 encoded SAML assertion to use.
      --browser             Open Google SSO in a browser and prompt for a copied SAMLResponse.
      --browser-capture     Use Firefox to capture the browser SAMLResponse automatically.
      --browser-timeout BROWSER_TIMEOUT
                            Seconds to wait for browser SAML capture.
      --firefox-executable FIREFOX_EXECUTABLE
                            Path to a Firefox executable for --browser-capture (defaults to the Firefox on $PATH).
      --firefox-profile FIREFOX_PROFILE
                            Path to a Firefox profile directory to copy for --browser-capture (defaults to Firefox's default
                            profile).
      --geckodriver-executable GECKODRIVER_EXECUTABLE
                            Path to geckodriver for --browser-capture.
      --no-cache            Do not cache the SAML Assertion.
      --print-creds         Print Credentials.
      --resolve-aliases     Resolve AWS account aliases.
      --save-failure-html   Write HTML failure responses to file for troubleshooting.
      --save-saml-flow      Write all GET and PUT requests and HTML responses to/from Google to files for troubleshooting.
      -a, --ask-role        Set true to always pick the role
      -r, --role-arn ROLE_ARN
                            The ARN of the role to assume
      -k, --keyring         Use keyring for storing the password.
      -l, --log {debug,info,warn}
                            Select log level (default: warn)
      -V, --version         show program's version number and exit

Development
-----------

.. code:: shell

    git clone https://github.com/ambasta/aws-google-auth
    cd aws-google-auth
    uv sync --all-extras

    uv run aws-google-auth --help    # run from the checkout
    uv run pytest                    # tests
    uv run ruff check                # lint (add --fix to fix what it can)
    uv run ruff format               # format
    uv run ty check                  # type check
    uv run rst-lint README.rst       # this file

The code is fully type-annotated and checked with `ty
<https://docs.astral.sh/ty/>`__; `ruff <https://docs.astral.sh/ruff/>`__
handles linting and formatting. CI runs all of the above on every push and
pull request. See
`CONTRIBUTING <CONTRIBUTING.md>`__ and the `code of conduct
<CODE_OF_CONDUCT.md>`__.

Notes on password sign-in
~~~~~~~~~~~~~~~~~~~~~~~~~

Google supports several second factors, and each one sends password sign-in
to a different "next" URL during ``do_login``. Google decides the order when
you have more than one. The ones this tool handles:

+------------------+-------------------------------------+
| Method           | URL Fragment                        |
+==================+=====================================+
| No second factor | (none)                              |
+------------------+-------------------------------------+
| TOTP (eg Google  | ``.../signin/challenge/totp/...``   |
|  Authenticator   |                                     |
|  or Authy)       |                                     |
+------------------+-------------------------------------+
| SMS (or voice    | ``.../signin/challenge/ipp/...``    |
|  call)           |                                     |
+------------------+-------------------------------------+
| SMS (or voice    | ``.../signin/challenge/iap/...``    |
|  call) with      |                                     |
|  number          |                                     |
|  submission      |                                     |
+------------------+-------------------------------------+
| Google Prompt    | ``.../signin/challenge/az/...``     |
|  (phone app)     |                                     |
+------------------+-------------------------------------+
| Security key     | ``.../signin/challenge/sk/...``     |
|  (eg yubikey)    |                                     |
+------------------+-------------------------------------+
| Dual prompt      | ``.../signin/challenge/dp/...``     |
|  (Validate 2FA ) |                                     |
+------------------+-------------------------------------+
| Backup code      | ``... (unknown yet) ...``           |
|  (printed codes) |                                     |
+------------------+-------------------------------------+

Acknowledgments
---------------

This work is inspired by `keyme <https://github.com/wheniwork/keyme>`__
-- their digging into the guts of how Google SAML auth works is what's
enabled it.

The attribute management and credential injection into AWS configuration files
was heavily borrowed from `aws-adfs <https://github.com/venth/aws-adfs>`__.
