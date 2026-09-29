# Contributing

Bug reports, fixes and improvements are all welcome.

## Reporting a problem

Open an issue with:

* the command you ran and the full output, ideally with `-l debug`
* your OS, Firefox version and `geckodriver --version` if you use `--browser-capture`

**Remove anything identifying before you paste**: email addresses, AWS account
IDs, role ARNs, your Google IdP/SP IDs and Firefox profile paths. Replace them
with placeholders such as `user@example.com`, `123456789012` or `C01abc234`.
Never paste a SAML response or credentials.

## Making a change

You need [uv](https://docs.astral.sh/uv/). Everything else is installed into a
local virtualenv:

```shell
git clone https://github.com/ambasta/aws-google-auth
cd aws-google-auth
uv sync --all-extras
```

Before opening a pull request, run the same checks CI runs:

```shell
uv run ruff check           # lint; --fix fixes most findings
uv run ruff format          # format
uv run ty check             # type check
uv run pytest               # tests
uv run rst-lint README.rst  # only if you touched the README
```

A few conventions:

* All code in `aws_google_auth/` is type-annotated; new functions should be too.
  Tests are exempt.
* Keep pull requests focused on one thing, and add or update tests for
  behaviour changes.
* Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  e.g. `fix(browser): ...` or `docs: ...`.
* Tests must not read or write your real `~/.aws` files; point
  `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` at a temporary directory
  as `test_config_parser.py` does.
