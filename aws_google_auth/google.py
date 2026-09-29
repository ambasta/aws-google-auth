import base64
import json
import logging
import os
import re
import sys
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, NoReturn
from urllib import parse as urllib_parse

import requests
from bs4 import BeautifulSoup, Tag
from requests import HTTPError

from aws_google_auth import _version

if TYPE_CHECKING:
    # configuration imports amazon, which imports this module, so only import it for type checking.
    from aws_google_auth.configuration import Configuration

# The U2F USB Library is optional, if it's there, include it.
try:
    from aws_google_auth import u2f
except ImportError:
    logging.info("Failed to import U2F libraries, U2F login unavailable. Other methods can still continue.")


# Form fields POSTed back to Google; requests drops fields whose value is None.
type FormData = Mapping[str, str | int | None]


class ExpectedGoogleException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


def _find_tag(page: Tag, name: str, attrs: Mapping[str, str | bool] | None = None) -> Tag:
    """Find a tag that the sign-in flow cannot continue without."""
    attrs = attrs or {}
    tag = page.find(name, dict(attrs))
    if tag is None:
        described = " ".join([name, *(key if value is True else f"{key}={value}" for key, value in attrs.items())])
        raise ExpectedGoogleException(f"Google's sign-in page changed: could not find <{described}>")
    return tag


def _optional_attr(tag: Tag, attr: str) -> str | None:
    value = tag.get(attr)
    # bs4 splits multi-valued attributes such as class into lists; join them back.
    if isinstance(value, list):
        return " ".join(value)
    return value


def _tag_attr(tag: Tag, attr: str) -> str:
    value = _optional_attr(tag, attr)
    if value is None:
        raise ExpectedGoogleException(f"Google's sign-in page changed: <{tag.name}> has no {attr} attribute")
    return value


def _input_value(page: Tag, name: str) -> str:
    return _tag_attr(_find_tag(page, "input", {"name": name}), "value")


def _form_inputs(form: Tag) -> dict[str, str | None]:
    """Collect the named <input> fields of a form, as a browser would submit them."""
    payload: dict[str, str | None] = {}
    for tag in form.find_all("input"):
        name = _optional_attr(tag, "name")
        if name is None:
            continue

        payload[name] = _optional_attr(tag, "value")
    return payload


class Google:
    session: requests.Session
    cont: str | None

    def __init__(self, config: Configuration, save_failure: bool, save_flow: bool = False) -> None:
        """The Google object holds authentication state
        for a given session. You need to supply:

        username: FQDN Google username, eg first.last@example.com
        password: obvious
        idp_id: Google's assigned IdP identifier for your G-suite account
        sp_id: Google's assigned SP identifier for your AWS SAML app

        Optionally, you can supply:
        duration_seconds: number of seconds for the session to be active (max 43200)
        """

        self.version = _version.__version__
        self.config = config
        self.base_url = "https://accounts.google.com"
        self.save_failure = save_failure
        self.session_state: requests.Response | None = None
        self.save_flow = save_flow
        if save_flow:
            self.save_flow_dict: dict[str, int] = {}
            self.save_flow_dir = "aws-google-auth-" + datetime.now().strftime("%Y-%m-%dT%H%M%S")
            os.makedirs(self.save_flow_dir, exist_ok=True)

    @property
    def login_url(self) -> str:
        return self.base_url + f"/o/saml2/initsso?idpid={self.config.idp_id}&spid={self.config.sp_id}&forceauthn=false"

    def check_for_failure(self, sess: requests.Response) -> requests.Response:

        if isinstance(sess.reason, bytes):
            # We attempt to decode utf-8 first because some servers
            # choose to localize their reason strings. If the string
            # isn't utf-8, we fall back to iso-8859-1 for all other
            # encodings. (See PR #3538)
            try:
                reason = sess.reason.decode("utf-8")
            except UnicodeDecodeError:
                reason = sess.reason.decode("iso-8859-1")
        else:
            reason = sess.reason

        if sess.status_code == 403:
            raise ExpectedGoogleException(f"{reason} accessing {sess.url}")

        try:
            sess.raise_for_status()
        except HTTPError as ex:
            if self.save_failure:
                logging.exception("Saving failure trace in 'failure.html'", ex)
                with open("failure.html", "w") as out:
                    out.write(sess.text)

            raise ex

        return sess

    def _save_file_name(self, url: str) -> str:
        filename = url.split("://")[1].split("?")[0].replace("accounts.google", "ac.go").replace("/", "~")
        file_idx = self.save_flow_dict.get(filename, 1)
        self.save_flow_dict[filename] = file_idx + 1
        return filename + "_" + str(file_idx)

    def _save_request(
        self, url: str, method: str = "GET", data: FormData | None = None, json_data: FormData | None = None
    ) -> None:
        if self.save_flow:
            filename = self._save_file_name(url) + "_" + method + ".req"
            with open(os.path.join(self.save_flow_dir, filename), "w", encoding="utf-8") as out:
                try:
                    out.write("params=" + url.split("?")[1])
                except IndexError:
                    out.write("params=None")
                out.write(self._redact_password("\ndata: " + json.dumps(data, indent=2)))
                out.write(self._redact_password("\njson: " + json.dumps(json_data, indent=2)))

    def _redact_password(self, text: str) -> str:
        password = self.config.password
        return text.replace(password, "<PASSWORD>") if password else text

    def _save_response(self, url: str, response: requests.Response) -> None:
        if self.save_flow:
            filename = self._save_file_name(url) + ".html"
            with open(os.path.join(self.save_flow_dir, filename), "w", encoding="utf-8") as out:
                out.write(response.text)

    def _raise_unexpected_login_page(self, sess: requests.Response, parsed_page: Tag, context: str) -> NoReturn:
        if self.save_failure:
            logging.error("Google %s page lookup failed, storing failure page to 'failure.html'.", context)
            with open("failure.html", "w", encoding="utf-8") as out:
                out.write(sess.text)

        error_msg = self.parse_error_message(sess)
        if error_msg is None:
            title = parsed_page.find("title")
            error_msg = title.get_text(strip=True) if title else "unexpected Google login page"

        if parsed_page.find(id="identifierId"):
            raise ExpectedGoogleException(
                f"Google returned the modern JavaScript sign-in page during {context} ({error_msg}). "
                f"This CLI expects Google's legacy HTML SAML form. Open this URL in a browser: {self.login_url} "
                "then run document.bg.invoke() in the browser console and pass the result with "
                "--bg-response."
            )

        raise ExpectedGoogleException(
            f"Google did not return the expected SAML login form during {context} ({error_msg}). "
            "Check GOOGLE_IDP_ID and GOOGLE_SP_ID; remove any extra spaces. "
            "Use --save-failure-html to save the response for debugging."
        )

    def post(self, url: str, data: FormData | None = None, json_data: FormData | None = None) -> requests.Response:
        try:
            self._save_request(url, method="POST", data=data, json_data=json_data)
            response = self.check_for_failure(self.session.post(url, data=data, json=json_data))
            self._save_response(url, response)

        except requests.exceptions.ConnectionError as e:
            logging.exception("There was a connection error, check your network settings.", e)
            sys.exit(1)
        except requests.exceptions.Timeout as e:
            logging.exception("The connection timed out, please try again.", e)
            sys.exit(1)
        except requests.exceptions.TooManyRedirects as e:
            logging.exception("The number of redirects exceeded the maximum allowed.", e)
            sys.exit(1)

        return response

    def get(self, url: str) -> requests.Response:
        try:
            self._save_request(url)
            response = self.check_for_failure(self.session.get(url))
            self._save_response(url, response)

        except requests.exceptions.ConnectionError as e:
            logging.exception("There was a connection error, check your network settings.", e)
            sys.exit(1)
        except requests.exceptions.Timeout as e:
            logging.exception("The connection timed out, please try again.", e)
            sys.exit(1)
        except requests.exceptions.TooManyRedirects as e:
            logging.exception("The number of redirects exceeded the maximum allowed.", e)
            sys.exit(1)

        return response

    @staticmethod
    def parse_error_message(sess: requests.Response) -> str | None:
        response_page = BeautifulSoup(sess.text, "html.parser")
        error = response_page.find("span", {"id": "errorMsg"})

        if error is None:
            return None
        else:
            return error.text

    @staticmethod
    def find_key_handles(input: object, challengeTxt: bytes) -> list[bytes]:
        keyHandles: list[bytes] = []
        if isinstance(input, dict):  # parse down a dict
            for item in input:
                keyHandles.extend(Google.find_key_handles(input[item], challengeTxt))

        elif isinstance(input, list):  # looks like we've hit an array - iterate it
            array = list(filter(None, input))  # remove any None type objects from the array
            for item in array:
                if isinstance(item, list):  # another array - recursive call
                    keyHandles.extend(Google.find_key_handles(item, challengeTxt))
                elif not isinstance(item, str):  # ints bools etc we don't care
                    continue
                else:  # we went a string or unicode here (python 3.x lost unicode global)
                    try:  # keyHandle string will be base64 encoded -
                        # if its not an exception is thrown and we continue as its not the string we're after
                        base64UrlEncoded = base64.urlsafe_b64encode(base64.b64decode(item))
                        if base64UrlEncoded != challengeTxt:  # make sure its not the challengeTxt - if it not return it
                            keyHandles.append(base64UrlEncoded)
                    except ValueError:
                        pass
        return keyHandles

    @staticmethod
    def find_app_id(inputString: str) -> str:
        try:
            searchMatch = re.search('"appid":"[a-z://.-_] + "', inputString)
            if searchMatch is None:
                raise ValueError("appid not found")
            searchResult = searchMatch.group()
            searchObject = json.loads("{" + searchResult + "}")
            return str(searchObject["appid"])
        except Exception:
            logging.exception("Was unable to find appid value in googles SAML page")
            sys.exit(1)

    def do_login(self) -> None:
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"AWS Sign-in/{self.version} (aws-google-auth)"
        sess = self.get(self.login_url)

        # Collect information from the page source
        first_page = BeautifulSoup(sess.text, "html.parser")
        continue_input = first_page.find("input", {"name": "continue"})
        form = first_page.find("form", {"id": "gaia_loginform"})
        if continue_input is None or form is None:
            self._raise_unexpected_login_page(sess, first_page, "initial login")

        # gxf = first_page.find('input', {'name': 'gxf'}).get('value')
        self.cont = _optional_attr(continue_input, "value")
        # page = first_page.find('input', {'name': 'Page'}).get('value')
        # sign_in = first_page.find('input', {'name': 'signIn'}).get('value')
        account_login_url = _tag_attr(form, "action")

        payload = _form_inputs(form)

        payload["Email"] = self.config.username

        if self.config.bg_response:
            payload["bgresponse"] = self.config.bg_response

        if payload.get("PersistentCookie") is not None:
            payload["PersistentCookie"] = "yes"

        if payload.get("TrustDevice") is not None:
            payload["TrustDevice"] = "on"

        # POST to account login info page, to collect profile and session info
        sess = self.post(account_login_url, data=payload)

        self.session.headers["Referer"] = sess.url

        # Collect ProfileInformation, SessionState, signIn, and Password Challenge URL
        challenge_page = BeautifulSoup(sess.text, "html.parser")

        # Handle the "old-style" page
        old_style_form = challenge_page.find("form", {"id": "gaia_loginform"})
        if old_style_form:
            form = old_style_form
            passwd_challenge_url = _tag_attr(form, "action")
        else:
            # sometimes they serve up a different page
            logging.info("Handling new-style login page")
            form = challenge_page.find("form", {"id": "challenge"})
            if form is None:
                self._raise_unexpected_login_page(sess, challenge_page, "password challenge")
            passwd_challenge_url = "https://accounts.google.com" + _tag_attr(form, "action")

        payload.update(_form_inputs(form))

        # Update the payload
        payload["Passwd"] = self.config.password

        # Set bg_response in request payload to passwd challenge
        if self.config.bg_response:
            payload["bgresponse"] = self.config.bg_response

        # POST to Authenticate Password
        sess = self.post(passwd_challenge_url, data=payload)

        response_page = BeautifulSoup(sess.text, "html.parser")
        error = response_page.find(class_="error-msg")
        cap = response_page.find("input", {"name": "identifier-captcha-input"})

        # Were there any errors logging in? Could be invalid username or password,
        # unless Google is showing a CAPTCHA, which is handled below.
        if error is not None and cap is None:
            raise ExpectedGoogleException("Invalid username or password")

        if "signin/rejected" in sess.url:
            raise ExpectedGoogleException(
                f"""Default value of parameter `bgresponse` has not accepted.
                Please visit login URL {self.login_url}, open the web inspector and execute document.bg.invoke() in the console.
                Then, set --bg-response to the function output."""
            )

        self.check_extra_step(response_page)

        # Google asks for a CAPTCHA when it thinks you, or someone sharing
        # your IP address, is a bot. That is easier to solve in a real browser.
        if cap is not None:
            raise ExpectedGoogleException(
                "Google asked for a CAPTCHA. Sign in with --browser-capture instead to solve it in Firefox."
            )

        self.session.headers["Referer"] = sess.url

        if "selectchallenge/" in sess.url:
            sess = self.handle_selectchallenge(sess)

        # Was there an MFA challenge?
        if "challenge/totp/" in sess.url:
            error_msg = ""
            while error_msg is not None:
                sess = self.handle_totp(sess)
                error_msg = self.parse_error_message(sess)
                if error_msg is not None:
                    logging.error(error_msg)
        elif "challenge/ipp/" in sess.url:
            sess = self.handle_sms(sess)
        elif "challenge/az/" in sess.url:
            sess = self.handle_prompt(sess)
        elif "challenge/sk/" in sess.url:
            sess = self.handle_sk(sess)
        elif "challenge/iap/" in sess.url:
            sess = self.handle_iap(sess)
        elif "challenge/dp/" in sess.url:
            sess = self.handle_dp(sess)
        elif "challenge/ootp/5" in sess.url:
            raise NotImplementedError("Offline Google App OOTP not implemented")

        # ... there are different URLs for backup codes (printed)
        # and security keys (eg yubikey) as well
        # save for later
        self.session_state = sess

    @staticmethod
    def check_extra_step(response: Tag) -> None:
        # Google's page uses a typographic apostrophe here.
        extra_step = response.find(string="This extra step shows that it’s really you trying to sign in")  # noqa: RUF001
        contact_admin = response.find(id="contactAdminMessage")
        if extra_step and contact_admin:
            raise ValueError(contact_admin.text)

    def parse_saml(self) -> bytes:
        session_state = self.session_state
        if session_state is None:
            raise RuntimeError("You must use do_login() before calling parse_saml()")

        parsed = BeautifulSoup(session_state.text, "html.parser")
        saml_input = parsed.find("input", {"name": "SAMLResponse"})
        saml_element = None if saml_input is None else _optional_attr(saml_input, "value")
        if saml_element is None:
            if self.save_failure:
                logging.error("SAML lookup failed, storing failure page to 'saml.html' to assist with debugging.")
                with open("saml.html", "wb") as out:
                    out.write(session_state.text.encode("utf-8"))

            raise ExpectedGoogleException(
                "Something went wrong - Could not find SAML response, check your credentials or use --save-failure-html to debug."
            )

        return base64.b64decode(saml_element)

    def handle_sk(self, sess: requests.Response) -> requests.Response:
        response_page = BeautifulSoup(sess.text, "html.parser")
        challenge_url = sess.url.split("?")[0]
        challenges_txt = _input_value(response_page, "id-challenge")

        facet_url = urllib_parse.urlparse(challenge_url)
        facet = facet_url.scheme + "://" + facet_url.netloc

        keyHandleJSField = _tag_attr(_find_tag(response_page, "div", {"jsname": "C0oDBd"}), "data-challenge-ui")
        startJSONPosition = keyHandleJSField.find("{")
        endJSONPosition = keyHandleJSField.rfind("}")
        keyHandleJsonPayload = json.loads(keyHandleJSField[startJSONPosition : endJSONPosition + 1])

        keyHandles = self.find_key_handles(
            keyHandleJsonPayload, base64.urlsafe_b64encode(base64.b64decode(challenges_txt))
        )
        appId = self.find_app_id(str(keyHandleJsonPayload))

        # txt sent for signing needs to be base64 url encode
        # we also have to remove any base64 padding because including including it will prevent google accepting the auth response
        challenges_txt_encode_pad_removed = base64.urlsafe_b64encode(base64.b64decode(challenges_txt)).strip(b"=")

        u2f_challenges = [
            {
                "version": "U2F_V2",
                "challenge": challenges_txt_encode_pad_removed.decode(),
                "appId": appId,
                "keyHandle": keyHandle.decode(),
            }
            for keyHandle in keyHandles
        ]

        # Prompt the user up to attempts_remaining times to insert their U2F device.
        attempts_remaining = 5
        auth_response = None
        while True:
            try:
                auth_response_dict = u2f.u2f_auth(u2f_challenges, facet)
                auth_response = json.dumps(auth_response_dict)
                break
            except RuntimeWarning:
                logging.error("No U2F device found. %d attempts remaining", attempts_remaining)
                if attempts_remaining <= 0:
                    break
                else:
                    input("Insert your U2F device and press enter to try again...")
                    attempts_remaining -= 1

        # If we exceed the number of attempts, raise an error and let the program exit.
        if auth_response is None:
            raise ExpectedGoogleException("No U2F device found. Please check your setup.")

        payload = {
            "challengeId": _input_value(response_page, "challengeId"),
            "challengeType": _input_value(response_page, "challengeType"),
            "continue": _input_value(response_page, "continue"),
            "scc": _input_value(response_page, "scc"),
            "sarp": _input_value(response_page, "sarp"),
            "checkedDomains": _input_value(response_page, "checkedDomains"),
            "pstMsg": "1",
            "TL": _input_value(response_page, "TL"),
            "gxf": _input_value(response_page, "gxf"),
            "id-challenge": challenges_txt,
            "id-assertion": auth_response,
            "TrustDevice": "on",
        }
        return self.post(challenge_url, data=payload)

    def handle_sms(self, sess: requests.Response) -> requests.Response:
        response_page = BeautifulSoup(sess.text, "html.parser")
        challenge_url = sess.url.split("?")[0]

        sms_token = input("Enter SMS token: G-") or None

        challenge_form = _find_tag(response_page, "form")
        payload = _form_inputs(challenge_form)

        if response_page.find("input", {"name": "TrustDevice"}) is not None:
            payload["TrustDevice"] = "on"

        payload["Pin"] = sms_token

        payload.pop("SendMethod", None)

        # Submit IPP (SMS code)
        return self.post(challenge_url, data=payload)

    def handle_prompt(self, sess: requests.Response) -> requests.Response:
        response_page = BeautifulSoup(sess.text, "html.parser")
        challenge_url = sess.url.split("?")[0]

        data_key = _tag_attr(_find_tag(response_page, "div", {"data-api-key": True}), "data-api-key")
        data_tx_id = _tag_attr(_find_tag(response_page, "div", {"data-tx-id": True}), "data-tx-id")

        # Need to post this to the verification/pause endpoint
        await_url = f"https://content.googleapis.com/cryptauth/v1/authzen/awaittx?alt=json&key={data_key}"
        await_body = {"txId": data_tx_id}

        self.check_prompt_code(response_page)

        print("Open the Google App, and tap 'Yes' on the prompt to sign in ...")

        self.session.headers["Referer"] = sess.url

        while True:
            try:
                response = self.post(await_url, json_data=await_body)
                break
            except requests.exceptions.HTTPError as ex:
                if ex.response is None or not ex.response.status_code == 500:
                    raise ex

        parsed_response = json.loads(response.text)

        payload = {
            "challengeId": _input_value(response_page, "challengeId"),
            "challengeType": _input_value(response_page, "challengeType"),
            "continue": _input_value(response_page, "continue"),
            "scc": _input_value(response_page, "scc"),
            "sarp": _input_value(response_page, "sarp"),
            "checkedDomains": _input_value(response_page, "checkedDomains"),
            "checkConnection": "youtube:1295:1",
            "pstMsg": _input_value(response_page, "pstMsg"),
            "TL": _input_value(response_page, "TL"),
            "gxf": _input_value(response_page, "gxf"),
            "token": parsed_response["txToken"],
            "action": _input_value(response_page, "action"),
            "TrustDevice": "on",
        }

        return self.post(challenge_url, data=payload)

    @staticmethod
    def check_prompt_code(response: Tag) -> None:
        """
        Sometimes there is an additional numerical code on the response page that needs to be selected
        on the prompt from a list of multiple choice. Print it if it's there.
        """
        num_code = response.find("div", {"jsname": "EKvSSd"})
        if num_code:
            print(f"numerical code for prompt: {num_code.string}")

    def handle_totp(self, sess: requests.Response) -> requests.Response:
        response_page = BeautifulSoup(sess.text, "html.parser")
        tl = _input_value(response_page, "TL")
        gxf = _input_value(response_page, "gxf")
        challenge_url = sess.url.split("?")[0]
        challenge_id = challenge_url.split("totp/")[1]

        mfa_token = input("MFA token: ") or None

        if not mfa_token:
            raise ValueError(f"MFA token required for {self.config.username} but none supplied.")

        payload = {
            "challengeId": challenge_id,
            "challengeType": 6,
            "continue": self.cont,
            "scc": 1,
            "sarp": 1,
            "checkedDomains": "youtube",
            "pstMsg": 0,
            "TL": tl,
            "gxf": gxf,
            "Pin": mfa_token,
            "TrustDevice": "on",
        }

        # Submit TOTP
        return self.post(challenge_url, data=payload)

    def handle_dp(self, sess: requests.Response) -> requests.Response:
        response_page = BeautifulSoup(sess.text, "html.parser")

        input("Check your phone - after you have confirmed response press ENTER to continue.") or None

        form = _find_tag(response_page, "form", {"id": "challenge"})
        challenge_url = "https://accounts.google.com" + _tag_attr(form, "action")

        payload = _form_inputs(form)

        # Submit Configuration
        return self.post(challenge_url, data=payload)

    def handle_iap(self, sess: requests.Response) -> requests.Response:
        response_page = BeautifulSoup(sess.text, "html.parser")
        challenge_url = sess.url.split("?")[0]
        phone_number = input("Enter your phone number:") or None

        while True:
            try:
                choice = int(input("Type 1 to receive a code by SMS or 2 for a voice call:"))
                if choice not in [1, 2]:
                    raise ValueError
            except ValueError:
                logging.error("Not a valid (integer) option, try again")
                continue
            else:
                if choice == 1:
                    send_method = "SMS"
                elif choice == 2:
                    send_method = "VOICE"
                else:
                    continue
                break

        payload = {
            "challengeId": _input_value(response_page, "challengeId"),
            "challengeType": _input_value(response_page, "challengeType"),
            "continue": self.cont,
            "scc": _input_value(response_page, "scc"),
            "sarp": _input_value(response_page, "sarp"),
            "checkedDomains": _input_value(response_page, "checkedDomains"),
            "pstMsg": _input_value(response_page, "pstMsg"),
            "TL": _input_value(response_page, "TL"),
            "gxf": _input_value(response_page, "gxf"),
            "phoneNumber": phone_number,
            "sendMethod": send_method,
        }

        # Submit phone number and desired method (SMS or voice call)
        sess = self.post(challenge_url, data=payload)

        response_page = BeautifulSoup(sess.text, "html.parser")
        challenge_url = sess.url.split("?")[0]

        token = input("Enter " + send_method + " token: G-") or None

        payload = {
            "challengeId": _input_value(response_page, "challengeId"),
            "challengeType": _input_value(response_page, "challengeType"),
            "continue": _input_value(response_page, "continue"),
            "scc": _input_value(response_page, "scc"),
            "sarp": _input_value(response_page, "sarp"),
            "checkedDomains": _input_value(response_page, "checkedDomains"),
            "pstMsg": _input_value(response_page, "pstMsg"),
            "TL": _input_value(response_page, "TL"),
            "gxf": _input_value(response_page, "gxf"),
            "pin": token,
        }

        # Submit SMS/VOICE token
        return self.post(challenge_url, data=payload)

    def handle_selectchallenge(self, sess: requests.Response) -> requests.Response:
        response_page = BeautifulSoup(sess.text, "html.parser")

        challenges: list[list[str]] = []
        for i in response_page.select("form[data-challengeentry]"):
            action = _tag_attr(i, "action")

            if "challenge/totp/" in action:
                challenges.append(["TOTP (Google Authenticator)", _tag_attr(i, "data-challengeentry")])
            elif "challenge/ipp/" in action:
                challenges.append(["SMS", _tag_attr(i, "data-challengeentry")])
            elif "challenge/iap/" in action:
                challenges.append(["SMS other phone", _tag_attr(i, "data-challengeentry")])
            elif "challenge/sk/" in action:
                challenges.append(["YubiKey", _tag_attr(i, "data-challengeentry")])
            elif "challenge/az/" in action:
                challenges.append(["Google Prompt", _tag_attr(i, "data-challengeentry")])

        print("Choose MFA method from available:")
        for i, mfa in enumerate(challenges, start=1):
            print(f"{i}: {mfa[0]}")

        selected_challenge = input("Enter MFA choice number (1): ") or None

        if selected_challenge is not None and int(selected_challenge) <= len(challenges):
            selected_challenge = int(selected_challenge) - 1
        else:
            selected_challenge = 0

        challenge_id = challenges[selected_challenge][1]
        print(f"MFA Type Chosen: {challenges[selected_challenge][0]}")

        # We need the specific form of the challenge chosen
        challenge_form = _find_tag(response_page, "form", {"data-challengeentry": challenge_id})

        payload = _form_inputs(challenge_form)

        if response_page.find("input", {"name": "TrustDevice"}) is not None:
            payload["TrustDevice"] = "on"

        # POST to google with the chosen challenge
        return self.post(self.base_url + _tag_attr(challenge_form, "action"), data=payload)
