#!/usr/bin/env python

import base64
import os
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from threading import Thread

import botocore.session
from botocore.exceptions import ClientError, ProfileNotFound

from aws_google_auth.google import ExpectedGoogleException


class Amazon:
    def __init__(self, config, saml_xml):
        self.config = config
        self.saml_xml = saml_xml
        self.__token = None

    @property
    def sts_client(self):
        try:
            profile = os.environ.get("AWS_PROFILE")
            if profile is not None:
                del os.environ["AWS_PROFILE"]
            client = botocore.session.Session().create_client("sts", region_name=self.config.region)
            if profile is not None:
                os.environ["AWS_PROFILE"] = profile
            return client
        except ProfileNotFound as ex:
            raise ExpectedGoogleException(f"Error : {ex}.") from ex

    @property
    def base64_encoded_saml(self):
        return base64.b64encode(self.saml_xml).decode("utf-8")

    @property
    def token(self):
        if self.__token is None:
            self.__token = self.assume_role(
                self.config.role_arn, self.config.provider, self.base64_encoded_saml, self.config.duration
            )
        return self.__token

    @property
    def access_key_id(self):
        return self.token["Credentials"]["AccessKeyId"]

    @property
    def secret_access_key(self):
        return self.token["Credentials"]["SecretAccessKey"]

    @property
    def session_token(self):
        return self.token["Credentials"]["SessionToken"]

    @property
    def expiration(self):
        return self.token["Credentials"]["Expiration"]

    def print_export_line(self):
        export_template = "export AWS_ACCESS_KEY_ID='{}' AWS_SECRET_ACCESS_KEY='{}' AWS_SESSION_TOKEN='{}' AWS_SESSION_EXPIRATION='{}'"

        formatted = export_template.format(
            self.access_key_id,
            self.secret_access_key,
            self.session_token,
            self.expiration.strftime("%Y-%m-%dT%H:%M:%S%z"),
        )

        print(formatted)

    @property
    def roles(self):
        doc = ET.fromstring(self.saml_xml)
        roles = {}
        for attribute in doc.iterfind('.//*[@Name="https://aws.amazon.com/SAML/Attributes/Role"]'):
            for x in attribute.itertext():
                if "arn:aws:iam:" in x or "arn:aws-us-gov:iam:" in x:
                    res = x.split(",")
                    roles[res[0]] = res[1]
        return roles

    def assume_role(self, role, principal, saml_assertion, duration=None, auto_duration=True):
        sts_call_vars = {"RoleArn": role, "PrincipalArn": principal, "SAMLAssertion": saml_assertion}

        # Try the maximum duration of 12 hours, if it fails try to use the
        # maximum duration indicated by the error
        if self.config.auto_duration and auto_duration:
            sts_call_vars["DurationSeconds"] = self.config.max_duration
            try:
                res = self.sts_client.assume_role_with_saml(**sts_call_vars)
            except ClientError as err:
                if err.response.get("Error", []).get("Code") == "ValidationError" and err.response.get("Error", []).get(
                    "Message"
                ):
                    m = re.search(
                        "Member must have value less than or equal to ([0-9]{3,5})", err.response["Error"]["Message"]
                    )
                    if m is not None and m.group(1):
                        new_duration = int(m.group(1))
                        return self.assume_role(
                            role, principal, saml_assertion, duration=new_duration, auto_duration=False
                        )
                # Unknown error or no max time returned in error message
                raise
        elif duration:
            sts_call_vars["DurationSeconds"] = duration

        res = self.sts_client.assume_role_with_saml(**sts_call_vars)

        return res

    def resolve_aws_aliases(self, roles):
        def resolve_aws_alias(role, principal, aws_dict):
            session = botocore.session.Session()

            sts = session.create_client("sts", region_name=self.config.region)
            saml = sts.assume_role_with_saml(
                RoleArn=role, PrincipalArn=principal, SAMLAssertion=self.base64_encoded_saml
            )

            iam = session.create_client(
                "iam",
                region_name=self.config.region,
                aws_access_key_id=saml["Credentials"]["AccessKeyId"],
                aws_secret_access_key=saml["Credentials"]["SecretAccessKey"],
                aws_session_token=saml["Credentials"]["SessionToken"],
            )
            try:
                response = iam.list_account_aliases()
                account_alias = response["AccountAliases"][0]
                aws_dict[role.split(":")[4]] = account_alias
            except Exception:
                sts = session.create_client(
                    "sts",
                    region_name=self.config.region,
                    aws_access_key_id=saml["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=saml["Credentials"]["SecretAccessKey"],
                    aws_session_token=saml["Credentials"]["SessionToken"],
                )

                account_id = sts.get_caller_identity().get("Account")
                aws_dict[role.split(":")[4]] = f"{account_id}"

        threads = []
        aws_id_alias = {}
        for role, principal in roles.items():
            t = Thread(target=resolve_aws_alias, args=(role, principal, aws_id_alias))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return aws_id_alias

    @staticmethod
    def is_valid_saml_assertion(saml_xml):
        if saml_xml is None:
            return False

        try:
            doc = ET.fromstring(saml_xml)
            conditions = list(doc.iter(tag="{urn:oasis:names:tc:SAML:2.0:assertion}Conditions"))
            not_before_str = conditions[0].get("NotBefore")
            not_on_or_after_str = conditions[0].get("NotOnOrAfter")

            now = datetime.now(UTC)
            not_before = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
            not_on_or_after = datetime.strptime(not_on_or_after_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)

            return not_before <= now < not_on_or_after
        except Exception:
            return False
