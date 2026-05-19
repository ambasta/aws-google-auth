FROM python:3.14-alpine

RUN apk add --update-cache ca-certificates libusb-dev build-base \
                           eudev-dev linux-headers libffi-dev openssl-dev

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock README.rst LICENSE.txt /build/
COPY aws_google_auth /build/aws_google_auth
RUN uv pip install --system /build/[u2f]

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["aws-google-auth"]
