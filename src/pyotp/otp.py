from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import Any

_BASE32_SECRET_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwxyz=")


def normalize_secret(secret: str | bytes) -> str:
    """
    Normalizes a base32 secret by removing spaces and hyphens, which are
    commonly used to group characters when secrets are displayed or copied.
    """
    if isinstance(secret, bytes):
        secret = secret.decode("ascii")
    return secret.replace(" ", "").replace("-", "")


class OTP:
    """
    Base class for OTP handlers.
    """

    def __init__(
        self,
        s: str,
        *,
        digits: int = 6,
        digest: Any = hashlib.sha1,
        name: str | None = None,
        issuer: str | None = None,
    ) -> None:
        self.digits = digits
        if not 6 <= digits <= 10:
            raise ValueError("digits must be between 6 and 10")
        self.digest = digest
        if digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")
        self.secret = normalize_secret(s)
        self.name = name or "Secret"
        self.issuer = issuer

    def generate_otp(self, input: int) -> str:
        """
        :param input: the HMAC counter value to use as the OTP input.
            Usually either the counter, or the computed integer based on the Unix timestamp
        """
        if input < 0:
            raise ValueError("input must be positive integer")
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
        if hasher.digest_size < 18:
            raise ValueError("digest size is lower than 18 bytes, which will trigger error on otp generation")
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        str_code = str(10_000_000_000 + (code % 10**self.digits))
        return str_code[-self.digits :]

    def byte_secret(self) -> bytes:
        secret = normalize_secret(self.secret)
        if any(char not in _BASE32_SECRET_CHARS for char in secret):
            raise ValueError("secret contains characters that are not valid base32")
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)
        try:
            decoded = base64.b32decode(secret, casefold=True)
        except binascii.Error as error:
            raise ValueError("secret is not valid base32") from error
        if len(decoded) < 10:
            raise ValueError("Secrets must be at least 80 bits after decoding")
        return decoded

    @staticmethod
    def int_to_bytestring(i: int, *, padding: int = 8) -> bytes:
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(reversed(result.ljust(padding, b"\0")))
