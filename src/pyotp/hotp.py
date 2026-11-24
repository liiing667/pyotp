from __future__ import annotations

import hashlib
from typing import Any

from . import utils
from .exceptions import OTPVerificationError
from .otp import OTP


class HOTP(OTP):
    """
    Handler for HMAC-based OTP counters.
    """

    def __init__(
        self,
        s: str,
        *,
        digits: int = 6,
        digest: Any = None,
        name: str | None = None,
        issuer: str | None = None,
        initial_count: int = 0,
    ) -> None:
        """
        :param s: secret in base32 format
        :param initial_count: starting HMAC counter value, defaults to 0
        :param digits: number of digits in the OTP, from 6 to 10
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        """
        if digest is None:
            digest = hashlib.sha1
        elif digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")

        self.initial_count = initial_count
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def at(self, count: int) -> str:
        """
        Generates the OTP for the given count.

        :param count: the OTP HMAC counter
        :returns: OTP
        """
        return self.generate_otp(self.initial_count + count)

    def verify(self, otp: str, counter: int, *, look_ahead_window: int = 0) -> bool:
        """
        Verifies the OTP against the given counter and its bounded look-ahead window.

        This method is stateless: it does not advance any counter and can accept the same OTP more
        than once. Use :meth:`verify_and_advance` to obtain the next counter that must be persisted
        for replay protection.

        :param otp: the OTP to check against
        :param counter: the current OTP counter relative to ``initial_count``
        :param look_ahead_window: number of counters after ``counter`` that are also accepted
        :returns: True if verification succeeded, False otherwise
        :raises ValueError: if ``counter`` or ``look_ahead_window`` is invalid
        """
        try:
            self.verify_and_advance(otp, counter, look_ahead_window=look_ahead_window)
        except OTPVerificationError:
            return False
        return True

    def verify_and_advance(self, otp: str, counter: int, *, look_ahead_window: int = 0) -> int:
        """
        Verifies the OTP and returns the next counter to persist.

        .. caution::

            Note the signature difference between this method and :meth:`verify`:
            this method raises :class:`~pyotp.exceptions.OTPVerificationError`
            on an OTP mismatch, while :meth:`verify` returns ``False``.

        On a successful match at counter ``C`` (with
        ``counter <= C <= counter + look_ahead_window``), this method returns
        ``C + 1``. Persist the returned value and supply it as ``counter`` on
        the next verification; reused or out-of-order counters can then never
        pass again. If persisting the returned value fails, do not replace the
        previously stored counter, so it remains unchanged for a retry.

        :param otp: the OTP to check against
        :param counter: the current OTP counter relative to ``initial_count``
        :param look_ahead_window: number of counters after ``counter`` that are also accepted
        :returns: the next counter value to persist (the matching relative counter plus one)
        :raises pyotp.exceptions.OTPVerificationError: if the OTP does not match a permitted counter
        :raises ValueError: if ``counter`` or ``look_ahead_window`` is invalid
        """
        if counter < 0:
            raise ValueError("counter cannot be negative")
        if look_ahead_window < 0:
            raise ValueError("look_ahead_window cannot be negative")

        for candidate in range(counter, counter + look_ahead_window + 1):
            if utils.strings_equal(str(otp), str(self.at(candidate))):
                return candidate + 1

        raise OTPVerificationError("OTP verification failed")

    def provisioning_uri(
        self,
        *,
        name: str | None = None,
        initial_count: int | None = None,
        issuer_name: str | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Returns the provisioning URI for the OTP.  This can then be
        encoded in a QR Code and used to provision an OTP app like
        Google Authenticator.

        See also:
            https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        :param name: name of the user account
        :param initial_count: starting HMAC counter value, defaults to 0
        :param issuer_name: the name of the OTP issuer; this will be the
            organization title of the OTP entry in Authenticator
        :returns: provisioning URI
        """
        return utils.build_uri(
            self.secret,
            name=name if name else self.name,
            initial_count=initial_count if initial_count is not None else self.initial_count,
            issuer=issuer_name if issuer_name else self.issuer,
            algorithm=self.digest().name,
            digits=self.digits,
            **kwargs,
        )
