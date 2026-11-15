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
        Verifies the OTP passed in against the OTP of the given counter.

        This method is stateless: it does not advance any counter and can therefore accept the same
        OTP more than once. To enforce single-use semantics, persist the counter returned by
        :meth:`verify_and_advance` and reject any counter that does not move forward.

        :param otp: the OTP to check against
        :param counter: the OTP HMAC counter
        :param look_ahead_window: number of counters after ``counter`` that are also accepted,
            bounded to prevent unbounded counter searches. Defaults to 0, which accepts only the
            OTP for ``counter`` itself.
        :returns: True if the OTP matches any counter in the permitted window, False otherwise
        :raises ValueError: if counter or look_ahead_window is negative
        """
        if counter < 0:
            raise ValueError("counter cannot be negative")
        if look_ahead_window < 0:
            raise ValueError("look_ahead_window cannot be negative")

        for candidate in range(counter, counter + look_ahead_window + 1):
            if utils.strings_equal(str(otp), str(self.at(candidate))):
                return True
        return False

    def verify_and_advance(self, otp: str, counter: int, *, look_ahead_window: int = 0) -> int:
        """
        Verifies the OTP against the given counter and returns the next counter to persist.

        The ``counter`` argument is the current counter stored for this credential. On a successful
        match at counter ``C`` (with ``counter <= C <= counter + look_ahead_window``), this method
        returns ``C + 1``. Persist the returned value and supply it as ``counter`` on the next
        verification: an OTP whose counter is not strictly greater than the previously accepted one
        can then never pass again, which prevents replay and out-of-order reuse.

        :param otp: the OTP to check against
        :param counter: the currently persisted OTP HMAC counter
        :param look_ahead_window: number of counters after ``counter`` that are also accepted,
            bounded to prevent unbounded counter searches. Defaults to 0, which accepts only the
            OTP for ``counter`` itself.
        :returns: the next counter value to persist (matching counter plus one)
        :raises pyotp.exceptions.OTPVerificationError: if the OTP does not match any counter in
            the permitted window
        :raises ValueError: if counter or look_ahead_window is negative
        """
        if counter < 0:
            raise ValueError("counter cannot be negative")
        if look_ahead_window < 0:
            raise ValueError("look_ahead_window cannot be negative")

        for offset in range(look_ahead_window + 1):
            candidate = counter + offset
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
