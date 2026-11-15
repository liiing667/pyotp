from __future__ import annotations

import calendar
import datetime
import hashlib
import time
from typing import Any

from . import utils
from .exceptions import OTPVerificationError
from .otp import OTP

_TIMESTAMP_LIMIT = 253402300800  # 10000-01-01 00:00:00 UTC, exclusive.


class TOTP(OTP):
    """
    Handler for time-based OTP counters.
    """

    def __init__(
        self,
        s: str,
        *,
        digits: int = 6,
        digest: Any = None,
        name: str | None = None,
        issuer: str | None = None,
        interval: int = 30,
    ) -> None:
        """
        :param s: secret in base32 format
        :param digits: number of digits in the OTP, from 6 to 10
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        :param interval: the time interval in seconds for OTP. This defaults to 30.
        """
        if digest is None:
            digest = hashlib.sha1
        elif digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")

        if interval <= 0:
            raise ValueError("interval must be positive")
        self.interval = interval
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def at(self, for_time: int | float | datetime.datetime, *, counter_offset: int = 0) -> str:
        """
        Accepts a Unix timestamp (int or float) or a datetime object.

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, respecting ``fold``.

        To get the time until the next timecode change (seconds until the current OTP expires), use this instead:

        .. code:: python

            totp = pyotp.TOTP(...)
            time_remaining = totp.interval - time.time() % totp.interval

        :param for_time: the time to generate an OTP for
        :param counter_offset: the amount of ticks to add to the time counter
        :returns: OTP value
        :raises ValueError: if for_time is before the Unix epoch or after year 9999 in UTC
        """
        return self.generate_otp(self.timecode(for_time) + counter_offset)

    def now(self) -> str:
        """
        Generate the current time OTP

        :returns: OTP value
        :raises ValueError: if the current time is before the Unix epoch or after year 9999 in UTC
        """
        return self.generate_otp(self.timecode(time.time()))

    def verify(
        self,
        otp: str,
        *,
        for_time: int | float | datetime.datetime | None = None,
        valid_window: int = 0,
        last_timecode: int | None = None,
    ) -> bool:
        """
        Verifies the OTP passed in against the current time OTP.

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, respecting ``fold``.

        :param otp: the OTP to check against
        :param for_time: Unix timestamp (int or float) or datetime to check OTP at (defaults to now)
        :param valid_window: extends the validity to this many counter ticks before and after the current one
        :param last_timecode: timecode of the last accepted OTP for this credential, as persisted by
            the caller. When provided, an OTP whose matching timecode is not strictly greater than
            this value is rejected, which prevents reuse of an already-consumed timecode. Pass
            ``None`` for a credential that has never authenticated.
        :returns: True if verification succeeded, False otherwise
        :raises ValueError: if for_time is before the Unix epoch or after year 9999 in UTC, if
            valid_window is negative, or if last_timecode is negative
        """
        if for_time is None:
            for_time = time.time()

        if last_timecode is not None and last_timecode < 0:
            raise ValueError("last_timecode cannot be negative")

        try:
            matched_timecode = self._match_timecode(otp, for_time, valid_window)
        except OTPVerificationError:
            return False

        return last_timecode is None or matched_timecode > last_timecode

    def verify_and_get_timecode(
        self,
        otp: str,
        *,
        for_time: int | float | datetime.datetime | None = None,
        valid_window: int = 0,
        last_timecode: int | None = None,
    ) -> int:
        """
        Verifies the OTP passed in against the current time OTP and returns the matching timecode.

        .. caution::

            Note the signature difference between this method and :meth:`verify`:
            this method raises :class:`~pyotp.exceptions.OTPVerificationError`
            on an OTP mismatch, while :meth:`verify` returns ``False``.

        This is useful when callers need to prevent TOTP reuse. An
        application can store the timecode from the last successful
        authentication and reject future OTPs whose matching timecode
        is not greater than the stored one.

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, respecting ``fold``.

        :param otp: the OTP to check against
        :param for_time: Unix timestamp (int or float) or datetime to check OTP at (defaults to now)
        :param valid_window: extends the validity to this counter ticks before and after the current one
        :param last_timecode: timecode of the last accepted OTP for this credential, as persisted by
            the caller. When provided, an OTP whose matching timecode is not strictly greater than
            this value is rejected, which prevents reuse of an already-consumed timecode. Pass
            ``None`` for a credential that has never authenticated.
        :returns: matching timecode if verification succeeded
        :raises pyotp.exceptions.OTPVerificationError: if the OTP does not match within the valid window
        :raises ValueError: if valid_window or last_timecode is negative, or for_time is before the
            Unix epoch or after year 9999 in UTC
        """
        if for_time is None:
            for_time = time.time()

        if last_timecode is not None and last_timecode < 0:
            raise ValueError("last_timecode cannot be negative")

        matched_timecode = self._match_timecode(otp, for_time, valid_window)

        if last_timecode is not None and matched_timecode <= last_timecode:
            raise OTPVerificationError("OTP timecode has already been used")

        return matched_timecode

    def _match_timecode(
        self, otp: str, for_time: int | float | datetime.datetime, valid_window: int
    ) -> int:
        """
        Finds the timecode whose OTP matches the supplied value within the permitted window.

        :raises ValueError: if valid_window is negative
        :raises pyotp.exceptions.OTPVerificationError: if no OTP in the window matches
        """
        if valid_window < 0:
            raise ValueError("valid_window cannot be negative")

        current_timecode = self.timecode(for_time)
        for offset in range(-valid_window, valid_window + 1):
            candidate_timecode = current_timecode + offset
            if candidate_timecode < 0:
                continue
            if utils.strings_equal(str(otp), str(self.generate_otp(candidate_timecode))):
                return candidate_timecode
        raise OTPVerificationError("OTP verification failed")

    def provisioning_uri(self, *, name: str | None = None, issuer_name: str | None = None, **kwargs: Any) -> str:
        """
        Returns the provisioning URI for the OTP.  This can then be
        encoded in a QR Code and used to provision an OTP app like
        Google Authenticator.

        See also:
            https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        """
        return utils.build_uri(
            self.secret,
            name if name else self.name,
            issuer=issuer_name if issuer_name else self.issuer,
            algorithm=self.digest().name,
            digits=self.digits,
            period=self.interval,
            **kwargs,
        )

    def timecode(self, for_time: int | float | datetime.datetime) -> int:
        """
        Converts a Unix timestamp (int or float) or a datetime object
        to the corresponding counter value (timecode).

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, using ``fold`` to
        distinguish repeated clock times. Subsecond precision is ignored.

        :raises ValueError: if for_time is before the Unix epoch or after year 9999 in UTC
        """
        error_message = "for_time must be at or after the Unix epoch and before year 10000 UTC"
        timestamp: int | float
        if isinstance(for_time, datetime.datetime):
            try:
                if for_time.tzinfo:
                    timestamp = calendar.timegm(for_time.utctimetuple())
                else:
                    # Preserve whole-second behavior without discarding fold.
                    timestamp = for_time.replace(microsecond=0).timestamp()
            except (OverflowError, OSError, ValueError) as error:
                raise ValueError(error_message) from error
        else:
            timestamp = for_time
        if not 0 <= timestamp < _TIMESTAMP_LIMIT:
            raise ValueError(error_message)
        return int(int(timestamp) / self.interval)
