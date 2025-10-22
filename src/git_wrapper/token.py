"""Token management helpers for authenticated Git operations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .github import (
    DEFAULT_HOSTNAME,
    GitHubAppClient,
    GitHubAppError,
    decode_private_key_base64,
    generate_jwt,
    read_private_key,
)

TokenPayload = Dict[str, Any]


class TokenProviderError(RuntimeError):
    """Raised when generating or refreshing a GitHub installation token fails."""


def _parse_expiration(timestamp: str) -> datetime:
    """Convert an ISO formatted timestamp from the GitHub API into a datetime."""

    try:
        normalized = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError as exc:  # pragma: no cover - defensive branch
        raise TokenProviderError("Installation token payload includes invalid expires_at value") from exc


class InstallationTokenManager:
    """Generate and cache GitHub App installation tokens.

    The manager mirrors the ``gh-token`` CLI ``generate`` command behaviour whilst keeping
    the original module untouched. Tokens are refreshed automatically when they are close to
    expiring to avoid mid-command authentication failures.
    """

    _app_id: str
    _installation_id: Optional[str]
    _hostname: str
    _private_key: bytes
    _client: GitHubAppClient
    _jwt_duration: int
    _refresh_slack: timedelta

    _cached_token: Optional[str]
    _cached_payload: Optional[TokenPayload]
    _cached_expiry: Optional[datetime]

    def __init__(
        self,
        *,
        app_id: str,
        key_path: Optional[str] = None,
        base64_key: Optional[str] = None,
        installation_id: Optional[str] = None,
        hostname: str = DEFAULT_HOSTNAME,
        client: Optional[GitHubAppClient] = None,
        jwt_duration: int = 10,
        refresh_slack: timedelta = timedelta(minutes=1),
    ) -> None:
        if not app_id:
            raise TokenProviderError("GitHub App ID must be provided")
        if bool(key_path) == bool(base64_key):
            raise TokenProviderError("Either key_path or base64_key must be supplied")

        self._app_id = app_id
        self._installation_id = installation_id
        self._hostname = hostname or DEFAULT_HOSTNAME
        self._client = client or GitHubAppClient(self._hostname)
        self._jwt_duration = jwt_duration
        self._refresh_slack = refresh_slack

        try:
            if key_path:
                self._private_key = read_private_key(key_path)
            else:
                assert base64_key is not None  # For type-checkers.
                self._private_key = decode_private_key_base64(base64_key)
        except GitHubAppError as exc:
            raise TokenProviderError(str(exc)) from exc

        self._cached_token = None
        self._cached_payload = None
        self._cached_expiry = None

    def get_token(self, *, force_refresh: bool = False) -> str:
        """Return a valid installation token, refreshing it when required."""

        if not force_refresh and self._cached_token and self._cached_expiry:
            now = datetime.now(timezone.utc)
            if now + self._refresh_slack < self._cached_expiry:
                return self._cached_token

        self._refresh_token()
        assert self._cached_token is not None  # For mypy.
        return self._cached_token

    def get_token_payload(self) -> TokenPayload:
        """Return the full payload associated with the cached token."""

        if not self._cached_payload:
            self._refresh_token()
        assert self._cached_payload is not None  # For mypy.
        return dict(self._cached_payload)

    def resolved_installation_id(self) -> str:
        """Return the installation ID used when generating tokens."""

        if not self._installation_id:
            self._refresh_token()
        assert self._installation_id is not None
        return self._installation_id

    def _refresh_token(self) -> None:
        """Generate a new installation token and update cached state."""

        try:
            jwt_token = generate_jwt(self._app_id, self._jwt_duration, self._private_key)

            installation_id = self._installation_id
            if not installation_id:
                installation_id = self._client.retrieve_default_installation_id(jwt_token)

            payload = self._client.generate_installation_token(jwt_token, installation_id)
        except GitHubAppError as exc:
            raise TokenProviderError(str(exc)) from exc

        token_value = payload.get("token")
        expiry_raw = payload.get("expires_at")
        if token_value is None:
            raise TokenProviderError("Installation token payload missing 'token'")
        if expiry_raw is None:
            raise TokenProviderError("Installation token payload missing 'expires_at'")

        expiry = _parse_expiration(str(expiry_raw))

        self._installation_id = str(installation_id)
        self._cached_token = str(token_value)
        self._cached_payload = dict(payload)
        self._cached_expiry = expiry
