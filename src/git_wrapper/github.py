"""Helper utilities for interacting with the GitHub App API."""

from __future__ import annotations

import base64
import binascii
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt
import requests

DEFAULT_HOSTNAME = "api.github.com"
USER_AGENT = "gh-token-py/0.1.0"


class GitHubAppError(RuntimeError):
    """Raised when a GitHub App operation fails."""


def normalize_hostname(hostname: str) -> str:
    """Return a CLI friendly hostname compatible with the GitHub API.

    The Go version accepts hostnames with or without the ``/api/v3`` suffix,
    so this helper mirrors the behaviour by appending the suffix when the user
    targets a GitHub Enterprise instance.
    """

    cleaned = (hostname or DEFAULT_HOSTNAME).strip().lower()
    cleaned = cleaned.rstrip("/")
    if not cleaned:
        cleaned = DEFAULT_HOSTNAME

    if cleaned != DEFAULT_HOSTNAME and "/api/v3" not in cleaned:
        cleaned = f"{cleaned}/api/v3"

    return cleaned.rstrip("/")


def read_private_key(path: str) -> bytes:
    """Load an RSA private key from disk."""

    key_path = Path(path)
    try:
        return key_path.read_bytes()
    except FileNotFoundError as exc:
        raise GitHubAppError(f"Unable to read key file '{path}': file not found") from exc
    except OSError as exc:
        raise GitHubAppError(f"Unable to read key file '{path}': {exc}") from exc


def decode_private_key_base64(encoded_key: str) -> bytes:
    """Decode a base64 encoded RSA private key."""

    try:
        return base64.b64decode(encoded_key.strip())
    except (ValueError, binascii.Error) as exc:  # type: ignore[attr-defined]
        raise GitHubAppError("Unable to decode key from base64") from exc


def generate_jwt(app_id: str, expiry_minutes: int, private_key: bytes) -> str:
    """Generate a JWT signed with the GitHub App's private key."""

    if not app_id:
        raise GitHubAppError("GitHub App ID must be provided")

    if expiry_minutes < 1 or expiry_minutes > 10:
        expiry_minutes = 10

    now = datetime.now(timezone.utc)
    payload = {
        "iat": now - timedelta(seconds=60),
        "exp": now + timedelta(minutes=expiry_minutes),
        "iss": app_id,
    }

    try:
        # PyJWT returns a str when algorithm is asymmetric and key is bytes.
        return jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as exc:  # pragma: no cover - PyJWT wraps multiple errors.
        raise GitHubAppError("Unable to sign JWT") from exc


class GitHubAppClient:
    """HTTP client used to interact with the GitHub App API."""

    hostname: str
    session: requests.Session

    def __init__(self, hostname: str, session: Optional[requests.Session] = None) -> None:
        self.hostname = normalize_hostname(hostname)
        self.session = session or requests.Session()

    def _request(
        self,
        method: str,
        path: str,
        *,
        bearer: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Perform an HTTP request with the headers required by GitHub."""

        url = f"https://{self.hostname}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"

        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=20,
            )
        except requests.RequestException as exc:
            raise GitHubAppError(f"Request to {url} failed: {exc}") from exc

        return response

    def retrieve_default_installation_id(self, jwt_token: str) -> str:
        """Return the first installation ID for the authenticated GitHub App."""

        response = self._request(
            "GET",
            "/app/installations",
            bearer=jwt_token,
            params={"per_page": 1},
        )

        if response.status_code != 200:
            raise GitHubAppError(
                f"Failed retrieving default installation ID: unexpected status {response.status_code}"
            )

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise GitHubAppError("Unable to decode installations response") from exc

        if not isinstance(payload, list) or not payload:
            raise GitHubAppError("No installations found for the GitHub App")

        installation = payload[0]
        installation_id = installation.get("id")
        if installation_id is None:
            raise GitHubAppError("Installation payload missing 'id' field")

        return str(installation_id)

    def generate_installation_token(self, jwt_token: str, installation_id: str) -> Dict[str, Any]:
        """Create an installation access token for the given installation ID."""

        response = self._request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            bearer=jwt_token,
        )

        if response.status_code != 201:
            raise GitHubAppError(
                f"Failed generating installation token: unexpected status {response.status_code}"
            )

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise GitHubAppError("Unable to decode installation token response") from exc

        if not isinstance(payload, dict):
            raise GitHubAppError("Unexpected token response format")

        return payload

    def list_installations(self, jwt_token: str) -> List[Dict[str, Any]]:
        """List all installations associated with the GitHub App."""

        page = 1
        results: List[Dict[str, Any]] = []

        while True:
            response = self._request(
                "GET",
                "/app/installations",
                bearer=jwt_token,
                params={"per_page": 100, "page": page},
            )
            if response.status_code != 200:
                raise GitHubAppError(
                    f"Failed listing installations: unexpected status {response.status_code}"
                )

            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise GitHubAppError("Unable to decode installations response") from exc

            if not isinstance(payload, list):
                raise GitHubAppError("Unexpected installations response format")

            results.extend(payload)

            if len(payload) < 100:
                break

            page += 1
            time.sleep(1)

        return results

    def revoke_installation_token(self, token: str) -> None:
        """Revoke an installation access token."""

        response = self._request(
            "DELETE",
            "/installation/token",
            bearer=token,
        )

        if response.status_code != 204:
            raise GitHubAppError(
                "Token might be invalid or not properly formatted: "
                f"unexpected status {response.status_code}"
            )

    def list_installation_repositories(self, installation_token: str) -> Dict[str, Any]:
        """Return repositories accessible to the installation using its token."""

        response = self._request(
            "GET",
            "/installation/repositories",
            bearer=installation_token,
        )

        if response.status_code != 200:
            raise GitHubAppError(
                "Failed listing installation repositories: "
                f"unexpected status {response.status_code}"
            )

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise GitHubAppError("Unable to decode installation repositories response") from exc

        if not isinstance(payload, dict) or "repositories" not in payload:
            raise GitHubAppError("Unexpected repositories response format")

        return payload
