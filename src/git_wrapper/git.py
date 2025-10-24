"""Minimal git wrapper that injects GitHub App installation tokens."""

from __future__ import annotations

import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Union
from urllib.parse import urlsplit, urlunsplit

from .token import InstallationTokenManager


class GitWrapperError(RuntimeError):
    """Raised when preparing or executing git commands fails."""


class GitExecutionError(GitWrapperError):
    """Raised when a git command exits with a non-zero code."""

    def __init__(
        self,
        command: Sequence[str],
        returncode: int,
        stdout: Optional[str],
        stderr: Optional[str],
    ) -> None:
        message = "git command '{cmd}' failed with exit code {code}".format(
            cmd=" ".join(command),
            code=returncode,
        )
        if stderr:
            message = f"{message}: {stderr.strip()}"
        super().__init__(message)
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _inject_token_into_url(remote_url: str, token: str) -> str:
    """Return the remote URL with the installation token embedded."""

    parts = urlsplit(remote_url)
    if parts.scheme != "https":
        raise GitWrapperError("Token authentication requires an https remote URL")

    netloc = parts.netloc.split("@")[-1]
    authed_netloc = f"x-access-token:{token}@{netloc}"
    return urlunsplit((parts.scheme, authed_netloc, parts.path, parts.query, parts.fragment))


class Git:
    """Execute git commands with temporary token-based authentication."""

    def __init__(
        self,
        repo_path: Union[str, Path],
        *,
        token_manager: InstallationTokenManager,
        remote: str = "origin",
    ) -> None:
        self._repo_path = Path(repo_path).resolve()
        if not (self._repo_path / ".git").exists():
            raise GitWrapperError(f"{self._repo_path} is not a git repository")

        self._token_manager = token_manager
        self._remote = remote

    @classmethod
    def clone(
        cls,
        repository: str,
        destination: Union[str, Path],
        *,
        token_manager: InstallationTokenManager,
        branch: Optional[str] = None,
        depth: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        options: Optional[Sequence[str]] = None,
    ) -> None:
        """Clone the repository using a temporary installation token."""

        authed_url = _inject_token_into_url(repository, token_manager.get_token())
        git_args: List[str] = ["clone", *(str(opt) for opt in options or ())]

        if branch:
            git_args.extend(["--branch", branch])
        if depth:
            git_args.extend(["--depth", str(depth)])

        git_args.extend([authed_url, str(destination)])
        _run_git(git_args, cwd=Path(cwd) if cwd else None)

    def run(
        self,
        args: Iterable[str],
        *,
        use_token: bool = False,
        check: bool = True,
        capture_output: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Run an arbitrary git command within the repository."""

        git_args = [str(arg) for arg in args]
        if not use_token:
            return _run_git(
                git_args,
                cwd=self._repo_path,
                check=check,
                capture_output=capture_output,
            )

        token = self._token_manager.get_token()
        with self._temporary_remote(token):
            return _run_git(
                git_args,
                cwd=self._repo_path,
                check=check,
                capture_output=capture_output,
            )

    def pull(self, *options: str, branch: Optional[str] = None) -> None:
        """Run ``git pull`` with token-authenticated remote access."""

        args = ["pull", *options, self._remote]
        if branch:
            args.append(branch)
        self.run(args, use_token=True)

    def fetch(self, *args: str) -> None:
        """Run ``git fetch`` against the configured remote."""

        command = ["fetch", self._remote, *(str(arg) for arg in args)]
        self.run(command, use_token=True)

    def push(self, *args: str, force: bool = False) -> None:
        """Run ``git push`` with an authenticated remote."""

        command = ["push", self._remote]
        if force:
            command.append("--force")
        command.extend(str(arg) for arg in args)
        self.run(command, use_token=True)

    @contextmanager
    def _temporary_remote(self, token: str):
        """Temporarily update the remote URL to include the installation token."""

        original_url = self._get_remote_url()
        authed_url = _inject_token_into_url(original_url, token)

        if authed_url == original_url:
            yield
            return

        self._set_remote_url(authed_url)
        try:
            yield
        finally:
            self._set_remote_url(original_url)

    def _get_remote_url(self) -> str:
        """Return the current remote URL."""

        result = _run_git(
            ["remote", "get-url", self._remote],
            cwd=self._repo_path,
            capture_output=True,
        )
        if result.stdout is None:
            raise GitWrapperError(f"Unable to determine URL for remote '{self._remote}'")
        remote_url = result.stdout.strip()
        if not remote_url:
            raise GitWrapperError(f"Remote '{self._remote}' is not configured with a URL")
        return remote_url

    def _set_remote_url(self, url: str) -> None:
        """Update the remote URL."""

        _run_git(
            ["remote", "set-url", self._remote, url],
            cwd=self._repo_path,
        )


def _run_git(
    git_args: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute a git command and optionally return the captured output."""

    command = ["git", *map(str, git_args)]
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture_output,
        check=False,
    )

    if check and result.returncode != 0:
        raise GitExecutionError(command, result.returncode, result.stdout, result.stderr)

    return result
