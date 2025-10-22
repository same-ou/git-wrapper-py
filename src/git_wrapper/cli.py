"""Command line interface mapping to ``git_wrapper.git.Git`` operations."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Tuple

from .git import Git, GitExecutionError, GitWrapperError
from .github import DEFAULT_HOSTNAME
from .token import InstallationTokenManager, TokenProviderError

try:  # Optional dependency group.
    import click
except ImportError:  # pragma: no cover - exercised only without the CLI extra.
    click = None  # type: ignore[assignment]


def _require_cli_dependencies() -> None:
    if click is None:
        message = (
            "git-wrapper CLI dependencies are not installed. "
            "Install them with 'pip install git-wrapper[cli]'."
        )
        print(message, file=sys.stderr)
        raise SystemExit(1)


if click is not None:
    _CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

    def _token_options(func):
        options = [
            click.option(
                "--hostname",
                "-H",
                default=DEFAULT_HOSTNAME,
                show_default=True,
                envvar="GITHUB_API_HOST",
                help="GitHub API hostname. Defaults to api.github.com.",
            ),
            click.option(
                "--installation-id",
                envvar="GITHUB_INSTALLATION_ID",
                help="Installation identifier to use. Defaults to the first installation.",
            ),
            click.option(
                "--base64-key",
                envvar="GITHUB_APP_KEY_B64",
                help="Base64 encoded representation of the private key.",
            ),
            click.option(
                "--key-path",
                type=click.Path(
                    exists=True,
                    file_okay=True,
                    dir_okay=False,
                    readable=True,
                    path_type=Path,
                ),
                envvar="GITHUB_APP_KEY_PATH",
                help="Path to the PEM encoded GitHub App private key.",
            ),
            click.option(
                "--app-id",
                envvar="GITHUB_APP_ID",
                required=True,
                help="GitHub App identifier.",
            ),
        ]
        for option in reversed(options):
            func = option(func)
        return func

    def _create_token_manager(
        app_id: str,
        key_path: Optional[Path],
        base64_key: Optional[str],
        installation_id: Optional[str],
        hostname: str,
    ) -> InstallationTokenManager:
        if (key_path is None) == (base64_key is None):
            raise click.UsageError("Provide either --key-path or --base64-key.")

        try:
            return InstallationTokenManager(
                app_id=app_id,
                key_path=str(key_path) if key_path else None,
                base64_key=base64_key,
                installation_id=installation_id,
                hostname=hostname,
            )
        except TokenProviderError as exc:
            raise click.ClickException(str(exc)) from exc

    def _create_git(
        repo_path: Path,
        *,
        remote: str,
        manager: InstallationTokenManager,
    ) -> Git:
        try:
            return Git(repo_path, token_manager=manager, remote=remote)
        except GitWrapperError as exc:
            raise click.ClickException(str(exc)) from exc

    @click.group(context_settings=_CONTEXT_SETTINGS)
    def _cli() -> None:
        """Execute git-wrapper operations backed by GitHub App tokens."""

    @_cli.command(context_settings=_CONTEXT_SETTINGS)
    @_token_options
    @click.argument("repository")
    @click.argument("destination", type=click.Path(path_type=Path))
    @click.option("--branch", help="Branch to check out.")
    @click.option("--depth", type=int, default=None, help="Limit the history depth passed to git clone.")
    @click.option(
        "--cwd",
        type=click.Path(path_type=Path),
        help="Working directory to execute git clone from.",
    )
    def clone(  # type: ignore[misc]
        repository: str,
        destination: Path,
        branch: Optional[str],
        depth: Optional[int],
        cwd: Optional[Path],
        app_id: str,
        key_path: Optional[Path],
        base64_key: Optional[str],
        installation_id: Optional[str],
        hostname: str,
    ) -> None:
        """Clone a repository with an authenticated installation token."""

        manager = _create_token_manager(app_id, key_path, base64_key, installation_id, hostname)
        try:
            Git.clone(
                repository,
                destination,
                token_manager=manager,
                branch=branch,
                depth=depth,
                cwd=cwd,
            )
            click.echo(f"Repository cloned into {destination}")
        except GitWrapperError as exc:
            raise click.ClickException(str(exc)) from exc

    @_cli.command(context_settings=_CONTEXT_SETTINGS)
    @_token_options
    @click.argument("args", nargs=-1)
    @click.option(
        "--repo",
        "-r",
        default=Path("."),
        type=click.Path(path_type=Path),
        show_default=True,
        help="Path to the git repository.",
    )
    @click.option("--remote", "-R", default="origin", show_default=True, help="Remote name to target.")
    @click.option(
        "--use-token/--no-token",
        default=False,
        show_default=True,
        help="Use the temporary authenticated remote when running the command.",
    )
    @click.option(
        "--check/--no-check",
        default=True,
        show_default=True,
        help="Raise an error when the git command exits with a non-zero status.",
    )
    @click.option(
        "--capture-output",
        is_flag=True,
        help="Capture and display stdout/stderr from the git command.",
    )
    def run(  # type: ignore[misc]
        args: Tuple[str, ...],
        repo: Path,
        remote: str,
        use_token: bool,
        check: bool,
        capture_output: bool,
        app_id: str,
        key_path: Optional[Path],
        base64_key: Optional[str],
        installation_id: Optional[str],
        hostname: str,
    ) -> None:
        """Execute an arbitrary git command."""

        if not args:
            raise click.UsageError("Provide at least one argument to pass to git.")

        manager = _create_token_manager(app_id, key_path, base64_key, installation_id, hostname)
        git = _create_git(repo, remote=remote, manager=manager)

        try:
            result = git.run(
                args,
                use_token=use_token,
                check=check,
                capture_output=capture_output,
            )
        except (GitWrapperError, GitExecutionError) as exc:
            raise click.ClickException(str(exc)) from exc

        if capture_output:
            if result.stdout:
                click.echo(result.stdout, nl=False)
            if result.stderr:
                click.echo(result.stderr, err=True, nl=False)

        raise SystemExit(result.returncode)

    @_cli.command(context_settings=_CONTEXT_SETTINGS)
    @_token_options
    @click.option(
        "--repo",
        "-r",
        default=Path("."),
        type=click.Path(path_type=Path),
        show_default=True,
        help="Path to the git repository.",
    )
    @click.option("--remote", "-R", default="origin", show_default=True, help="Remote name to target.")
    @click.option("--branch", help="Branch to pull.")
    def pull(  # type: ignore[misc]
        repo: Path,
        remote: str,
        branch: Optional[str],
        app_id: str,
        key_path: Optional[Path],
        base64_key: Optional[str],
        installation_id: Optional[str],
        hostname: str,
    ) -> None:
        """Run git pull with temporary authentication."""

        manager = _create_token_manager(app_id, key_path, base64_key, installation_id, hostname)
        git = _create_git(repo, remote=remote, manager=manager)

        try:
            git.pull(branch=branch)
            click.echo("Pull completed successfully.")
        except GitWrapperError as exc:
            raise click.ClickException(str(exc)) from exc

    @_cli.command(context_settings=_CONTEXT_SETTINGS)
    @_token_options
    @click.argument("refspecs", nargs=-1)
    @click.option(
        "--repo",
        "-r",
        default=Path("."),
        type=click.Path(path_type=Path),
        show_default=True,
        help="Path to the git repository.",
    )
    @click.option("--remote", "-R", default="origin", show_default=True, help="Remote name to target.")
    def fetch(  # type: ignore[misc]
        refspecs: Tuple[str, ...],
        repo: Path,
        remote: str,
        app_id: str,
        key_path: Optional[Path],
        base64_key: Optional[str],
        installation_id: Optional[str],
        hostname: str,
    ) -> None:
        """Run git fetch with temporary authentication."""

        manager = _create_token_manager(app_id, key_path, base64_key, installation_id, hostname)
        git = _create_git(repo, remote=remote, manager=manager)

        try:
            git.fetch(*refspecs)
            click.echo("Fetch completed successfully.")
        except GitWrapperError as exc:
            raise click.ClickException(str(exc)) from exc

    @_cli.command(context_settings=_CONTEXT_SETTINGS)
    @_token_options
    @click.argument("refspecs", nargs=-1)
    @click.option(
        "--repo",
        "-r",
        default=Path("."),
        type=click.Path(path_type=Path),
        show_default=True,
        help="Path to the git repository.",
    )
    @click.option("--remote", "-R", default="origin", show_default=True, help="Remote name to target.")
    @click.option("--force", is_flag=True, help="Force push the provided refspecs.")
    def push(  # type: ignore[misc]
        refspecs: Tuple[str, ...],
        repo: Path,
        remote: str,
        force: bool,
        app_id: str,
        key_path: Optional[Path],
        base64_key: Optional[str],
        installation_id: Optional[str],
        hostname: str,
    ) -> None:
        """Run git push with temporary authentication."""

        manager = _create_token_manager(app_id, key_path, base64_key, installation_id, hostname)
        git = _create_git(repo, remote=remote, manager=manager)

        try:
            git.push(*refspecs, force=force)
            click.echo("Push completed successfully.")
        except GitWrapperError as exc:
            raise click.ClickException(str(exc)) from exc
else:
    _cli = None


def main() -> None:
    """Entry-point used by console_scripts."""

    _require_cli_dependencies()
    assert _cli is not None  # For type-checkers.
    _cli()


__all__ = ["main"]
