"""Configuration, from environment variables only (12-factor)."""

import os
from dataclasses import dataclass, field

DEFAULT_DB_URL = "postgresql+psycopg:///sast_autofix"  # local socket, OS-user (peer) auth


@dataclass(frozen=True)
class Settings:
    db_url: str = field(default_factory=lambda: os.environ.get("SAST_DB_URL", DEFAULT_DB_URL))
    # Optional. Bearer token the pipeline uses to read finding history without a
    # user session. Unset: machine access is off and only signed-in users can read.
    history_token: str | None = field(default_factory=lambda: os.environ.get("SAST_HISTORY_TOKEN") or None)
    # Fernet key that encrypts integration secrets. Unset: integrations can't be saved.
    secret_key: str | None = field(default_factory=lambda: os.environ.get("SAST_SECRET_KEY") or None)
    # Base URL people reach the dashboard on, for links in notifications.
    public_url: str = field(default_factory=lambda: os.environ.get("SAST_PUBLIC_URL", "http://127.0.0.1:8710"))
    # Optional. Read-only GitHub token for live PR state; without it the
    # dashboard shows PR data as recorded by the pipeline.
    github_token: str | None = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN") or None)
    # Where people's browsers reach Langfuse, for links to a run's trace. Unset: the
    # address in the Langfuse key file. The project id is the one setup.sh creates.
    langfuse_public_url: str | None = field(default_factory=lambda: os.environ.get("SAST_LANGFUSE_PUBLIC_URL") or None)
    langfuse_project_id: str = field(default_factory=lambda: os.environ.get("SAST_LANGFUSE_PROJECT", "sast-autofix"))
    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    # systemd unit of the self-hosted Actions runner, for the health page.
    runner_service: str | None = field(default_factory=lambda: os.environ.get("SAST_RUNNER_SERVICE") or None)
    web_dist: str = field(default_factory=lambda: os.environ.get(
        "SAST_WEB_DIST",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "web", "dist"),
    ))


def get_settings() -> Settings:
    return Settings()
