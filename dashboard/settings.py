"""Configuration, from environment variables only (12-factor)."""

import os
from dataclasses import dataclass, field

DEFAULT_DB_URL = "postgresql+psycopg:///sast_autofix"  # local socket, OS-user (peer) auth


@dataclass(frozen=True)
class Settings:
    db_url: str = field(default_factory=lambda: os.environ.get("SAST_DB_URL", DEFAULT_DB_URL))
    # Optional. Read-only GitHub token for live PR state; without it the
    # dashboard shows PR data as recorded by the pipeline.
    github_token: str | None = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN") or None)
    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    # systemd unit of the self-hosted Actions runner, for the health page.
    runner_service: str | None = field(default_factory=lambda: os.environ.get("SAST_RUNNER_SERVICE") or None)
    web_dist: str = field(default_factory=lambda: os.environ.get(
        "SAST_WEB_DIST",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "web", "dist"),
    ))


def get_settings() -> Settings:
    return Settings()
