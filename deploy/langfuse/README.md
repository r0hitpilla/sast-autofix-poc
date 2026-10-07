# Langfuse: tracing every AI call

A private [Langfuse](https://langfuse.com) on this machine records every model
call the pipeline makes: model, purpose (triage, fix, review, proof, Laya...),
tokens, time, and optionally the prompt and reply. One trace per CI run.

Prompts contain the client's source code, so this is **self-hosted only**. The
tool refuses a Langfuse Cloud address unless `allow_cloud: true` is set.

## Start it

    deploy/langfuse/setup.sh

This creates, once and never overwriting:

| File | What | Mode |
|---|---|---|
| `deploy/langfuse/.env` | container secrets and the UI login | 600, not committed |
| `~/.config/sast-autofix/langfuse.env` | host and API keys the pipeline reads | 600 |

then starts the stack on **http://127.0.0.1:3000**. Only that port is
published, and only on localhost; Postgres, ClickHouse, Redis and MinIO stay
inside Docker's network. Anonymous usage telemetry and public sign-up are off.

UI login: `admin@sast-autofix.local`; the password is in `deploy/langfuse/.env`
(`LANGFUSE_INIT_USER_PASSWORD`). To see it from another machine use an SSH
tunnel: `ssh -L 3000:127.0.0.1:3000 <this machine>`.

## Turn it on or off

`config.yaml`:

    observability:
      langfuse:
        enabled: true            # false: nothing is sent
        host: http://127.0.0.1:3000
        allow_cloud: false       # keep false
        capture_content: true    # false: send tokens, timings and purpose only, never prompts

A missing key, an unreachable server or any tracing error switches tracing
off for that run. It never fails or slows a scan. Token counts also go into
every run report and the dashboard's Models page whether or not Langfuse runs.

## Why OpenTelemetry and not the Langfuse SDK

The SDK needs OpenTelemetry 1.45 or newer; Semgrep, which the pipeline runs,
pins 1.37 in this environment. The pipeline sends standard OTLP traces to
Langfuse's `/api/public/otel` endpoint with the OpenTelemetry packages already
installed.

## Maintenance

    cd deploy/langfuse
    docker compose --env-file .env ps            # state
    docker compose --env-file .env logs -f langfuse-web
    docker compose --env-file .env down          # stop (data is kept in volumes)
    docker compose --env-file .env down -v       # stop and DELETE all traces

`official-compose.yml` is Langfuse's own file, pinned here; `docker-compose.yml`
is generated from it by `make_compose.py`. To upgrade, replace
`official-compose.yml` with a newer one and rerun `setup.sh`.

Langfuse 4 serves reads from `/api/public/v2/observations`; the older
`/api/public/traces` is not available in its default mode.
