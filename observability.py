"""Optional tracing of every AI call to a self-hosted Langfuse.

Why OpenTelemetry and not the Langfuse SDK: the SDK needs OpenTelemetry 1.45
or newer, and Semgrep (which the pipeline runs) pins 1.37 in this environment.
Langfuse's server accepts standard OTLP traces and maps the GenAI attributes
to generations with token usage, so this uses the OpenTelemetry packages that
are already installed and adds nothing that could break Semgrep.

Privacy, because prompts contain the client's source code:
  * a Langfuse Cloud host is refused unless `allow_cloud` is set explicitly;
  * `capture_content: false` sends only metadata (model, tokens, timings,
    purpose), never the prompt or the reply;
  * a missing key, an unreachable server or any tracing error turns tracing
    off. It never fails or slows a scan.
"""

import base64
import json
import os
import sys
import time
from contextlib import contextmanager
from urllib.parse import urlparse

import httpx

CLOUD_DOMAINS = ("langfuse.com",)
HEALTH_TIMEOUT = 3.0
OTLP_PATH = "/api/public/otel/v1/traces"


def is_cloud(host: str) -> bool:
    name = (urlparse(host).hostname or "").lower()
    return any(name == d or name.endswith("." + d) for d in CLOUD_DOMAINS)


def _warn(message: str) -> None:
    print(f"[langfuse] {message}", file=sys.stderr, flush=True)


class NullTracer:
    """Does nothing. What every run gets unless Langfuse is configured."""

    enabled = False

    @contextmanager
    def run(self, **kwargs):
        yield

    def generation(self, **kwargs):
        return None

    def span(self, **kwargs):
        return None

    def flush(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


class LangfuseTracer:
    enabled = True

    def __init__(self, host: str, public_key: str, secret_key: str,
                 capture_content: bool = True, exporter=None, processor="batch"):
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

        self._trace = trace
        self.host = host.rstrip("/")
        self.capture_content = capture_content
        if exporter is None:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            token = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
            exporter = OTLPSpanExporter(
                endpoint=self.host + OTLP_PATH,
                headers={"Authorization": f"Basic {token}", "x-langfuse-ingestion-version": "4"},
                timeout=10,
            )
        # Our own provider, never the global one: Semgrep sets up its own.
        self.provider = TracerProvider(resource=Resource.create({"service.name": "sast-autofix"}))
        self.provider.add_span_processor(
            SimpleSpanProcessor(exporter) if processor == "simple" else BatchSpanProcessor(exporter)
        )
        self._tracer = self.provider.get_tracer("sast-autofix")
        self._root = None

    # -- structure: one trace per pipeline run, one child per AI call ----------

    @contextmanager
    def run(self, name: str, session_id: str | None = None, tags=(), metadata=None, **_):
        attrs = {"langfuse.observation.type": "span", "langfuse.trace.name": name}
        if session_id:
            attrs["langfuse.session.id"] = str(session_id)
        if tags:
            attrs["langfuse.trace.tags"] = [str(t) for t in tags]
        for key, value in (metadata or {}).items():
            attrs[f"langfuse.trace.metadata.{key}"] = str(value)
        try:
            self._root = self._tracer.start_span(name, attributes=attrs)
        except Exception as exc:
            _warn(f"could not start a trace ({exc}); continuing without tracing")
            self._root = None
        try:
            yield
        finally:
            try:
                if self._root is not None:
                    self._root.end()
            except Exception:
                pass
            self._root = None

    def _context(self):
        return self._trace.set_span_in_context(self._root) if self._root is not None else None

    def _emit(self, name, attrs, start_ns, end_ns, error=None):
        """Send one span. Returns (trace_id, span_id) as the hex strings Langfuse
        shows them under, or None if it could not be sent."""
        try:
            span = self._tracer.start_span(name, context=self._context(),
                                           start_time=start_ns, attributes=attrs)
            span.end(end_time=end_ns)
            ctx = span.get_span_context()
            return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")
        except Exception as exc:  # tracing must never break a scan
            _warn(f"dropped a span ({exc})")
            return None

    def generation(self, name, model, start_ns, end_ns, prompt_tokens=None, completion_tokens=None,
                   input=None, output=None, ok=True, error=None, metadata=None, parameters=None, **_):
        attrs = {"langfuse.observation.type": "generation", "gen_ai.request.model": model,
                 "langfuse.observation.model.name": model}
        usage = {}
        if prompt_tokens is not None:
            usage["input"] = prompt_tokens
            attrs["gen_ai.usage.input_tokens"] = prompt_tokens
        if completion_tokens is not None:
            usage["output"] = completion_tokens
            attrs["gen_ai.usage.output_tokens"] = completion_tokens
        if usage:
            usage["total"] = usage.get("input", 0) + usage.get("output", 0)
            attrs["langfuse.observation.usage_details"] = json.dumps(usage)
        if parameters:
            attrs["langfuse.observation.model.parameters"] = json.dumps(parameters)
        if self.capture_content:
            if input is not None:
                attrs["langfuse.observation.input"] = input
            if output is not None:
                attrs["langfuse.observation.output"] = output
        if not ok:
            attrs["langfuse.observation.level"] = "ERROR"
            attrs["langfuse.observation.status_message"] = str(error or "failed")[:500]
        for key, value in (metadata or {}).items():
            if value is not None:
                attrs[f"langfuse.observation.metadata.{key}"] = str(value)
        return self._emit(name, attrs, start_ns, end_ns)

    def span(self, name, start_ns, end_ns, ok=True, error=None, metadata=None, **_):
        attrs = {"langfuse.observation.type": "span"}
        if not ok:
            attrs["langfuse.observation.level"] = "ERROR"
            attrs["langfuse.observation.status_message"] = str(error or "failed")[:500]
        for key, value in (metadata or {}).items():
            if value is not None:
                attrs[f"langfuse.observation.metadata.{key}"] = str(value)
        return self._emit(name, attrs, start_ns, end_ns)

    def flush(self) -> None:
        try:
            self.provider.force_flush(timeout_millis=15000)
        except Exception as exc:
            _warn(f"flush failed ({exc})")

    def shutdown(self) -> None:
        try:
            self.provider.shutdown()
        except Exception:
            pass


KEY_FILE = os.path.expanduser("~/.config/sast-autofix/langfuse.env")


def read_key_file(path: str = KEY_FILE) -> dict:
    """KEY=VALUE pairs from a private file, so a CI runner finds the Langfuse
    keys without a restart. Refused unless only its owner can read it."""
    try:
        info = os.stat(path)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            _warn(f"{path} must be owned by you and mode 600; ignoring it")
            return {}
        values = {}
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip().strip('"').strip("'")
        return values
    except OSError:
        return {}


def server_reachable(host: str) -> bool:
    try:
        return httpx.get(host.rstrip("/") + "/api/public/health", timeout=HEALTH_TIMEOUT).status_code == 200
    except httpx.HTTPError:
        return False


def from_config(cfg, env=None, key_file=KEY_FILE):
    """A tracer for this run: Langfuse when it is switched on and safe, else a
    no-op. Never raises. Settings come from the environment first, then from the
    private key file."""
    env = os.environ if env is None else env
    try:
        if getattr(cfg, "langfuse_enabled", False) is not True:
            return NullTracer()
        stored = read_key_file(key_file)
        get = lambda name: env.get(name) or stored.get(name)  # noqa: E731
        host = get("LANGFUSE_HOST") or cfg.langfuse_host
        public, secret = get("LANGFUSE_PUBLIC_KEY"), get("LANGFUSE_SECRET_KEY")
        if not (public and secret):
            _warn("enabled, but LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY are not set; tracing is off")
            return NullTracer()
        if is_cloud(host) and not cfg.langfuse_allow_cloud:
            _warn(f"{host} is Langfuse Cloud. Prompts contain your source code, so tracing is off. "
                  "Self-host Langfuse, or set allow_cloud: true if you accept that.")
            return NullTracer()
        if not server_reachable(host):
            _warn(f"{host} is not reachable; tracing is off for this run")
            return NullTracer()
        tracer = LangfuseTracer(host, public, secret, capture_content=cfg.langfuse_capture_content)
        _warn(f"tracing to {host}" + ("" if cfg.langfuse_capture_content else " (metadata only, no prompts)"))
        return tracer
    except Exception as exc:
        _warn(f"could not start ({exc}); tracing is off")
        return NullTracer()


def now_ns() -> int:
    return time.time_ns()
