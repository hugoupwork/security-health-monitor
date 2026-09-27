#!/usr/bin/env python3
"""Independent security-health monitor. Standard library only; no host administration."""
from datetime import datetime, timezone
from contextlib import contextmanager
import json
import os
import re
import signal
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

CHECKS = frozenset({"collector_fresh", "webhook_running", "private_alert_worker_fresh",
                    "coverage_current", "backup_fresh"})
NAMES = {"collector_fresh": "health collector freshness", "webhook_running": "webhook availability",
         "private_alert_worker_fresh": "private alert worker freshness",
         "coverage_current": "security coverage freshness", "backup_fresh": "backup freshness"}
TITLES = {"production": "Security monitor state: production", "test": "Security monitor state: test"}


class MonitorError(Exception):
    """Codes only. Never format a URL, response body or credential into logs."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise MonitorError("redirect_rejected")


def utc_now():
    return datetime.now(timezone.utc)


def stamp(now=None):
    return (now or utc_now()).isoformat().replace("+00:00", "Z")


def parse_utc(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
        raise MonitorError("invalid_timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise MonitorError("invalid_timestamp") from None


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MonitorError("duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(MonitorError("invalid_json_number")))
    except (ValueError, UnicodeError):
        raise MonitorError("invalid_json") from None


def validate_health_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None
                or parsed.path != "/security-health.json" or parsed.query or parsed.fragment
                or any(char.isspace() or ord(char) < 32 for char in value)
                or "\\" in value):
            raise ValueError()
    except (ValueError, TypeError):
        raise MonitorError("invalid_health_configuration") from None
    return value


@contextmanager
def deadline(seconds):
    """Bound total network time, including DNS and a slow response body, on Linux/macOS."""
    def expired(*_):
        raise MonitorError("request_timeout")
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, expired)
    prior_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if prior_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, *prior_timer)


def request_json(url, *, method="GET", headers=None, payload=None, limit=4096, timeout=10):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request_headers = {"Accept": "application/json", "User-Agent": "independent-security-monitor/1"}
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    request_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with deadline(timeout), opener.open(req, timeout=timeout) as response:
            if response.geturl() != url or not 200 <= response.status < 300:
                raise MonitorError("unexpected_http_response")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > limit):
                raise MonitorError("response_too_large")
            body = response.read(limit + 1)
    except MonitorError:
        raise
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout, OSError):
        raise MonitorError("request_failed") from None
    if len(body) > limit:
        raise MonitorError("response_too_large")
    return strict_json(body)


def assess_health(value, now=None):
    if not isinstance(value, dict) or set(value) != {"schema_version", "generated_at_utc", "ok", "checks"}:
        raise MonitorError("invalid_health_schema")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or type(value["ok"]) is not bool:
        raise MonitorError("invalid_health_schema")
    checks = value["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECKS or any(type(v) is not bool for v in checks.values()):
        raise MonitorError("invalid_health_schema")
    age = ((now or utc_now()) - parse_utc(value["generated_at_utc"])).total_seconds()
    if not -60 <= age <= 300:
        return False, "health publication freshness"
    if value["ok"] != all(checks.values()):
        raise MonitorError("inconsistent_health_schema")
    failed = [NAMES[name] for name in sorted(CHECKS) if not checks[name]]
    return not failed, ", ".join(failed)


def new_state(namespace):
    return {"schema_version": 1, "namespace": namespace, "health": "unknown", "sequence": 0,
            "updated_at_utc": stamp(), "notification": None}


def validate_state(value, namespace):
    if (not isinstance(value, dict) or set(value) != {"schema_version", "namespace", "health", "sequence", "updated_at_utc", "notification"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["namespace"] != namespace or value["health"] not in {"unknown", "healthy", "unhealthy"}
            or type(value["sequence"]) is not int or value["sequence"] < 0):
        raise MonitorError("invalid_state")
    parse_utc(value["updated_at_utc"])
    notice = value["notification"]
    if notice is not None:
        if (not isinstance(notice, dict) or set(notice) != {"transition_id", "kind", "delivery", "claimed_at_utc", "completed_at_utc"}
                or not isinstance(notice["transition_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", notice["transition_id"])
                or notice["kind"] not in {"failure", "recovery"} or notice["delivery"] not in {"claimed", "sent", "unknown"}):
            raise MonitorError("invalid_state")
        parse_utc(notice["claimed_at_utc"])
        if notice["completed_at_utc"] is not None:
            parse_utc(notice["completed_at_utc"])
        if (notice["kind"] == "failure") != (value["health"] == "unhealthy"):
            raise MonitorError("invalid_state")
    return value


class GitHubState:
    def __init__(self, repository, token, namespace, issue_number, request=request_json):
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not token
                or not re.fullmatch(r"[1-9][0-9]{0,9}", str(issue_number))):
            raise MonitorError("invalid_github_configuration")
        self.base = "https://api.github.com/repos/" + repository
        self.headers = {"Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28"}
        self.namespace, self.request, self.number = namespace, request, int(issue_number)
        self.owner = repository.split('/')[0]

    def api(self, suffix, method="GET", payload=None):
        return self.request(self.base + suffix, method=method, payload=payload, headers=self.headers,
                            limit=65536, timeout=5)

    def load(self):
        # Only an owner-provisioned ID is authoritative. Public issue titles are untrusted.
        return self.read()

    def read(self):
        issue = self.api(f"/issues/{self.number}")
        if (not isinstance(issue, dict) or type(issue.get("number")) is not int or issue["number"] != self.number
                or "pull_request" in issue or issue.get("title") != TITLES[self.namespace]
                or not isinstance(issue.get("body"), str) or len(issue["body"]) > 8192
                or not isinstance(issue.get("user"), dict)
                or issue["user"].get("login") not in {self.owner, "github-actions[bot]"}):
            raise MonitorError("invalid_state_response")
        return validate_state(strict_json(issue["body"]), self.namespace)

    def save_verified(self, value):
        validate_state(value, self.namespace)
        # Never retry an uncertain mutation. Read back before any Telegram dispatch.
        self.api(f"/issues/{self.number}", "PATCH", {"body": json.dumps(value, sort_keys=True)})
        if self.read() != value:
            raise MonitorError("state_readback_mismatch")


def send_telegram(token, chat_id, message, request=request_json):
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token) or not re.fullmatch(r"-?[0-9]+", chat_id):
        raise MonitorError("invalid_alert_configuration")
    # The URL contains the credential. Never log it or propagate HTTP exceptions.
    value = request("https://api.telegram.org/bot" + token + "/sendMessage", method="POST",
                    payload={"chat_id": chat_id, "text": message, "link_preview_options": {"is_disabled": True}},
                    limit=32768, timeout=5)
    result = value.get("result") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get("ok") is not True or not isinstance(result, dict) or type(result.get("message_id")) is not int
            or not isinstance(result.get("chat"), dict) or str(result["chat"].get("id")) != chat_id
            or result.get("text") != message):
        raise MonitorError("alert_receipt_unverified")


def transition(store, healthy, reason, sender, namespace):
    state = store.load()
    notice = state["notification"]
    if notice and notice["delivery"] in {"claimed", "unknown"}:
        raise MonitorError("prior_delivery_requires_reconciliation")
    desired = "healthy" if healthy else "unhealthy"
    if state["health"] == desired:
        return "unchanged"
    previous = state["health"]
    state["health"], state["updated_at_utc"] = desired, stamp()
    if previous == "unknown" and healthy:
        store.save_verified(state)
        return "healthy_baseline"
    kind = "recovery" if healthy else "failure"
    state["sequence"] += 1
    state["notification"] = {"transition_id": uuid.uuid4().hex, "kind": kind, "delivery": "claimed",
                             "claimed_at_utc": stamp(), "completed_at_utc": None}
    store.save_verified(state)
    prefix = "TEST ONLY: " if namespace == "test" else ""
    message = (prefix + "Independent security monitor: checks have recovered." if healthy else
               prefix + "Independent security monitor: attention needed. Failed check: " + reason + ".")
    if namespace == "test":
        message += " This is a synthetic alert; no service was stopped."
    try:
        sender(message)
    except Exception:
        state["notification"]["delivery"] = "unknown"
        state["notification"]["completed_at_utc"] = stamp()
        try:
            store.save_verified(state)
        except Exception:
            pass  # The already-durable claim still prevents automatic replay.
        raise MonitorError("alert_delivery_requires_reconciliation") from None
    state["notification"]["delivery"] = "sent"
    state["notification"]["completed_at_utc"] = stamp()
    store.save_verified(state)
    return kind + "_sent"


def main():
    mode = os.environ.get("TEST_MODE", "none")
    if mode not in {"none", "failure", "recovery"}:
        raise MonitorError("invalid_test_mode")
    namespace = "production" if mode == "none" else "test"
    url = validate_health_url(os.environ.get("HEALTH_URL", ""))
    if mode == "none":
        try:
            healthy, reason = assess_health(request_json(url))
        except MonitorError:
            healthy, reason = False, "health endpoint unavailable or invalid"
    else:
        healthy, reason = mode == "recovery", "synthetic failure"
    issue_key = "PRODUCTION_STATE_ISSUE_ID" if namespace == "production" else "TEST_STATE_ISSUE_ID"
    store = GitHubState(os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_TOKEN", ""),
                        namespace, os.environ.get(issue_key, ""))
    result = transition(store, healthy, reason,
                        lambda message: send_telegram(os.environ.get("ALERT_BOT_TOKEN", ""), os.environ.get("ALERT_CHAT_ID", ""), message), namespace)
    print(json.dumps({"namespace": namespace, "healthy": healthy, "result": result}))
    return 0 if healthy or mode != "none" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        code = str(error) if isinstance(error, MonitorError) else "unexpected_monitor_failure"
        print(json.dumps({"result": "failed", "reason": code}))
        sys.exit(1)
