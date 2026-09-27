#!/usr/bin/env python3
"""Update one generic month marker. This job receives no alert credentials."""
import base64
from datetime import datetime, timezone
import json
import os
import re
import sys
from monitor import MonitorError, request_json, strict_json

FILE = "monitor-activity.json"


def decode_file(value):
    if (not isinstance(value, dict) or value.get("type") != "file"
            or value.get("path") != FILE or value.get("encoding") != "base64"
            or not re.fullmatch(r"[a-f0-9]{40}", value.get("sha", ""))
            or not isinstance(value.get("content"), str) or len(value["content"]) > 2048):
        raise MonitorError("invalid_activity_file")
    try:
        body = strict_json(base64.b64decode(value["content"].replace("\n", ""), validate=True))
    except Exception:
        raise MonitorError("invalid_activity_file") from None
    if (not isinstance(body, dict) or set(body) != {"schema_version", "month"}
            or type(body["schema_version"]) is not int or body["schema_version"] != 1
            or (body["month"] is not None and
                (not isinstance(body["month"], str) or not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", body["month"])))):
        raise MonitorError("invalid_activity_file")
    return body


def maintain(repository, token, now=None, request=request_json):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository) or not token:
        raise MonitorError("invalid_maintenance_configuration")
    month = (now or datetime.now(timezone.utc)).strftime("%Y-%m")
    url = "https://api.github.com/repos/" + repository + "/contents/" + FILE
    headers = {"Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28"}
    def api(method="GET", payload=None):
        return request(url, method=method, payload=payload, headers=headers, limit=16384, timeout=5)
    current = api()
    body = decode_file(current)
    if body["month"] == month:
        return "unchanged"
    if body["month"] is not None and body["month"] > month:
        raise MonitorError("activity_month_in_future")
    desired = {"schema_version": 1, "month": month}
    encoded = base64.b64encode((json.dumps(desired, sort_keys=True) + "\n").encode()).decode()
    # No automatic mutation retry. A later run reads the file before deciding to write.
    result = api("PUT", {"message": "Refresh monthly monitor activity", "content": encoded, "sha": current["sha"]})
    if (not isinstance(result, dict) or not isinstance(result.get("content"), dict)
            or result["content"].get("path") != FILE
            or not re.fullmatch(r"[a-f0-9]{40}", result["content"].get("sha", ""))):
        raise MonitorError("activity_write_unverified")
    observed = api()
    if decode_file(observed) != desired or observed["sha"] != result["content"]["sha"]:
        raise MonitorError("activity_readback_mismatch")
    return "updated"


if __name__ == "__main__":
    try:
        print(json.dumps({"maintenance": maintain(os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_TOKEN", ""))}))
    except Exception as error:
        print(json.dumps({"maintenance": "failed", "reason": str(error) if isinstance(error, MonitorError) else "unexpected_maintenance_failure"}))
        sys.exit(1)
