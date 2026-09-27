import base64
from datetime import datetime, timezone
import json
import unittest
from maintain import maintain, MonitorError, FILE

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


class Transport:
    def __init__(self, month=None):
        self.body = {"schema_version": 1, "month": month}
        self.sha = "a" * 40
        self.calls = []
        self.uncertain = False
    def __call__(self, url, **kwargs):
        assert url == "https://api.github.com/repos/example/monitor/contents/" + FILE
        assert kwargs["timeout"] == 5
        self.calls.append(kwargs["method"])
        if kwargs["method"] == "PUT":
            assert set(kwargs["payload"]) == {"message", "content", "sha"}
            assert kwargs["payload"]["sha"] == self.sha
            self.body = json.loads(base64.b64decode(kwargs["payload"]["content"]))
            self.sha = "b" * 40
            if self.uncertain:
                raise MonitorError("request_failed")
            return {"content": {"path": FILE, "sha": self.sha}}
        return {"type": "file", "path": FILE, "encoding": "base64", "sha": self.sha,
                "content": base64.b64encode(json.dumps(self.body).encode()).decode()}


class MaintenanceTests(unittest.TestCase):
    def test_first_update_is_exact_and_read_back(self):
        t = Transport()
        self.assertEqual(maintain("example/monitor", "fake", NOW, t), "updated")
        self.assertEqual(t.calls, ["GET", "PUT", "GET"])
        self.assertEqual(t.body, {"schema_version": 1, "month": "2026-09"})
    def test_same_month_has_no_write(self):
        t = Transport("2026-09")
        self.assertEqual(maintain("example/monitor", "fake", NOW, t), "unchanged")
        self.assertEqual(t.calls, ["GET"])
    def test_uncertain_commit_is_not_replayed(self):
        t = Transport("2026-08"); t.uncertain = True
        with self.assertRaises(MonitorError): maintain("example/monitor", "fake", NOW, t)
        self.assertEqual(maintain("example/monitor", "fake", NOW, t), "unchanged")
        self.assertEqual(t.calls.count("PUT"), 1)
    def test_future_state_fails_without_write(self):
        t = Transport("2026-10")
        with self.assertRaises(MonitorError): maintain("example/monitor", "fake", NOW, t)
        self.assertEqual(t.calls, ["GET"])
    def test_extra_state_or_bad_schema_fails(self):
        for field in [{"secret": "unexpected"}, {"schema_version": True}, {"month": "2026-13"}]:
            t = Transport(); t.body.update(field)
            with self.assertRaises(MonitorError): maintain("example/monitor", "fake", NOW, t)
            self.assertEqual(t.calls, ["GET"])
    def test_configuration_cannot_change_target(self):
        for repository in ["bad", "example/monitor/../../other", "https://example.org/x", "example/monitor?x=y"]:
            t = Transport()
            with self.assertRaises(MonitorError): maintain(repository, "fake", NOW, t)
            self.assertEqual(t.calls, [])


if __name__ == "__main__":
    unittest.main()
