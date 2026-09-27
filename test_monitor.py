import copy
from datetime import datetime, timedelta, timezone
import io
import json
import os
import time
import unittest
from unittest import mock

import monitor as m


NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


def health():
    return {"schema_version": 1, "generated_at_utc": m.stamp(NOW), "ok": True,
            "checks": {key: True for key in m.CHECKS}}


class Store:
    def __init__(self, namespace="production"):
        self.value, self.writes = m.new_state(namespace), []
        self.fail_claim, self.fail_receipt = False, False

    def load(self):
        return copy.deepcopy(self.value)

    def save_verified(self, value):
        notice = value["notification"]
        if notice and ((notice["delivery"] == "claimed" and self.fail_claim)
                       or (notice["delivery"] != "claimed" and self.fail_receipt)):
            raise m.MonitorError("injected_state_failure")
        self.value = copy.deepcopy(value)
        self.writes.append(copy.deepcopy(value))


class SchemaTests(unittest.TestCase):
    def test_healthy_exact_schema(self):
        self.assertEqual(m.assess_health(health(), NOW), (True, ""))

    def test_all_check_failures_are_recognized(self):
        for key in m.CHECKS:
            value = health()
            value["checks"][key], value["ok"] = False, False
            healthy, reason = m.assess_health(value, NOW)
            self.assertFalse(healthy)
            self.assertEqual(reason, m.NAMES[key])

    def test_unknown_fields_and_boolean_substitutes_fail(self):
        changes = [lambda v: v.update(extra="untrusted"), lambda v: v.update(schema_version=True),
                   lambda v: v.update(ok=1), lambda v: v["checks"].update(backup_fresh=1),
                   lambda v: v["checks"].update(extra=True), lambda v: v["checks"].pop("backup_fresh")]
        for change in changes:
            value = health()
            change(value)
            with self.assertRaises(m.MonitorError):
                m.assess_health(value, NOW)

    def test_top_level_status_must_agree(self):
        value = health()
        value["ok"] = False
        with self.assertRaises(m.MonitorError):
            m.assess_health(value, NOW)

    def test_age_boundaries(self):
        for age, expected in [(-61, False), (-60, True), (300, True), (301, False)]:
            value = health()
            value["generated_at_utc"] = m.stamp(NOW - timedelta(seconds=age))
            self.assertEqual(m.assess_health(value, NOW)[0], expected)

    def test_only_utc_timestamps(self):
        for value in ["2026-09-27T12:00:00", "2026-09-27T12:00:00+08:00", "2026-99-99T12:00:00Z", 123]:
            with self.assertRaises(m.MonitorError):
                m.parse_utc(value)
        self.assertEqual(m.parse_utc("2026-09-27T12:00:00+00:00"), NOW)

    def test_duplicate_keys_and_nonfinite_values_rejected(self):
        for raw in [b'{"ok":true,"ok":false}', b'{"x":NaN}', b'{"x":Infinity}', b'not-json']:
            with self.assertRaises(m.MonitorError):
                m.strict_json(raw)

    def test_url_is_one_fixed_https_endpoint(self):
        allowed = "https://example.test/security-health.json"
        self.assertEqual(m.validate_health_url(allowed), allowed)
        for value in ["http://example.test/security-health.json", "https://example.test:444/security-health.json",
                      "https://user:pass@example.test/security-health.json", allowed + "?q=x", allowed + "#x",
                      "https://example.test/other", "https://example.test/security-health.json\n", "", "file:///security-health.json"]:
            with self.assertRaises(m.MonitorError):
                m.validate_health_url(value)


class DiagnosticTests(unittest.TestCase):
    def test_only_finite_health_labels_and_error_codes_are_logged(self):
        for reason in list(m.NAMES.values()) + ["health publication freshness"]:
            self.assertEqual(m.safe_health_detail(False, reason), reason)
        self.assertEqual(m.safe_health_detail(False, ", ".join(m.NAMES.values())),
                         ", ".join(sorted(m.NAMES.values())))
        for code in m.HEALTH_ERROR_CODES:
            self.assertEqual(m.safe_health_detail(False, error=m.MonitorError(code)), code)
        for untrusted in ["https://secret.invalid/?token=private-value", "password=private-value", "request_failed: private-value"]:
            self.assertEqual(m.safe_health_detail(False, untrusted), "health_assessment_failed")
            self.assertEqual(m.safe_health_detail(False, error=m.MonitorError(untrusted)), "health_assessment_failed")

    def run_main(self, store, response=None, error=None):
        output, sender = io.StringIO(), mock.Mock()
        with mock.patch.dict(os.environ, {"TEST_MODE": "none", "HEALTH_URL": "https://example.test/security-health.json"}), \
             mock.patch.object(m, "request_json", return_value=response, side_effect=error), \
             mock.patch.object(m, "utc_now", return_value=NOW), \
             mock.patch.object(m, "GitHubState", return_value=store), \
             mock.patch.object(m, "send_telegram", sender), \
             mock.patch("sys.stdout", output):
            exit_code = m.main()
        return exit_code, json.loads(output.getvalue()), sender

    def test_actual_failed_check_logged_without_duplicate_send(self):
        store, value = Store(), health()
        value["ok"] = value["checks"]["coverage_current"] = False
        status, first, first_sender = self.run_main(store, value)
        self.assertEqual(status, 1)
        self.assertEqual(first["health_reason"], "security coverage freshness")
        self.assertEqual(first_sender.call_count, 1)
        status, second, second_sender = self.run_main(store, value)
        self.assertEqual(second["result"], "unchanged")
        second_sender.assert_not_called()
        self.assertEqual(store.value["sequence"], 1)

    def test_error_diagnostic_redacted_and_recovery_preserves_transition(self):
        store = Store()
        status, failure, sender = self.run_main(store, error=m.MonitorError("request_failed"))
        self.assertEqual(failure["health_reason"], "request_failed")
        status, recovery, sender = self.run_main(store, health())
        self.assertEqual((status, recovery["result"], recovery["health_reason"]), (0, "recovery_sent", "healthy"))
        self.assertEqual(store.value["sequence"], 2)
        self.assertEqual(sender.call_count, 1)
        _, redacted, _ = self.run_main(Store(), error=m.MonitorError("https://secret.invalid/?token=private-value"))
        self.assertNotIn("private-value", json.dumps(redacted))


class TransitionTests(unittest.TestCase):
    def test_initial_healthy_has_no_message(self):
        store, sender = Store(), mock.Mock()
        self.assertEqual(m.transition(store, True, "", sender, "production"), "healthy_baseline")
        sender.assert_not_called()

    def test_failure_claim_precedes_send_and_duplicate_is_suppressed(self):
        store = Store()
        def send(message):
            self.assertEqual(store.value["notification"]["delivery"], "claimed")
            self.assertEqual(store.value["health"], "unhealthy")
        sender = mock.Mock(side_effect=send)
        self.assertEqual(m.transition(store, False, "backup freshness", sender, "production"), "failure_sent")
        self.assertEqual(store.value["notification"]["delivery"], "sent")
        self.assertEqual(m.transition(store, False, "backup freshness", sender, "production"), "unchanged")
        self.assertEqual(sender.call_count, 1)

    def test_failed_claim_never_dispatches(self):
        store, sender = Store(), mock.Mock()
        store.fail_claim = True
        with self.assertRaises(m.MonitorError):
            m.transition(store, False, "test", sender, "production")
        sender.assert_not_called()

    def test_uncertain_send_is_not_retried(self):
        store, sender = Store(), mock.Mock(side_effect=TimeoutError())
        with self.assertRaises(m.MonitorError):
            m.transition(store, False, "test", sender, "production")
        self.assertEqual(store.value["notification"]["delivery"], "unknown")
        for healthy in [False, True]:
            with self.assertRaises(m.MonitorError):
                m.transition(store, healthy, "test", sender, "production")
        self.assertEqual(sender.call_count, 1)

    def test_receipt_write_failure_leaves_durable_claim_and_blocks_replay(self):
        store, sender = Store(), mock.Mock()
        store.fail_receipt = True
        with self.assertRaises(m.MonitorError):
            m.transition(store, False, "test", sender, "production")
        self.assertEqual(store.value["notification"]["delivery"], "claimed")
        store.fail_receipt = False
        with self.assertRaises(m.MonitorError):
            m.transition(store, False, "test", sender, "production")
        self.assertEqual(sender.call_count, 1)

    def test_recovery_is_one_separate_transition(self):
        store, sender = Store(), mock.Mock()
        m.transition(store, False, "test", sender, "production")
        self.assertEqual(m.transition(store, True, "", sender, "production"), "recovery_sent")
        m.transition(store, True, "", sender, "production")
        self.assertEqual(sender.call_count, 2)
        self.assertEqual(store.value["sequence"], 2)

    def test_synthetic_messages_are_labelled_and_state_separate(self):
        production, synthetic, sender = Store(), Store("test"), mock.Mock()
        m.transition(synthetic, False, "synthetic failure", sender, "test")
        m.transition(synthetic, True, "", sender, "test")
        self.assertEqual(production.value["health"], "unknown")
        for call in sender.call_args_list:
            self.assertTrue(call.args[0].startswith("TEST ONLY:"))
            self.assertIn("no service was stopped", call.args[0])


class TransportTests(unittest.TestCase):
    class Response:
        status = 200
        def __init__(self, raw=b'{}', url="https://example.test/security-health.json", length=None):
            self.raw, self.url = raw, url
            self.headers = {} if length is None else {"Content-Length": str(length)}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def geturl(self):
            return self.url
        def read(self, size):
            return self.raw[:size]

    def test_body_cap_and_final_url_check(self):
        for response in [self.Response(b'x' * 4097), self.Response(length=4097), self.Response(url="https://other.test/")]:
            opener = mock.Mock()
            opener.open.return_value = response
            with mock.patch.object(m.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(m.MonitorError):
                    m.request_json("https://example.test/security-health.json")

    def test_redirect_handler_rejects_every_redirect(self):
        with self.assertRaises(m.MonitorError):
            m.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test/")

    def test_total_deadline_interrupts_slow_body(self):
        started = time.monotonic()
        with self.assertRaises(m.MonitorError):
            with m.deadline(0.02):
                time.sleep(1)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_telegram_requires_matching_recipient_text_and_receipt(self):
        valid = {"ok": True, "result": {"message_id": 1, "chat": {"id": 123}, "text": "test"}}
        request = mock.Mock(return_value=valid)
        m.send_telegram("123:abc", "123", "test", request)
        for value in [None, {"ok": False}, {"ok": True, "result": {"message_id": 1, "chat": {"id": 999}, "text": "test"}}]:
            with self.assertRaises(m.MonitorError):
                m.send_telegram("123:abc", "123", "test", mock.Mock(return_value=value))

    def test_state_patch_requires_fresh_exact_readback(self):
        state = m.new_state("production")
        request = mock.Mock(side_effect=[{}, {"number": 1, "user": {"login": "example"}, "title": m.TITLES["production"], "body": json.dumps({**state, "health": "healthy"})}])
        store = m.GitHubState("example/repository", "fake", "production", "1", request)
        with self.assertRaises(m.MonitorError):
            store.save_verified(state)
        self.assertEqual(request.call_count, 2)

    def test_uncertain_patch_is_never_retried(self):
        request = mock.Mock(side_effect=m.MonitorError("request_failed"))
        store = m.GitHubState("example/repository", "fake", "production", "1", request)
        with self.assertRaises(m.MonitorError):
            store.save_verified(m.new_state("production"))
        self.assertEqual(request.call_count, 1)

    def test_exact_state_id_ignores_unrelated_public_issue_titles(self):
        issue = {"number": 7, "user": {"login": "example"}, "title": m.TITLES["production"],
                 "body": json.dumps(m.new_state("production"))}
        def request(url, **kwargs):
            self.assertEqual(url, "https://api.github.com/repos/example/repository/issues/7")
            self.assertEqual(kwargs["method"], "GET")
            return issue
        state = m.GitHubState("example/repository", "fake", "production", "7", request).load()
        self.assertEqual(state["health"], "unknown")

    def test_spoofed_author_and_wrong_issue_id_rejected(self):
        base = {"number": 7, "user": {"login": "example"}, "title": m.TITLES["production"],
                "body": json.dumps(m.new_state("production"))}
        for patch in [{"number": 8}, {"user": {"login": "outsider"}},
                      {"title": m.TITLES["test"]}, {"pull_request": {}}]:
            request = mock.Mock(return_value={**base, **patch})
            with self.assertRaises(m.MonitorError):
                m.GitHubState("example/repository", "fake", "production", "7", request).load()

    def test_actions_bot_owned_state_is_accepted(self):
        issue = {"number": 7, "user": {"login": "github-actions[bot]"}, "title": m.TITLES["production"],
                 "body": json.dumps(m.new_state("production"))}
        state = m.GitHubState("example/repository", "fake", "production", "7", mock.Mock(return_value=issue)).load()
        self.assertEqual(state["health"], "unknown")

    def test_absent_or_injected_issue_id_fails_before_request(self):
        for identifier in ["", "0", "1?foo=bar", "../2", "true", "1/other"]:
            request = mock.Mock()
            with self.assertRaises(m.MonitorError):
                m.GitHubState("example/repository", "fake", "production", identifier, request)
            request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
