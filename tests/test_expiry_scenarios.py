"""Fixed-scenario tests: same-millisecond expiry + top-up, IPs with multiple
records at different times, and violations that end purely by expiry."""

import unittest

from cloud_activity import (
    CloudActivityDetector,
    EXPORT_WINDOW_MS,
    LOGIN_WINDOW_MS,
    POLICY_EXPORT_VOLUME,
    POLICY_LOGIN_IP_FANOUT,
)


def login(ts, ip, identity="alice"):
    return {"timestamp": ts, "identity": identity,
            "action": "login", "source_ip": ip}


def export(ts, identity="alice"):
    return {"timestamp": ts, "identity": identity,
            "action": "data_export", "source_ip": "10.0.0.1"}


class LoginIpExpiryTest(unittest.TestCase):
    """4 IPs at t=0 start a violation. Some IPs get extra records later;
    at t=LOGIN_WINDOW_MS the t=0 records expire while ip1/ip4 top up in the
    same millisecond. The violation must continue unbroken and end exactly
    when ip2's last record expires."""

    def setUp(self):
        self.detector = CloudActivityDetector()
        w = LOGIN_WINDOW_MS  # 900_000
        self.detector.ingest([login(0, f"192.0.2.{i}") for i in (1, 2, 3, 4)])
        self.detector.ingest([login(5000, "192.0.2.2")])       # ip2 second record
        self.detector.ingest([login(8000, "192.0.2.3")])       # ip3 second record
        # Same millisecond: t=0 records expire; ip1 and ip4 re-login.
        self.detector.ingest([login(w, "192.0.2.1"), login(w, "192.0.2.4")])
        # No events ever again.

    def test_single_unbroken_segment_ends_on_schedule(self):
        violations = list(self.detector.evaluate(0, 2 * LOGIN_WINDOW_MS))
        self.assertEqual(len(violations), 1)
        v = violations[0]
        self.assertEqual(v.policy, POLICY_LOGIN_IP_FANOUT)
        self.assertEqual(v.identity, "alice")
        self.assertEqual(v.start, 0)
        # At t=905000 ip2's record (t=5000) expires; only ip1/ip3/ip4 remain
        # -> 3 distinct IPs, not strictly more than 3.
        self.assertEqual(v.end, 5000 + LOGIN_WINDOW_MS)

    def test_no_transient_drop_at_topup_millisecond(self):
        # A narrow query straddling the top-up millisecond must still report
        # one continuous segment, not two pieces split at t=900000.
        w = LOGIN_WINDOW_MS
        violations = list(self.detector.evaluate(w - 10, w + 10))
        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end), (w - 10, w + 10))

    def test_partial_expiry_does_not_remove_ip_early(self):
        # ip3 has records at 0 and 8000. Querying just after the t=0 record
        # expires must still show the violation active (ip3 retained).
        w = LOGIN_WINDOW_MS
        violations = list(self.detector.evaluate(w + 1, w + 4000))
        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end),
                         (w + 1, w + 4000))


class ExportCountExpiryTest(unittest.TestCase):
    """51 exports at t=0 start a violation. At exactly t=EXPORT_WINDOW_MS the
    old batch expires and a new batch arrives in the same millisecond."""

    def test_topup_below_threshold_ends_segment_exactly(self):
        detector = CloudActivityDetector()
        w = EXPORT_WINDOW_MS
        detector.ingest([export(0) for _ in range(51)])
        detector.ingest([export(w) for _ in range(50)])  # same ms as expiry
        violations = list(detector.evaluate(0, 3 * w))
        self.assertEqual(len(violations), 1)
        # At t=w the window holds exactly 50 -> not strictly more than 50.
        self.assertEqual((violations[0].start, violations[0].end), (0, w))
        self.assertEqual(violations[0].policy, POLICY_EXPORT_VOLUME)

    def test_topup_above_threshold_continues_without_split(self):
        detector = CloudActivityDetector()
        w = EXPORT_WINDOW_MS
        detector.ingest([export(0) for _ in range(51)])
        detector.ingest([export(w) for _ in range(51)])  # same ms as expiry
        violations = list(detector.evaluate(0, 3 * w))
        self.assertEqual(len(violations), 1)
        # Count stays > 50 through t=w, then the t=w batch expires at t=2w.
        self.assertEqual((violations[0].start, violations[0].end), (0, 2 * w))


if __name__ == "__main__":
    unittest.main()
