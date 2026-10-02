import os
import random
import tempfile
import unittest
from unittest import mock

import violation_detector as vd
from violation_detector import Event, Violation, ViolationDetector


def make_detector(events=()):
    detector = ViolationDetector()
    detector.ingest(events)
    return detector


def naive_violations(events, start, end, export_window, export_threshold,
                     login_window, login_threshold):
    """Independent point-wise reference: evaluates every millisecond."""
    by_identity = {}
    for event in events:
        by_identity.setdefault(event.identity, []).append(event)
    policies = (
        (vd.ACTION_DATA_EXPORT, export_window, export_threshold,
         vd.POLICY_DATA_EXPORT_COUNT, False),
        (vd.ACTION_LOGIN, login_window, login_threshold,
         vd.POLICY_LOGIN_DISTINCT_IP, True),
    )
    out = []
    for identity, identity_events in by_identity.items():
        for action, window, threshold, policy, distinct in policies:
            relevant = [(e.timestamp, e.source_ip) for e in identity_events
                        if e.action == action]
            seg_start = None
            for t in range(start, end):
                in_window = [(ts, ip) for ts, ip in relevant
                             if t - window < ts <= t]
                if distinct:
                    active = len({ip for _, ip in in_window}) > threshold
                else:
                    active = len(in_window) > threshold
                if active and seg_start is None:
                    seg_start = t
                elif not active and seg_start is not None:
                    out.append(Violation(identity, policy, seg_start, t))
                    seg_start = None
            if seg_start is not None:
                out.append(Violation(identity, policy, seg_start, end))
    out.sort(key=lambda v: (v.identity, v.policy, v.start, v.end))
    return out


def merge_touching(violations):
    """Merge segments that touch, per (identity, policy)."""
    groups = {}
    for v in violations:
        groups.setdefault((v.identity, v.policy), []).append(v)
    merged = []
    for (identity, policy), group in groups.items():
        group.sort(key=lambda v: v.start)
        cur_start, cur_end = group[0].start, group[0].end
        for v in group[1:]:
            if v.start <= cur_end:
                cur_end = max(cur_end, v.end)
            else:
                merged.append(Violation(identity, policy, cur_start, cur_end))
                cur_start, cur_end = v.start, v.end
        merged.append(Violation(identity, policy, cur_start, cur_end))
    merged.sort(key=lambda v: (v.identity, v.policy, v.start, v.end))
    return merged


class ExpiryAndArrivalTest(unittest.TestCase):
    def test_same_ms_expiry_and_arrival_no_false_split(self):
        # Real 15-minute login window, threshold 3 distinct IPs.
        W = vd.LOGIN_WINDOW_MS  # 900_000
        events = [
            Event(0, "u", "login", "A"),
            Event(0, "u", "login", "B"),
            Event(0, "u", "login", "C"),
            Event(100, "u", "login", "D"),          # 4 distinct -> violation starts
            Event(200, "u", "login", "A"),          # A now has two records
            Event(800_000, "u", "login", "B"),      # renew B, C before expiry
            Event(800_000, "u", "login", "C"),
            Event(100 + W, "u", "login", "D"),      # arrives exactly when D@100 expires
        ]
        detector = make_detector(events)
        # At t=W: A@0 expires but A stays via A@200; B@0/C@0 expire but stay
        # via the 800_000 records. At t=100+W: D@100 expires and D renews in
        # the same millisecond. Neither may split the segment. After A@200
        # expires at 200+W and nothing new arrives, distinct drops to 3 and
        # the violation must end exactly there.
        result = list(detector.evaluate(0, 10 * W))
        self.assertEqual(
            result,
            [Violation("u", vd.POLICY_LOGIN_DISTINCT_IP, 100, 200 + W)],
        )

    def test_violation_ends_on_expiry_without_new_events(self):
        W = vd.LOGIN_WINDOW_MS
        events = [Event(0, "u", "login", ip) for ip in ("A", "B", "C", "D")]
        detector = make_detector(events)
        # No events after t=0; all four IPs expire at W, ending the segment.
        result = list(detector.evaluate(0, 10 * W))
        self.assertEqual(
            result,
            [Violation("u", vd.POLICY_LOGIN_DISTINCT_IP, 0, W)],
        )
        # A query entirely after expiry sees nothing.
        self.assertEqual(list(detector.evaluate(W, 2 * W)), [])

    def test_export_threshold_and_same_ms_renewal(self):
        W = vd.EXPORT_WINDOW_MS
        events = [Event(0, "u", "data_export", "A") for _ in range(51)]
        # The first 51 expire exactly at W; 51 same-ms replacements keep the
        # count above the threshold with no transient drop or split.
        events += [Event(W, "u", "data_export", "A") for _ in range(51)]
        detector = make_detector(events)
        result = list(detector.evaluate(0, 10 * W))
        self.assertEqual(
            result,
            [Violation("u", vd.POLICY_DATA_EXPORT_COUNT, 0, 2 * W)],
        )
        # Exactly at 2W the replacements expire and the violation ends.
        self.assertEqual(list(detector.evaluate(2 * W, 3 * W)), [])

    def test_exactly_at_threshold_is_not_a_violation(self):
        events = [Event(0, "u", "data_export", "A") for _ in range(50)]
        events += [Event(0, "v", "login", ip) for ip in ("A", "B", "C")]
        detector = make_detector(events)
        self.assertEqual(list(detector.evaluate(0, 10**9)), [])


class RandomizedReferenceTest(unittest.TestCase):
    # Small windows/thresholds keep the point-wise reference timeline short
    # while exercising identical sweep logic (expiry included).
    PATCHES = {
        "EXPORT_WINDOW_MS": 200,
        "EXPORT_THRESHOLD": 5,
        "LOGIN_WINDOW_MS": 100,
        "LOGIN_THRESHOLD": 2,
    }

    def setUp(self):
        patcher = mock.patch.multiple(vd, **self.PATCHES)
        patcher.start()
        self.addCleanup(patcher.stop)

    def build_events(self):
        rng = random.Random(20261002)
        identities = ["u1", "u2", "u3"]
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        actions = [vd.ACTION_LOGIN, vd.ACTION_DATA_EXPORT]
        events = [
            Event(rng.randrange(0, 1500), rng.choice(identities),
                  rng.choice(actions), rng.choice(ips))
            for _ in range(120)
        ]
        # Same-timestamp clusters, destined to land in different batches.
        events += [Event(500, "u1", vd.ACTION_DATA_EXPORT, "10.0.0.1")
                   for _ in range(6)]            # 6 > 5: violation
        events += [Event(700, "u2", vd.ACTION_DATA_EXPORT, "10.0.0.2")
                   for _ in range(5)]            # exactly 5: no violation
        events += [Event(900, "u3", vd.ACTION_LOGIN, ip)
                   for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3")]
        events += [Event(1000, "u2", vd.ACTION_LOGIN, ip)
                   for ip in ("10.0.0.1", "10.0.0.2")]  # exactly 2 distinct
        shuffled = events[:]
        rng.shuffle(shuffled)
        return events, shuffled

    def ingest_in_batches(self, detector, events, batches):
        size = (len(events) + batches - 1) // batches
        for offset in range(0, len(events), size):
            detector.ingest(events[offset:offset + size])

    def test_against_naive_reference(self):
        events, shuffled = self.build_events()
        detector = make_detector()
        self.ingest_in_batches(detector, shuffled, 3)

        naive_kwargs = dict(
            export_window=self.PATCHES["EXPORT_WINDOW_MS"],
            export_threshold=self.PATCHES["EXPORT_THRESHOLD"],
            login_window=self.PATCHES["LOGIN_WINDOW_MS"],
            login_threshold=self.PATCHES["LOGIN_THRESHOLD"],
        )
        query_ranges = [
            (0, 1600),      # whole timeline
            (350, 900),     # arbitrary interior range
            (501, 1000),    # starts inside an existing violation
            (0, 1),         # single millisecond
            (1200, 1600),   # tail, after expiries
        ]
        for start, end in query_ranges:
            with self.subTest(start=start, end=end):
                self.assertEqual(
                    list(detector.evaluate(start, end)),
                    naive_violations(events, start, end, **naive_kwargs),
                )

    def test_ingestion_order_and_batching_do_not_matter(self):
        events, shuffled = self.build_events()
        detector_sorted = make_detector(sorted(events, key=lambda e: e.timestamp))
        detector_shuffled = make_detector()
        self.ingest_in_batches(detector_shuffled, shuffled, 5)
        for start, end in [(0, 1600), (400, 1100)]:
            self.assertEqual(
                list(detector_sorted.evaluate(start, end)),
                list(detector_shuffled.evaluate(start, end)),
            )

    def test_split_queries_concatenate_to_full_query(self):
        events, shuffled = self.build_events()
        detector = make_detector()
        self.ingest_in_batches(detector, shuffled, 3)
        full = list(detector.evaluate(0, 1600))
        for mid in (1, 250, 500, 700, 1000, 1599):
            with self.subTest(mid=mid):
                parts = list(detector.evaluate(0, mid)) + \
                        list(detector.evaluate(mid, 1600))
                self.assertEqual(merge_touching(parts), full)


class PersistenceTest(unittest.TestCase):
    def test_events_survive_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "events.db")
            detector = ViolationDetector(db_path)
            detector.ingest(
                Event(1000, "u", "data_export", "A") for _ in range(51)
            )
            detector.close()
            reopened = ViolationDetector(db_path)
            self.assertEqual(
                list(reopened.evaluate(0, 10**9)),
                [Violation("u", vd.POLICY_DATA_EXPORT_COUNT, 1000,
                           1000 + vd.EXPORT_WINDOW_MS)],
            )
            reopened.close()


if __name__ == "__main__":
    unittest.main()
