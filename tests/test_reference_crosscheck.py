"""Cross-check the library against an independent naive reference using
fixed-seed shuffled data ingested in random batches."""

import random
import unittest

from cloud_activity import (
    CloudActivityDetector,
    EXPORT_WINDOW_MS,
    LOGIN_WINDOW_MS,
)
from tests.naive_reference import naive_violations

IDENTITIES = ["alice", "bob", "carol"]
IP_POOL = [f"203.0.113.{i}" for i in range(6)]
HORIZON = 2_000_000


def make_events(seed=20261002):
    rng = random.Random(seed)
    events = []

    def add(ts, identity, action, ip):
        events.append({"timestamp": ts, "identity": identity,
                       "action": action, "source_ip": ip})

    # Export bursts straddling the threshold of 50.
    for _ in range(14):
        identity = rng.choice(IDENTITIES)
        base = rng.randrange(0, HORIZON)
        count = rng.choice([48, 50, 51, 55, 70])
        span = rng.choice([0, 1, 500, 60_000])
        for _ in range(count):
            add(base + rng.randrange(0, span + 1), identity,
                "data_export", rng.choice(IP_POOL))

    # Login bursts with 2-5 distinct IPs around the threshold of 3.
    for _ in range(14):
        identity = rng.choice(IDENTITIES)
        base = rng.randrange(0, HORIZON)
        ip_count = rng.choice([2, 3, 4, 5])
        ips = rng.sample(IP_POOL, ip_count)
        span = rng.choice([0, 1, 2_000, 120_000])
        for _ in range(rng.randrange(4, 12)):
            add(base + rng.randrange(0, span + 1), identity,
                "login", rng.choice(ips))

    # Sparse background noise.
    for _ in range(60):
        add(rng.randrange(0, HORIZON), rng.choice(IDENTITIES),
            rng.choice(["login", "data_export"]), rng.choice(IP_POOL))

    rng.shuffle(events)
    return events


def ingest_in_random_batches(detector, events, seed):
    rng = random.Random(seed)
    remaining = list(events)
    while remaining:
        batch_size = rng.randrange(1, max(2, len(remaining) // 3 + 1))
        batch, remaining = remaining[:batch_size], remaining[batch_size:]
        detector.ingest(batch)


def tuples_of(violations):
    return sorted((v.identity, v.policy, v.start, v.end) for v in violations)


def merge_touching(segments):
    """Merge segments that touch (same identity+policy, end == start)."""
    merged = {}
    for identity, policy, start, end in segments:
        key = (identity, policy)
        merged.setdefault(key, []).append((start, end))
    out = []
    for (identity, policy), spans in merged.items():
        spans.sort()
        cur_start, cur_end = spans[0]
        for start, end in spans[1:]:
            if start == cur_end:
                cur_end = end
            else:
                out.append((identity, policy, cur_start, cur_end))
                cur_start, cur_end = start, end
        out.append((identity, policy, cur_start, cur_end))
    return sorted(out)


class RandomizedCrossCheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = make_events()
        cls.detector = CloudActivityDetector()
        ingest_in_random_batches(cls.detector, cls.events, seed=7)

    def test_full_range_matches_naive(self):
        expected = naive_violations(self.events, 0, HORIZON + EXPORT_WINDOW_MS)
        actual = tuples_of(self.detector.evaluate(0, HORIZON + EXPORT_WINDOW_MS))
        self.assertEqual(actual, expected)

    def test_random_subranges_match_naive(self):
        rng = random.Random(99)
        for _ in range(25):
            start = rng.randrange(0, HORIZON)
            end = start + rng.randrange(1, HORIZON // 2)
            expected = naive_violations(self.events, start, end)
            actual = tuples_of(self.detector.evaluate(start, end))
            self.assertEqual(actual, expected, f"range [{start}, {end})")

    def test_ingestion_order_and_batching_are_irrelevant(self):
        other = CloudActivityDetector()
        ingest_in_random_batches(other, list(reversed(self.events)), seed=1234)
        self.assertEqual(
            tuples_of(other.evaluate(0, HORIZON + EXPORT_WINDOW_MS)),
            tuples_of(self.detector.evaluate(0, HORIZON + EXPORT_WINDOW_MS)),
        )

    def test_split_queries_concatenate_to_whole(self):
        rng = random.Random(555)
        for _ in range(15):
            start = rng.randrange(0, HORIZON)
            end = start + rng.randrange(2, HORIZON)
            mid = rng.randrange(start + 1, end)
            whole = tuples_of(self.detector.evaluate(start, end))
            pieces = (tuples_of(self.detector.evaluate(start, mid))
                      + tuples_of(self.detector.evaluate(mid, end)))
            self.assertEqual(merge_touching(pieces), whole,
                             f"split [{start}, {mid}) + [{mid}, {end})")


class ThresholdEdgeTest(unittest.TestCase):
    def test_exactly_50_exports_is_not_a_violation(self):
        detector = CloudActivityDetector()
        detector.ingest([{"timestamp": 10_000, "identity": "a",
                          "action": "data_export", "source_ip": "10.0.0.1"}
                         for _ in range(50)])
        self.assertEqual(list(detector.evaluate(0, 2 * EXPORT_WINDOW_MS)), [])

    def test_51st_export_opens_violation_at_its_own_timestamp(self):
        detector = CloudActivityDetector()
        detector.ingest([{"timestamp": 10_000, "identity": "a",
                          "action": "data_export", "source_ip": "10.0.0.1"}
                         for _ in range(50)])
        detector.ingest([{"timestamp": 20_000, "identity": "a",
                          "action": "data_export", "source_ip": "10.0.0.1"}])
        violations = list(detector.evaluate(0, 2 * EXPORT_WINDOW_MS))
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].start, 20_000)
        self.assertEqual(violations[0].end, 10_000 + EXPORT_WINDOW_MS)

    def test_exactly_3_ips_is_not_a_violation(self):
        detector = CloudActivityDetector()
        detector.ingest([{"timestamp": 5_000, "identity": "a",
                          "action": "login", "source_ip": f"10.0.0.{i}"}
                         for i in range(3)])
        self.assertEqual(list(detector.evaluate(0, 2 * LOGIN_WINDOW_MS)), [])

    def test_4th_ip_opens_violation(self):
        detector = CloudActivityDetector()
        detector.ingest([{"timestamp": 5_000, "identity": "a",
                          "action": "login", "source_ip": f"10.0.0.{i}"}
                         for i in range(4)])
        violations = list(detector.evaluate(0, 2 * LOGIN_WINDOW_MS))
        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end),
                         (5_000, 5_000 + LOGIN_WINDOW_MS))


class SameTimestampAcrossBatchesTest(unittest.TestCase):
    def test_same_timestamp_exports_split_across_batches(self):
        detector = CloudActivityDetector()
        batch1 = [{"timestamp": 42_000, "identity": "a",
                   "action": "data_export", "source_ip": "10.0.0.1"}
                  for _ in range(20)]
        batch2 = [{"timestamp": 42_000, "identity": "a",
                   "action": "data_export", "source_ip": "10.0.0.1"}
                  for _ in range(31)]
        detector.ingest(batch1)
        self.assertEqual(list(detector.evaluate(0, 2 * EXPORT_WINDOW_MS)), [])
        detector.ingest(batch2)
        violations = list(detector.evaluate(0, 2 * EXPORT_WINDOW_MS))
        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end),
                         (42_000, 42_000 + EXPORT_WINDOW_MS))

    def test_same_timestamp_logins_split_across_batches(self):
        detector = CloudActivityDetector()
        for i in (0, 1):
            detector.ingest([{"timestamp": 7_000, "identity": "a",
                              "action": "login", "source_ip": f"10.0.0.{i}"}])
        self.assertEqual(list(detector.evaluate(0, 2 * LOGIN_WINDOW_MS)), [])
        for i in (2, 3):
            detector.ingest([{"timestamp": 7_000, "identity": "a",
                              "action": "login", "source_ip": f"10.0.0.{i}"}])
        violations = list(detector.evaluate(0, 2 * LOGIN_WINDOW_MS))
        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end),
                         (7_000, 7_000 + LOGIN_WINDOW_MS))


class MidViolationQueryTest(unittest.TestCase):
    def test_query_starting_inside_violation_is_clipped_to_start(self):
        detector = CloudActivityDetector()
        detector.ingest([{"timestamp": 0, "identity": "a",
                          "action": "data_export", "source_ip": "10.0.0.1"}
                         for _ in range(60)])
        violations = list(detector.evaluate(1_000_000, 2_000_000))
        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end),
                         (1_000_000, 2_000_000))

    def test_query_ending_inside_violation_is_clipped_to_end(self):
        detector = CloudActivityDetector()
        detector.ingest([{"timestamp": 0, "identity": "a",
                          "action": "data_export", "source_ip": "10.0.0.1"}
                         for _ in range(60)])
        violations = list(detector.evaluate(0, 1_000_000))
        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end),
                         (0, 1_000_000))


if __name__ == "__main__":
    unittest.main()
