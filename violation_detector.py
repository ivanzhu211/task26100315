"""Offline backtracking violation detection over cloud activity events.

Events are persisted in SQLite. The event set is fixed during evaluation:
results depend only on the ingested events, never on ingestion order or
batch boundaries.

Policies (both per identity):
  - data_export: more than 50 data_export events in the last 60 minutes.
  - login: logins from more than 3 distinct IPs in the last 15 minutes.

The window at time t is (t - W, t], W being the policy window length.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Iterable, Iterator

ACTION_LOGIN = "login"
ACTION_DATA_EXPORT = "data_export"

POLICY_DATA_EXPORT_COUNT = "data_export_count"
POLICY_LOGIN_DISTINCT_IP = "login_distinct_ip"

EXPORT_WINDOW_MS = 60 * 60 * 1000
EXPORT_THRESHOLD = 50

LOGIN_WINDOW_MS = 15 * 60 * 1000
LOGIN_THRESHOLD = 3


@dataclass(frozen=True)
class Event:
    timestamp: int
    identity: str
    action: str
    source_ip: str


@dataclass(frozen=True)
class Violation:
    identity: str
    policy: str
    start: int
    end: int


class ViolationDetector:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "timestamp INTEGER NOT NULL, "
            "identity TEXT NOT NULL, "
            "action TEXT NOT NULL, "
            "source_ip TEXT NOT NULL)"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def ingest(self, events: Iterable[Event]) -> None:
        rows = []
        for event in events:
            if isinstance(event, Event):
                row = (event.timestamp, event.identity, event.action, event.source_ip)
            elif isinstance(event, dict):
                row = (
                    event["timestamp"],
                    event["identity"],
                    event["action"],
                    event["source_ip"],
                )
            else:
                row = tuple(event)
            if row[2] not in (ACTION_LOGIN, ACTION_DATA_EXPORT):
                raise ValueError(f"unknown action: {row[2]!r}")
            rows.append((int(row[0]), str(row[1]), row[2], str(row[3])))
        self._conn.executemany(
            "INSERT INTO events (timestamp, identity, action, source_ip)"
            " VALUES (?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()

    def evaluate(self, start: int, end: int) -> Iterator[Violation]:
        if end <= start:
            return iter(())
        violations = []
        for action, window, threshold, policy, distinct in (
            (ACTION_DATA_EXPORT, EXPORT_WINDOW_MS, EXPORT_THRESHOLD,
             POLICY_DATA_EXPORT_COUNT, False),
            (ACTION_LOGIN, LOGIN_WINDOW_MS, LOGIN_THRESHOLD,
             POLICY_LOGIN_DISTINCT_IP, True),
        ):
            # An event can only affect windows at t in [start, end) when
            # start - window < timestamp < end.
            cursor = self._conn.execute(
                "SELECT identity, timestamp, source_ip FROM events"
                " WHERE action = ? AND timestamp > ? AND timestamp < ?"
                " ORDER BY identity, timestamp",
                (action, start - window, end),
            )
            by_identity = {}
            for identity, ts, ip in cursor:
                by_identity.setdefault(identity, []).append((ts, ip))
            for identity, rows in by_identity.items():
                if distinct:
                    segments = _distinct_ip_segments(rows, window, threshold)
                else:
                    segments = _count_segments(
                        [ts for ts, _ in rows], window, threshold
                    )
                for seg_start, seg_end in segments:
                    clipped_start = max(seg_start, start)
                    clipped_end = min(seg_end, end)
                    if clipped_start < clipped_end:
                        violations.append(
                            Violation(identity, policy, clipped_start, clipped_end)
                        )
        violations.sort(key=lambda v: (v.identity, v.policy, v.start, v.end))
        return iter(violations)


def _count_segments(timestamps, window, threshold):
    """Maximal [a, b) segments where the sliding-window count > threshold.

    An event at ts contributes to windows at t in [ts, ts + window), so the
    count only changes at critical points ts (enters) and ts + window
    (expires). Changes sharing a point are applied together, so a same-ms
    expiry plus arrival never creates a transient drop or zero-length split.
    """
    deltas = {}
    for ts in timestamps:
        deltas[ts] = deltas.get(ts, 0) + 1
        deltas[ts + window] = deltas.get(ts + window, 0) - 1
    count = 0
    seg_start = None
    for point in sorted(deltas):
        count += deltas[point]
        if count > threshold:
            if seg_start is None:
                seg_start = point
        elif seg_start is not None:
            yield (seg_start, point)
            seg_start = None


def _distinct_ip_segments(events, window, threshold):
    """Maximal [a, b) segments where distinct IPs in the window > threshold.

    Each login keeps its IP visible for [ts, ts + window); an IP stays in
    the window as long as any of its logins is unexpired, so partial expiry
    of older records does not remove it.
    """
    deltas = {}
    for ts, ip in events:
        arrive = deltas.setdefault(ts, {})
        arrive[ip] = arrive.get(ip, 0) + 1
        expire = deltas.setdefault(ts + window, {})
        expire[ip] = expire.get(ip, 0) - 1
    ip_counts = {}
    distinct = 0
    seg_start = None
    for point in sorted(deltas):
        for ip, delta in deltas[point].items():
            before = ip_counts.get(ip, 0)
            after = before + delta
            if after:
                ip_counts[ip] = after
            else:
                ip_counts.pop(ip, None)
            if before == 0 and after > 0:
                distinct += 1
            elif before > 0 and after == 0:
                distinct -= 1
        if distinct > threshold:
            if seg_start is None:
                seg_start = point
        elif seg_start is not None:
            yield (seg_start, point)
            seg_start = None
