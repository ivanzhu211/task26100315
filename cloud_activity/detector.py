"""Offline retrospective violation detection over cloud activity events.

Storage: SQLite (stdlib sqlite3). Evaluation is a pure function of the
stored event set: ingestion order and batching never affect results.
"""

from __future__ import annotations

import bisect
import sqlite3
from dataclasses import dataclass
from typing import Iterable, Iterator, Union, Mapping, Any

# Policy parameters (fixed by spec).
EXPORT_WINDOW_MS = 60 * 60 * 1000  # 60 minutes
EXPORT_THRESHOLD = 50               # strictly more than 50 data_export
LOGIN_WINDOW_MS = 15 * 60 * 1000    # 15 minutes
LOGIN_IP_THRESHOLD = 3              # strictly more than 3 distinct IPs

POLICY_EXPORT_VOLUME = "data_export_volume"
POLICY_LOGIN_IP_FANOUT = "login_ip_fanout"

ACTION_LOGIN = "login"
ACTION_DATA_EXPORT = "data_export"


@dataclass(frozen=True)
class Event:
    timestamp: int  # UTC milliseconds
    identity: str
    action: str     # "login" | "data_export"
    source_ip: str


@dataclass(frozen=True)
class Violation:
    """A maximal continuous half-open [start, end) interval, clipped to the
    query range, during which one policy held for one identity."""
    identity: str
    policy: str
    start: int
    end: int


EventLike = Union[Event, Mapping[str, Any]]


def _emit(found: list, identity: str, policy: str,
          seg_start: int, seg_end: int, start: int, end: int) -> None:
    clipped_start = max(seg_start, start)
    clipped_end = min(seg_end, end)
    if clipped_start < clipped_end:
        found.append(Violation(identity, policy, clipped_start, clipped_end))


def _sweep(critical_points: list, holds) -> list:
    """Collapse a boolean state sampled at sorted critical points into maximal
    half-open [start, end) segments. The state is constant on
    [point, next_point), and events plus expiries are evaluated atomically at
    each point, so same-millisecond changes never create zero-length pieces."""
    segments = []
    open_start = None
    for point in critical_points:
        if holds(point):
            if open_start is None:
                open_start = point
        elif open_start is not None:
            if open_start < point:
                segments.append((open_start, point))
            open_start = None
    if open_start is not None:
        raise AssertionError("state must be false after the last expiry")
    return segments


def _count_segments(timestamps: list, window: int, threshold: int) -> list:
    """Segments where count of events in (t - window, t] exceeds threshold."""
    if not timestamps:
        return []
    critical = sorted({ts for ts in timestamps}
                      | {ts + window for ts in timestamps})

    def holds(t: int) -> bool:
        count = (bisect.bisect_right(timestamps, t)
                 - bisect.bisect_right(timestamps, t - window))
        return count > threshold

    return _sweep(critical, holds)


def _distinct_ip_segments(login_events: list, window: int,
                          threshold: int) -> list:
    """Segments where distinct source IPs with a login in (t - window, t]
    exceed threshold. An IP stays while any of its records is in-window."""
    if not login_events:
        return []
    per_ip: dict[str, list] = {}
    for timestamp, source_ip in login_events:
        per_ip.setdefault(source_ip, []).append(timestamp)
    for stamps in per_ip.values():
        stamps.sort()
    critical = sorted({ts for ts, _ in login_events}
                      | {ts + window for ts, _ in login_events})

    def holds(t: int) -> bool:
        distinct = 0
        for stamps in per_ip.values():
            if (bisect.bisect_right(stamps, t)
                    - bisect.bisect_right(stamps, t - window)) > 0:
                distinct += 1
                if distinct > threshold:
                    return True
        return False

    return _sweep(critical, holds)


def _normalize(event: EventLike) -> tuple:
    if isinstance(event, Event):
        timestamp, identity = event.timestamp, event.identity
        action, source_ip = event.action, event.source_ip
    else:
        timestamp = event["timestamp"]
        identity = event["identity"]
        action = event["action"]
        source_ip = event["source_ip"]
    timestamp = int(timestamp)
    identity = str(identity)
    source_ip = str(source_ip)
    if action not in (ACTION_LOGIN, ACTION_DATA_EXPORT):
        raise ValueError(f"unknown action: {action!r}")
    return (timestamp, identity, action, source_ip)


class CloudActivityDetector:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                timestamp INTEGER NOT NULL,
                identity  TEXT NOT NULL,
                action    TEXT NOT NULL,
                source_ip TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_identity_action_ts "
            "ON events(identity, action, timestamp)"
        )
        self._conn.commit()

    def ingest(self, events: Iterable[EventLike]) -> int:
        """Persist an iterable of events. Events may arrive out of order and
        in any batching; duplicates are never delivered by the caller."""
        rows = [_normalize(event) for event in events]
        self._conn.executemany(
            "INSERT INTO events (timestamp, identity, action, source_ip) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()
        return len(rows)

    def evaluate(self, start: int, end: int) -> Iterator[Violation]:
        """Yield Violation segments intersecting the half-open query range
        [start, end). Segments are clipped to the range; results depend only
        on the stored event set."""
        start = int(start)
        end = int(end)
        if end <= start:
            return
        # Only events that can influence [start, end): an event at ts affects
        # violation state on [ts, ts + W], so we need ts < end and
        # ts > start - W for the largest window W.
        lo = start - EXPORT_WINDOW_MS
        rows = self._conn.execute(
            "SELECT identity, action, timestamp, source_ip FROM events "
            "WHERE timestamp > ? AND timestamp < ? "
            "ORDER BY identity, action, timestamp",
            (lo, end),
        ).fetchall()

        by_identity: dict[str, dict[str, list]] = {}
        for identity, action, timestamp, source_ip in rows:
            bucket = by_identity.setdefault(
                identity, {ACTION_LOGIN: [], ACTION_DATA_EXPORT: []}
            )
            bucket[action].append((timestamp, source_ip))

        found: list[Violation] = []
        for identity, bucket in by_identity.items():
            export_ts = sorted(ts for ts, _ in bucket[ACTION_DATA_EXPORT])
            for seg_start, seg_end in _count_segments(
                export_ts, EXPORT_WINDOW_MS, EXPORT_THRESHOLD
            ):
                _emit(found, identity, POLICY_EXPORT_VOLUME,
                      seg_start, seg_end, start, end)
            login_events = sorted(bucket[ACTION_LOGIN])
            for seg_start, seg_end in _distinct_ip_segments(
                login_events, LOGIN_WINDOW_MS, LOGIN_IP_THRESHOLD
            ):
                _emit(found, identity, POLICY_LOGIN_IP_FANOUT,
                      seg_start, seg_end, start, end)

        found.sort(key=lambda v: (v.identity, v.policy, v.start))
        yield from found

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CloudActivityDetector":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
