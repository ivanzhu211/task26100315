"""Independent naive reference implementation.

For every identity/policy it collects all candidate boundary times (event
timestamps, their expiries, and the query bounds), then evaluates the policy
predicate directly from its definition at each boundary. The state is
constant between consecutive boundaries, so scanning boundaries is exact.
"""

EXPORT_WINDOW_MS = 60 * 60 * 1000
LOGIN_WINDOW_MS = 15 * 60 * 1000

POLICIES = (
    ("data_export_volume", "data_export", EXPORT_WINDOW_MS, 50),
    ("login_ip_fanout", "login", LOGIN_WINDOW_MS, 3),
)


def _holds(events, identity, action, window, threshold, t):
    relevant = [
        e for e in events
        if e["identity"] == identity
        and e["action"] == action
        and t - window < e["timestamp"] <= t
    ]
    if action == "data_export":
        return len(relevant) > threshold
    return len({e["source_ip"] for e in relevant}) > threshold


def naive_violations(events, start, end):
    """Return sorted (identity, policy, start, end) tuples for [start, end)."""
    results = []
    identities = sorted({e["identity"] for e in events})
    for identity in identities:
        own = [e for e in events if e["identity"] == identity]
        for policy, action, window, threshold in POLICIES:
            boundaries = {start, end}
            for e in own:
                if e["action"] == action:
                    boundaries.add(e["timestamp"])
                    boundaries.add(e["timestamp"] + window)
            points = sorted(boundaries)
            segments = []
            for left, right in zip(points, points[1:]):
                if _holds(events, identity, action, window, threshold, left):
                    if segments and segments[-1][1] == left:
                        segments[-1] = (segments[-1][0], right)
                    else:
                        segments.append((left, right))
            for seg_start, seg_end in segments:
                clipped = (max(seg_start, start), min(seg_end, end))
                if clipped[0] < clipped[1]:
                    results.append((identity, policy, clipped[0], clipped[1]))
    return sorted(results)
