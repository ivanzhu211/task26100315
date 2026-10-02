# task26100315

Offline backtracking violation detection over cloud activity events,
using only the Python standard library and SQLite.

## Usage

```python
from violation_detector import Event, ViolationDetector

detector = ViolationDetector("events.db")   # or ":memory:"
detector.ingest([Event(timestamp, identity, action, source_ip), ...])
for violation in detector.evaluate(start, end):   # [start, end), UTC ms
    print(violation)  # Violation(identity, policy, start, end)
```

Policies (per identity, window `(t - W, t]`):

- `data_export_count`: more than 50 `data_export` events in the last 60 minutes.
- `login_distinct_ip`: `login` events from more than 3 distinct IPs in the
  last 15 minutes.

Violations are reported as maximal continuous half-open segments clipped to
the query range. Results depend only on the event set, not on ingestion
order or batching.

## Tests

```
python3 -m unittest test_violation_detector -v
```
