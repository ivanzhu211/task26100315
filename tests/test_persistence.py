"""Events persisted in a SQLite file survive across detector instances."""

import os
import tempfile
import unittest

from cloud_activity import CloudActivityDetector, EXPORT_WINDOW_MS


class FilePersistenceTest(unittest.TestCase):
    def test_events_survive_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "events.db")
            detector = CloudActivityDetector(db_path)
            detector.ingest([{"timestamp": 0, "identity": "a",
                              "action": "data_export", "source_ip": "10.0.0.1"}
                             for _ in range(51)])
            detector.close()

            reopened = CloudActivityDetector(db_path)
            violations = list(reopened.evaluate(0, 2 * EXPORT_WINDOW_MS))
            reopened.close()

        self.assertEqual(len(violations), 1)
        self.assertEqual((violations[0].start, violations[0].end),
                         (0, EXPORT_WINDOW_MS))


if __name__ == "__main__":
    unittest.main()
