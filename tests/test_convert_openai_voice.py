import io
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / "scripts" / "convert_openai_voice.py"
SPEC = importlib.util.spec_from_file_location("converter", SCRIPT)
converter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(converter)


class ConverterTests(unittest.TestCase):
    def test_extracts_ipv4_and_ipv6(self):
        data = {"prefixes": [{"ipv4Prefix": f"192.0.2.{i}/32"} for i in range(10)] + [{"ipv6Prefix": "2001:db8::/32"}]}
        rules = converter.extract_rules(data)
        self.assertIn("IP-CIDR,192.0.2.0/32", rules)
        self.assertIn("IP-CIDR6,2001:db8::/32", rules)

    def test_rejects_large_removal(self):
        old = {f"IP-CIDR,192.0.2.{i}/32" for i in range(10)}
        with self.assertRaisesRegex(ValueError, "destructive"):
            converter.validate_change(old, set(list(old)[:4]))

    def test_monthly_status_heartbeat(self):
        now = datetime.now(timezone.utc)
        old = {"sourceCreationTime": "2026-01-01T00:00:00Z", "lastCheckedAt": (now - timedelta(days=31)).isoformat()}
        self.assertTrue(converter.should_refresh_status(old, "2026-01-01T00:00:00Z", False, False, now))

    def test_status_refreshes_when_age_limit_is_first_exceeded(self):
        now = datetime.now(timezone.utc)
        old = {
            "sourceCreationTime": "2026-01-01T00:00:00Z",
            "lastCheckedAt": now.isoformat(),
            "ageLimitExceeded": False,
        }
        self.assertTrue(converter.should_refresh_status(old, "2026-01-01T00:00:00Z", False, True, now))

    def test_old_but_valid_source_succeeds_with_warning(self):
        creation = datetime.now(timezone.utc) - timedelta(days=181)
        data = {
            "creationTime": creation.isoformat(),
            "prefixes": [{"ipv4Prefix": f"192.0.2.{i}/32"} for i in range(10)],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "OpenAI-Voice.list"
            status = Path(directory) / "OpenAI-Voice.status.json"
            stdout = io.StringIO()
            with (
                patch.object(converter, "fetch_json", return_value=data),
                patch.object(converter, "OUTPUT_FILE", output),
                patch.object(converter, "STATUS_FILE", status),
                patch("sys.stdout", stdout),
            ):
                self.assertEqual(converter.main(), 0)

            saved_status = json.loads(status.read_text(encoding="utf-8"))
            self.assertTrue(saved_status["ageLimitExceeded"])
            self.assertTrue(saved_status["stale"])
            self.assertIn("Upstream age limit exceeded", stdout.getvalue())

    def test_atomic_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.list"
            converter.atomic_write(path, "ok\n")
            self.assertEqual(path.read_text(encoding="utf-8"), "ok\n")


if __name__ == "__main__":
    unittest.main()
