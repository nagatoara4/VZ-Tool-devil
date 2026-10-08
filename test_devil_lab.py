import json
import tempfile
import unittest
from pathlib import Path

from devil_lab import scan_url, scan_headers, save_report

class UrlTests(unittest.TestCase):
    def ids(self, value):
        return {item["id"] for item in scan_url(value)["findings"]}

    def test_https_clean_url_has_no_http_flag(self):
        self.assertNotIn("http_without_tls", self.ids("https://example.org/docs"))

    def test_http_account_terms_flagged(self):
        ids = self.ids("http://example.org/account/verify")
        self.assertIn("http_without_tls", ids)
        self.assertIn("suspicious_terms", ids)

    def test_userinfo_flagged(self):
        self.assertIn("userinfo_present", self.ids("https://trusted.example@evil.example/"))

    def test_malformed_port_handled(self):
        self.assertIn("malformed_url", self.ids("https://example.org:bad/"))

    def test_report_json_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            save_report([scan_url("https://example.org")], target, "json")
            data = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(data["input_type"], "url")

class HeaderTests(unittest.TestCase):
    def test_reply_to_mismatch(self):
        raw = "From: billing@example.org\nReply-To: help@unrelated.test\nDate: Thu, 1 Jan 2026 00:00:00 +0000\n"
        self.assertIn("reply_to_mismatch", {f["id"] for f in scan_headers(raw)["findings"]})

    def test_missing_auth_results_flagged(self):
        self.assertIn("missing_auth_results", {f["id"] for f in scan_headers("From: user@example.org\n")["findings"]})

if __name__ == "__main__":
    unittest.main()
