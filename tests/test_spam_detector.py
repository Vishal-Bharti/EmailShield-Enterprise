import unittest

from analyzers.spam_detector import analyze_spam


class SpamDetectorTests(unittest.TestCase):
    def test_header_analysis_detects_reply_to_mismatch(self):
        headers = {
            "subject": "Urgent update required",
            "from": "alerts@bank.com",
            "reply_to": "support@freegift.com",
            "return_path": "bounce@freegift.com",
            "message_id": None,
        }

        result = analyze_spam(
            "Please verify your account now",
            headers=headers,
            auth={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
            iocs={"urls": [], "ips": []},
            attachments=[],
        )

        self.assertGreater(result["spam_score"], 0)
        self.assertIn("Reply-To domain differs from sender domain", result["reasons"])


if __name__ == "__main__":
    unittest.main()
