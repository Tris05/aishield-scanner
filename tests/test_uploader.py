import unittest
from aishield.uploader import normalize_repo_url

class UploaderTests(unittest.TestCase):
    def test_normalizes_public_github_url(self):
        self.assertEqual(normalize_repo_url("https://github.com/acme/demo.git"), "https://github.com/acme/demo")
    def test_rejects_credentials_and_private_hosts(self):
        for url in ("https://user:pass@github.com/acme/demo", "https://example.com/acme/demo", "http://github.com/acme/demo"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_repo_url(url)

if __name__ == "__main__":
    unittest.main()
