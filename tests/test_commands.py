"""Tests for the hardened command runner shared by the checks."""

import unittest

from mintguard.core.commands import run_command


class RunCommandTests(unittest.TestCase):
    def test_missing_binary_returns_none(self):
        # OSError ( FileNotFoundError) is swallowed into None, never raised.
        self.assertIsNone(run_command(["/no/existe/mintguard-test-bin"], timeout=10))

    def test_invalid_utf8_does_not_kill_the_check(self):
        # A local user can rename their own process to bytes that are not
        # UTF-8; with text=True (strict) that made `ss` output undecodable
        # and killed the whole check with UnicodeDecodeError.
        result = run_command(["/bin/sh", "-c", "printf '\\377\\376'"], timeout=10)
        self.assertIsNotNone(result)
        self.assertIn("\ufffd", result.stdout)

    def test_decoding_is_utf8_regardless_of_locale(self):
        # Deterministic decoding: parsers must not depend on the ambient
        # locale encoding.
        result = run_command(["/bin/sh", "-c", "printf 'caf\\303\\251'"], timeout=10)
        self.assertEqual(result.stdout, "café")


if __name__ == "__main__":
    unittest.main()
