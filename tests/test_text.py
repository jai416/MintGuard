"""Tests for the sanitizing of semi-trusted text (process and package names)."""

import unittest

from mintguard.core.text import sanitize


class SanitizeTests(unittest.TestCase):
    def test_ansi_escapes_are_neutralized(self):
        # A process name can carry escape sequences; the report must not
        # repaint the user's terminal.
        clean = sanitize("\x1b[31mrojo\x1b[0m")
        self.assertNotIn("\x1b", clean)
        self.assertIn("rojo", clean)

    def test_control_characters_are_replaced(self):
        self.assertEqual(sanitize("a\nb"), "a␦b")
        self.assertEqual(sanitize("a\tb"), "a␦b")

    def test_long_strings_are_capped(self):
        clean = sanitize("x" * 5000)
        self.assertLessEqual(len(clean), 121)
        self.assertTrue(clean.endswith("…"))

    def test_normal_text_is_untouched(self):
        self.assertEqual(sanitize("TCP 0.0.0.0:22"), "TCP 0.0.0.0:22")
        self.assertEqual(sanitize("café ñ ¡sí!"), "café ñ ¡sí!")


if __name__ == "__main__":
    unittest.main()
