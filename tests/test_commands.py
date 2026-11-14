"""Tests for the hardened command runner shared by the checks."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mintguard.core.commands import _is_trusted, resolve_binary, run_command


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
        self.assertIn("�", result.stdout)

    def test_decoding_is_utf8_regardless_of_locale(self):
        # Deterministic decoding: parsers must not depend on the ambient
        # locale encoding.
        result = run_command(["/bin/sh", "-c", "printf 'caf\\303\\251'"], timeout=10)
        self.assertEqual(result.stdout, "café")


def _stat(uid: int, mode: int) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 0, uid, uid, 0, 0, 0, 0))


class ResolveBinaryTests(unittest.TestCase):
    """Binaries are resolved from the standard directories, never from PATH.

    Under sudo the inherited PATH can point at ~/.local/bin: a binary
    found there would run as root.
    """

    def test_missing_binary_returns_none(self):
        self.assertIsNone(resolve_binary("mintguard-no-existe-xyz"))

    def test_system_binary_is_found_with_an_absolute_path(self):
        path = resolve_binary("sh")
        self.assertIsNotNone(path)
        self.assertTrue(os.path.isabs(path))

    def test_only_root_owned_regular_files_are_trusted(self):
        self.assertTrue(_is_trusted(_stat(0, 0o100755)))  # root's, 755
        self.assertFalse(_is_trusted(_stat(1000, 0o100755)))  # owned by a user
        self.assertFalse(_is_trusted(_stat(0, 0o100775)))  # writable by group
        self.assertFalse(_is_trusted(_stat(0, 0o100757)))  # writable by others
        self.assertFalse(_is_trusted(_stat(0, 0o040755)))  # a directory

    def test_user_owned_binary_in_a_standard_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "ss"
            fake.write_text("#!/bin/sh\n")
            fake.chmod(0o755)
            with mock.patch("mintguard.core.commands.SYSTEM_BIN_DIRS", (tmp,)):
                self.assertIsNone(resolve_binary("ss"))


if __name__ == "__main__":
    unittest.main()
