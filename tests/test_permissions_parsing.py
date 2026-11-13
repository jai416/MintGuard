"""Parsing tests for /etc/passwd, /etc/shadow, /etc/group and sshd_config."""

import unittest
from unittest import mock

from mintguard.checks.permissions import (
    accounts_without_password,
    _check_file_modes,
    external_sshd_includes,
    merge_sshd_texts,
    sshd_match_blocks,
    sshd_settings,
    sudo_members,
    uid_zero_names,
)

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
backdoor:x:0:0:backdoor:/root:/bin/sh
jai:x:1000:1000:Jai:/home/jai:/bin/bash
brokenline
"""

SHADOW = """root:$6$hash:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
vulnerable::19000:0:99999:7:::
"""

GROUP = """sudo:x:27:jai
wheel:x:10:root,admin2
users:x:100:
"""

SSHD_CONFIG = """# PermitRootLogin yes   (comment must be ignored)
PermitRootLogin prohibit-password
PasswordAuthentication no
Port 22
"""


class UidZeroTests(unittest.TestCase):
    def test_detects_root_and_extra(self):
        self.assertEqual(uid_zero_names(PASSWD.splitlines()), ["root", "backdoor"])

    def test_skips_broken_lines(self):
        self.assertEqual(
            uid_zero_names(["bad", "x:999:999:x:/home:/bin/sh"]),
            [],
        )


class EmptyPasswordTests(unittest.TestCase):
    def test_detects_empty_hash(self):
        self.assertEqual(accounts_without_password(SHADOW.splitlines()), ["vulnerable"])

    def test_locked_accounts_are_not_flagged(self):
        self.assertEqual(accounts_without_password(["root:$6$x:1:0:0:::"]), [])


class SudoMembersTests(unittest.TestCase):
    def test_groups_and_members(self):
        groups, members = sudo_members(GROUP.splitlines())
        self.assertEqual(groups, ["sudo", "wheel"])
        self.assertEqual(members, ["jai", "root", "admin2"])

    def test_members_deduplicated(self):
        # A user in both sudo and wheel used to appear twice.
        groups, members = sudo_members(["sudo:x:27:jai", "wheel:x:10:jai,root"])
        self.assertEqual(members, ["jai", "root"])


class SshdSettingsTests(unittest.TestCase):
    def test_first_occurrence_wins_like_sshd(self):
        settings = sshd_settings(SSHD_CONFIG.splitlines())
        self.assertEqual(settings["permitrootlogin"], "prohibit-password")
        self.assertEqual(settings["passwordauthentication"], "no")

    def test_comments_and_other_keys_ignored(self):
        settings = sshd_settings(SSHD_CONFIG.splitlines())
        self.assertNotIn("port", settings)

    def test_missing_keys(self):
        self.assertEqual(sshd_settings(["Port 22"]), {})

    def test_defaults_when_unset(self):
        # The checker treats missing passwordauthentication as sshd's
        # default `yes`; sshd_settings itself just reports nothing.
        self.assertEqual(sshd_settings([]), {})

    def test_tab_separated_directives(self):
        # Tabs are valid separators in sshd_config.
        self.assertEqual(
            sshd_settings(["PermitRootLogin\tyes", "PasswordAuthentication\tno"]),
            {"permitrootlogin": "yes", "passwordauthentication": "no"},
        )

    def test_parsing_stops_at_match_block(self):
        # Real case verified in the audit: global `no` plus a Match block
        # allowing passwords for one user. The global value stays `no`
        # (as sshd applies it globally); the conditional part must NOT be
        # read as the global setting.
        lines = [
            "PasswordAuthentication no",
            "Match User backdooruser",
            "    PasswordAuthentication yes",
        ]
        self.assertEqual(sshd_settings(lines), {"passwordauthentication": "no"})

    def test_match_block_detected(self):
        self.assertTrue(sshd_match_blocks(["Port 22", "Match User x", "PasswordAuthentication yes"]))
        self.assertTrue(sshd_match_blocks(["# nothing", "match all"]))
        self.assertFalse(sshd_match_blocks(["Port 22"]))
        self.assertFalse(sshd_match_blocks(["# Match User commented"]))

    def test_external_includes_flagged(self):
        lines = [
            "Include /etc/ssh/sshd_config.d/*.conf",
            "Include /etc/ssh/weird.conf",
            "Include sshd_config.d/relative.conf",
        ]
        self.assertEqual(
            external_sshd_includes(lines),
            ["/etc/ssh/weird.conf", "sshd_config.d/relative.conf"],
        )

    def test_standard_includes_not_flagged(self):
        self.assertEqual(
            external_sshd_includes(["Include /etc/ssh/sshd_config.d/*.conf"]), []
        )


class FileModesTests(unittest.TestCase):
    """C3: group-writable on critical files is as dangerous as world-writable."""

    def _check_with_modes(self, passwd: int, shadow: int, sudoers: int):
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            made = {}
            for name, mode in (("passwd", passwd), ("shadow", shadow), ("sudoers", sudoers)):
                path = Path(tmp) / name
                path.write_text("contenido")
                os.chmod(path, mode)
                made[name] = path
            with (
                mock.patch("mintguard.checks.permissions.PASSWD_PATH", made["passwd"]),
                mock.patch("mintguard.checks.permissions.SHADOW_PATH", made["shadow"]),
                mock.patch("mintguard.checks.permissions.SUDOERS_PATH", made["sudoers"]),
            ):
                return _check_file_modes()

    def test_group_writable_shadow_is_critica(self):
        findings = self._check_with_modes(0o644, 0o660, 0o440)
        flagged = [f for f in findings if "modificable" in f.title]
        self.assertEqual(len(flagged), 1)
        self.assertIn("shadow", flagged[0].title)
        self.assertEqual(flagged[0].severity.name, "CRITICA")
        self.assertIn("go-w", flagged[0].suggestion)

    def test_shadow_group_read_is_normal_on_debian(self):
        # root:shadow 0640 is the Debian default: group READ, no write.
        findings = self._check_with_modes(0o644, 0o640, 0o440)
        self.assertEqual(
            [f.title for f in findings], ["Permisos correctos en archivos críticos"]
        )

    def test_group_writable_passwd_is_alta(self):
        findings = self._check_with_modes(0o664, 0o640, 0o440)
        flagged = [f for f in findings if "modificable" in f.title]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity.name, "ALTA")


class MergeSshdTextsTests(unittest.TestCase):
    """sshd honours the FIRST occurrence; Debian/Ubuntu put the Include at
    the top, so the sshd_config.d files must win over the main file."""

    MAIN = ["Port 22\n", "PermitRootLogin prohibit-password\n", "PasswordAuthentication yes\n"]
    DROP_IN = ["PasswordAuthentication no\n"]

    def test_extras_take_precedence(self):
        merged = merge_sshd_texts(self.MAIN, [self.DROP_IN])
        self.assertEqual(sshd_settings(merged)["passwordauthentication"], "no")

    def test_main_values_survive_when_no_conflict(self):
        merged = merge_sshd_texts(self.MAIN, [self.DROP_IN])
        self.assertEqual(sshd_settings(merged)["permitrootlogin"], "prohibit-password")

    def test_no_extras_uses_main(self):
        merged = merge_sshd_texts(self.MAIN, [])
        self.assertEqual(sshd_settings(merged)["passwordauthentication"], "yes")


if __name__ == "__main__":
    unittest.main()
