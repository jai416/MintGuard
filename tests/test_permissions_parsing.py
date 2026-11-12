"""Parsing tests for /etc/passwd, /etc/shadow, /etc/group and sshd_config."""

import unittest

from mintguard.checks.permissions import (
    accounts_without_password,
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


if __name__ == "__main__":
    unittest.main()
