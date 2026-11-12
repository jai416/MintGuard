"""Parsing tests for the package-manager outputs.

A broken parser here produces false negatives in security, which is the
worst failure mode of this tool: the user believes they are protected
when they are not.
"""

import unittest

from mintguard.checks.updates import (
    count_apt_security_uris,
    parse_apt_upgradable,
    parse_dnf_check_update,
    parse_pacman_sync_qu,
    parse_zypper_list_patches,
    parse_zypper_list_updates,
)

APT_UPGRADABLE = """Listing... Done
cairo/now 1.16.0-4ubuntu1 amd64 [upgradable from: 1.16.0-4ubuntu1]
distro-info-data/noble-updates,noble-security 53.0.3ubuntu2~22.04.2 all [upgradable from: 53.0.3ubuntu2~22.04.1]
libgl1/noble 2.0.0-1 amd64 [upgradable from: 1.9.0-1]
"""

APT_URIS = """'http://archive.ubuntu.com/ubuntu/pool/main/g/gcc/gcc_12_amd64.deb' gcc_12.deb 5 size
'http://security.ubuntu.com/ubuntu/pool/main/l/linux/linux-image_6.8_amd64.deb' linux-image 8 size
'http://archive.ubuntu.com/ubuntu/pool/main/f/firefox/firefox_1.0_all.deb' firefox 1 size
'http://archive.ubuntu.com/ubuntu/pool/security/main/o/openssl/openssl_3.0.2_amd64.deb' openssl 4 size
"""

DNF_CHECK_UPDATE = """kernel-core.x86_64                6.8.0-40           baseos       security
bash.x86_64                        5.1.8-7            baseos
"""

PACMAN_QU = """firefox 133.0-2 -> 133.0.3-1
linux 6.10.3.arch1-1 -> 6.10.4.arch1-1
warning: something else
"""

ZYPPER_UPDATES = """v  | main-repo        | firefox        | 133.0 | x86_64
v  | main-repo        | thunderbird    | 128.2 | x86_64
"""

ZYPPER_PATCHES = """v  | openSUSE-backports | openSUSE-2024-100 | security    | important
v  | oss-repo           | some-patch        | recommended | moderate
"""


class AptParserTests(unittest.TestCase):
    def test_upgradable_names_and_skips_listing(self):
        self.assertEqual(
            parse_apt_upgradable(APT_UPGRADABLE),
            ["cairo", "distro-info-data", "libgl1"],
        )

    def test_upgradable_empty_output(self):
        self.assertEqual(parse_apt_upgradable(""), [])
        self.assertEqual(parse_apt_upgradable("Listing... Done\n"), [])

    def test_security_uris_counts_host_and_path_variants(self):
        self.assertEqual(count_apt_security_uris(APT_URIS), 2)

    def test_security_uris_empty(self):
        self.assertEqual(count_apt_security_uris(""), 0)


class DnfParserTests(unittest.TestCase):
    def test_packages_and_security_count(self):
        packages, security = parse_dnf_check_update(DNF_CHECK_UPDATE)
        self.assertEqual(packages, ["kernel-core.x86_64", "bash.x86_64"])
        self.assertEqual(security, 1)

    def test_empty(self):
        self.assertEqual(parse_dnf_check_update(""), ([], 0))


class PacmanParserTests(unittest.TestCase):
    def test_names_and_skips_warnings(self):
        self.assertEqual(parse_pacman_sync_qu(PACMAN_QU), ["firefox", "linux"])

    def test_empty(self):
        self.assertEqual(parse_pacman_sync_qu(""), [])


class ZypperParserTests(unittest.TestCase):
    def test_update_names(self):
        self.assertEqual(parse_zypper_list_updates(ZYPPER_UPDATES), ["firefox", "thunderbird"])

    def test_security_patches_counted(self):
        self.assertEqual(parse_zypper_list_patches(ZYPPER_PATCHES), 1)

    def test_empty(self):
        self.assertEqual(parse_zypper_list_updates(""), [])
        self.assertEqual(parse_zypper_list_patches(""), 0)


if __name__ == "__main__":
    unittest.main()
