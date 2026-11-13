"""Parsing tests for the package-manager outputs.

A broken parser here produces false negatives in security, which is the
worst failure mode of this tool: the user believes they are protected
when they are not.
"""

import unittest
from unittest import mock

from mintguard.checks.updates import (
    _cache_is_stale,
    _check_dnf,
    _check_pacman,
    _stale_cache_finding,
    _updates_finding,
    count_apt_security_uris,
    parse_apt_sim_security,
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

# Real `apt-get -s dist-upgrade --print-uris` output WITHOUT root
# (verified on Mint 22.3, 2026-11-13): rc 0, 49 Inst lines, ZERO .deb
# URIs. The old count_apt_security_uris returned 0 on it — security
# was silently never reported without sudo.
APT_SIM_NOROOT = """Inst libc6-dbg [2.39-0ubuntu8.9] (2.39-0ubuntu8.12 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]) []
Inst libc6 [2.39-0ubuntu8.9] (2.39-0ubuntu8.12 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst brave-browser [1.99.55] (1.99.57 Brave Browser:stable [amd64]) []
Inst mongodb-mongosh [2.14.1] (2.14.2 mongodb:jammy/mongodb-org/7.0 [amd64]) []
"""

DNF_CHECK_UPDATE = """kernel-core.x86_64                6.8.0-40           baseos       security
bash.x86_64                        5.1.8-7            baseos
"""

# Real output captured from dnf5 5.4.6.0 (Fedora 45, container): header
# "Upgrades", name.arch / version / repo columns, exit 100. The repo
# column is "updates" even for security updates.
DNF5_CHECK_UPDATE = """Upgrades
curl.x86_64            8.21.0-9.fc45     updates
dnf5.x86_64            5.4.7.0-1.fc45    updates
libcurl.x86_64         8.21.0-9.fc45     updates
pcre2-syntax.noarch    10.49-1.fc45      updates
tzdata.noarch          2026f-1.fc45      updates
vim-minimal.x86_64     2:9.2.1302-2.fc45 updates
"""

# Real output of `dnf5 check-upgrade --security` in the same container
# (6 of the 18 total updates; subset of the list above).
DNF5_CHECK_UPGRADE_SECURITY = """Upgrades
curl.x86_64         8.21.0-9.fc45 updates
libcurl.x86_64      8.21.0-9.fc45 updates
libmodulemd.x86_64  2.15.4-1.fc45 updates
pcre2.x86_64        10.49-1.fc45  updates
pcre2-syntax.noarch 10.49-1.fc45  updates
tpm2-tss.x86_64     4.2.1-1.fc45  updates
"""

PACMAN_QU = """firefox 133.0-2 -> 133.0.3-1
linux 6.10.3.arch1-1 -> 6.10.4.arch1-1
rsync 3.3.0-1 -> r3905.85f0-1
warning: something else
"""

ZYPPER_UPDATES = """S  | Repository                 | Name               | Current Version | Available Version | Arch
---+----------------------------+--------------------+-----------------+-------------------+-------
v  | openSUSE-Tumbleweed-Update | openSUSE-build-key | 1.0-68.1        | 1.0-69.1          | x86_64
v  | main-repo                  | firefox            | 133.0           | 133.0.1           | x86_64
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

    def test_security_uris_host_label_must_be_security(self):
        # `security.ubuntu.com` counts; `insecurity.example.com` must not
        # (a naive `"security" in host` check would count it).
        text = (
            "'http://security.debian.org/debian-security/pool/x.deb' a 1 size\n"
            "'http://insecurity.example.com/pool/y.deb' b 1 size\n"
        )
        self.assertEqual(count_apt_security_uris(text), 1)


class AptSimSecurityTests(unittest.TestCase):
    """parse_apt_sim_security over both real formats of the simulation."""

    def test_without_root_counts_inst_security_origins(self):
        # Real no-root output: 2 of the 4 Inst lines come from
        # noble-security; the third-party lines must not count.
        self.assertEqual(parse_apt_sim_security(APT_SIM_NOROOT), 2)

    def test_package_named_like_security_does_not_count(self):
        # Only the parenthesised origin section is searched.
        text = "Inst foo-security [1.0] (2.0 main-repo [amd64]) []\n"
        self.assertEqual(parse_apt_sim_security(text), 0)

    def test_with_root_keeps_uri_counting(self):
        self.assertEqual(parse_apt_sim_security(APT_URIS), 2)

    def test_empty(self):
        self.assertEqual(parse_apt_sim_security(""), 0)


class StaleCacheTests(unittest.TestCase):
    """C1: without root the apt index may be weeks old — declare it."""

    def test_cache_is_stale_threshold(self):
        week = 7 * 86400
        self.assertTrue(_cache_is_stale(1000.0, 1000.0 + week + 1))
        self.assertFalse(_cache_is_stale(1000.0, 1000.0 + week - 1))
        self.assertFalse(_cache_is_stale(1000.0, 1000.0 + week))  # exactly at the line

    def test_finding_declared_when_stale(self):
        with mock.patch("mintguard.checks.updates._apt_lists_mtime", return_value=1000.0):
            finding = _stale_cache_finding(now=1000.0 + 8 * 86400)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity.name, "BAJA")
        self.assertIn("desactualizada", finding.title)
        self.assertIn("apt-get update", finding.suggestion)

    def test_no_finding_when_fresh(self):
        with mock.patch("mintguard.checks.updates._apt_lists_mtime", return_value=1000.0):
            self.assertIsNone(_stale_cache_finding(now=1000.0 + 3600))

    def test_no_finding_when_unreadable(self):
        with mock.patch("mintguard.checks.updates._apt_lists_mtime", return_value=None):
            self.assertIsNone(_stale_cache_finding())


class UpdatesFindingTests(unittest.TestCase):
    """Decision matrix of the updates severity (the most important check)."""

    def test_no_updates_is_info(self):
        (finding,) = _updates_finding("apt", [], 0)
        self.assertEqual(finding.severity.name, "INFO")
        self.assertIn("No hay actualizaciones", finding.title)

    def test_security_updates_are_alta(self):
        (finding,) = _updates_finding("apt", ["a"], 1)
        self.assertEqual(finding.severity.name, "ALTA")

    def test_many_updates_are_media(self):
        (finding,) = _updates_finding("apt", [f"p{i}" for i in range(10)], 0)
        self.assertEqual(finding.severity.name, "MEDIA")

    def test_few_updates_are_baja(self):
        (finding,) = _updates_finding("apt", ["a", "b"], 0)
        self.assertEqual(finding.severity.name, "BAJA")

    def test_unknown_security_keeps_count_severity(self):
        (finding,) = _updates_finding("pacman", ["a"], None)
        self.assertEqual(finding.severity.name, "BAJA")
        self.assertIn("No se pudo estimar", finding.detail)

    def test_no_packages_is_no_updates_even_if_security_unknown(self):
        # The checkers call this only with a parsed package list; with zero
        # packages the INFO "no updates" is the correct verdict.
        (finding,) = _updates_finding("pacman", [], None)
        self.assertEqual(finding.severity.name, "INFO")
        self.assertIn("No hay actualizaciones", finding.title)


class ReturncodeTests(unittest.TestCase):
    """A failing manager must be BAJA "unavailable", never INFO "no updates"."""

    def _result(self, returncode, stdout=""):
        return mock.Mock(returncode=returncode, stdout=stdout)

    def test_pacman_failure_is_unavailable(self):
        with mock.patch("mintguard.checks.updates._run", return_value=self._result(1)):
            (finding,) = _check_pacman("/usr/bin/pacman")
        self.assertEqual(finding.severity.name, "BAJA")
        self.assertIn("No se pudo consultar pacman", finding.title)

    def test_pacman_success_is_parsed(self):
        with mock.patch(
            "mintguard.checks.updates._run",
            return_value=self._result(0, "firefox 1.0 -> 2.0\n"),
        ):
            (finding,) = _check_pacman("/usr/bin/pacman")
        self.assertEqual(finding.severity.name, "BAJA")
        self.assertIn("1 actualización", finding.title)


class DnfParserTests(unittest.TestCase):
    def test_packages_and_security_count(self):
        # Legacy dnf4-style line with a "security" repo column.
        packages, security = parse_dnf_check_update(DNF_CHECK_UPDATE)
        self.assertEqual(packages, ["kernel-core.x86_64", "bash.x86_64"])
        self.assertEqual(security, 1)

    def test_dnf5_real_output(self):
        # Real dnf5 5.4.6.0 output: repo column says "updates" for every
        # line, so the column-based security count is 0 here (security
        # detection must come from check-upgrade --security instead).
        packages, security = parse_dnf_check_update(DNF5_CHECK_UPDATE)
        self.assertEqual(
            packages,
            [
                "curl.x86_64",
                "dnf5.x86_64",
                "libcurl.x86_64",
                "pcre2-syntax.noarch",
                "tzdata.noarch",
                "vim-minimal.x86_64",
            ],
        )
        self.assertEqual(security, 0)

    def test_empty(self):
        self.assertEqual(parse_dnf_check_update(""), ([], 0))


class CheckDnfTests(unittest.TestCase):
    """_check_dnf against the real dnf5 behaviours captured in a container."""

    def _result(self, returncode, stdout="", stderr=""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_security_updates_are_alta_with_exact_count(self):
        results = [
            self._result(100, DNF5_CHECK_UPDATE),
            self._result(100, DNF5_CHECK_UPGRADE_SECURITY),
        ]
        with mock.patch("mintguard.checks.updates._run", side_effect=results):
            (finding,) = _check_dnf("/usr/bin/dnf")
        self.assertEqual(finding.severity.name, "ALTA")
        self.assertIn("6 proceden", finding.detail)
        self.assertNotIn("Aproximadamente", finding.detail)

    def test_metadata_failure_is_unavailable(self):
        with mock.patch(
            "mintguard.checks.updates._run",
            return_value=self._result(1, "", stderr="Failed to download metadata"),
        ):
            (finding,) = _check_dnf("/usr/bin/dnf")
        self.assertEqual(finding.severity.name, "BAJA")
        self.assertIn("No se pudo consultar dnf", finding.title)

    def test_fallback_to_check_update_security(self):
        results = [
            self._result(100, DNF5_CHECK_UPDATE),
            self._result(2, "", stderr='Unknown argument "--security"'),
            self._result(100, DNF5_CHECK_UPGRADE_SECURITY),
        ]
        with mock.patch("mintguard.checks.updates._run", side_effect=results):
            (finding,) = _check_dnf("/usr/bin/dnf")
        self.assertIn("6 proceden", finding.detail)

    def test_unknown_security_is_declared(self):
        results = [
            self._result(100, DNF5_CHECK_UPDATE),
            self._result(2, "", stderr="Unknown argument"),
            self._result(2, "", stderr="Unknown argument"),
        ]
        with mock.patch("mintguard.checks.updates._run", side_effect=results):
            (finding,) = _check_dnf("/usr/bin/dnf")
        self.assertIn("No se pudo estimar", finding.detail)


class PacmanParserTests(unittest.TestCase):
    def test_names_and_skips_warnings(self):
        self.assertEqual(parse_pacman_sync_qu(PACMAN_QU), ["firefox", "linux", "rsync"])

    def test_empty(self):
        self.assertEqual(parse_pacman_sync_qu(""), [])


class ZypperParserTests(unittest.TestCase):
    def test_update_names(self):
        # Real header captured from zypper 1.14.102 in a Tumbleweed
        # container: "S | Repository | Name | ..." starts with "S" and
        # must be skipped; data lines start with "v ".
        self.assertEqual(
            parse_zypper_list_updates(ZYPPER_UPDATES),
            ["openSUSE-build-key", "firefox"],
        )

    def test_security_patches_counted(self):
        self.assertEqual(parse_zypper_list_patches(ZYPPER_PATCHES), 1)

    def test_empty(self):
        self.assertEqual(parse_zypper_list_updates(""), [])
        self.assertEqual(parse_zypper_list_patches(""), 0)


if __name__ == "__main__":
    unittest.main()
