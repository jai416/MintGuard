"""Tests de DETECCIÓN: ¿el chequeo atrapa de verdad el caso malo?

El fuzz comprueba que los parsers no revientan. Aquí va lo contrario:
que **no se pasen en silencio**. Para un herramienta de seguridad, un
chequeo que no ve lo que debería ver es peor que un chequeo que se
equivoca: la falsa alarma se nota, el falso negativo no.

Cada test da el caso peligroso y exige que aparezca como hallazgo con
la severidad correcta.
"""

import unittest
from unittest import mock

from mintguard.checks import firewall, permissions, services, updates
from mintguard.checks.firewall import (
    parse_firewall_cmd_state,
    parse_systemctl_is_active,
    parse_ufw_status,
)
from mintguard.checks.permissions import (
    accounts_without_password,
    sudo_members,
    uid_zero_names,
)
from mintguard.checks.services import risky_service_names
from mintguard.checks.updates import (
    parse_apt_sim_security,
    parse_apt_upgradable,
    parse_dnf_check_update,
    parse_pacman_sync_qu,
    parse_zypper_list_patches,
    parse_zypper_list_updates,
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


class FirewallDetectionTests(unittest.TestCase):
    """El estado del firewall lo decide el exit code, no el texto.

    `systemctl is-active` de una unidad que NO existe imprime "inactive"
    y sale con código 4: si se creyera al texto, todo sistema sin
    ufw.service parecería "instalado pero inactivo" (falsa ALTA).
    """

    def test_active_is_detected(self):
        self.assertEqual(parse_systemctl_is_active("active\n", 0), "active")

    def test_inactive_unit_is_detected(self):
        self.assertEqual(parse_systemctl_is_active("inactive\n", 3), "inactive")
        self.assertEqual(parse_systemctl_is_active("failed\n", 3), "inactive")

    def test_nonexistent_unit_is_not_inactive(self):
        # El texto dice "inactive" pero el código es 4: unidad inexistente.
        self.assertIsNone(parse_systemctl_is_active("inactive\n", 4))

    def test_ufw_status_states(self):
        self.assertEqual(parse_ufw_status("Estado: activo\n"), "active")
        self.assertEqual(parse_ufw_status("Estado: inactivo\n"), "inactive")
        self.assertIsNone(parse_ufw_status("Estado: desconocido\n"))
        self.assertIsNone(parse_ufw_status(""))

    def test_firewalld_state(self):
        self.assertEqual(parse_firewall_cmd_state("running\n"), "active")
        self.assertEqual(parse_firewall_cmd_state("not running\n"), "inactive")
        self.assertIsNone(parse_firewall_cmd_state(""))

    def test_inactive_firewall_produces_the_alta_finding(self):
        findings = firewall.comprobar_firewall(DISTRO, "inactive")
        self.assertEqual(findings[0].severity, Severidad.ALTA)
        self.assertIn("no activo", findings[0].title)

    def test_unknown_firewall_is_not_an_alta(self):
        findings = firewall.comprobar_firewall(DISTRO, "desconocido")
        self.assertNotEqual(findings[0].severity, Severidad.ALTA)


class UpdatesDetectionTests(unittest.TestCase):
    """Una actualización de seguridad se cuenta; una normal, no."""

    APT_LIST = (
        "Listing...\n"
        "brave-browser/noble-security,noble-updates 1.2.3 amd64 [upgradable from: 1.2.2]\n"
        "libc6/noble-updates 2.39-1 amd64 [upgradable from: 2.38-1]\n"
    )

    def test_apt_upgradable_is_detected(self):
        packages = parse_apt_upgradable(self.APT_LIST)
        self.assertEqual(packages, ["brave-browser", "libc6"])

    def test_apt_listing_header_is_not_a_package(self):
        self.assertEqual(parse_apt_upgradable("Listing...\n"), [])

    def test_apt_security_estimate_counts_only_security_origins(self):
        text = (
            "Inst brave-browser [1.2.2] (1.2.3 Ubuntu:22.04/noble-security,noble-updates)\n"
            "Inst libc6 [2.38-1] (2.39-1 Ubuntu:22.04/noble-updates)\n"
        )
        count, estimated = parse_apt_sim_security(text)
        self.assertEqual(count, 1)
        self.assertTrue(estimated)

    def test_a_package_named_security_is_not_a_security_update(self):
        # "foo-security" es el NOMBRE del paquete, no su origen.
        text = "Inst foo-security [1.0] (1.1 Ubuntu:22.04/noble-updates)\n"
        count, _ = parse_apt_sim_security(text)
        self.assertEqual(count, 0)

    def test_apt_security_uris_are_counted_exactly(self):
        text = (
            "'http://archive.ubuntu.com/ubuntu/pool/main/f/foo/foo_1.deb' foo_1.deb 1\n"
            "'http://security.ubuntu.com/ubuntu/pool/main/b/bar/bar_1.deb' bar_1.deb 1\n"
        )
        count, estimated = parse_apt_sim_security(text)
        self.assertEqual(count, 1)
        self.assertFalse(estimated)

    def test_dnf_security_column_is_counted(self):
        text = (
            "kernel.x86_64   6.8.0-40.el9   kernel.x86_64\n"
            "openssl.x86_64  3.0.7-25.el9   openssl.x86_64   security\n"
        )
        packages, security = parse_dnf_check_update(text)
        self.assertEqual(len(packages), 2)
        self.assertEqual(security, 1)

    def test_pacman_outdated_is_detected(self):
        text = "linux 6.8.0-1 -> 6.8.1-1\n"
        self.assertEqual(parse_pacman_sync_qu(text), ["linux"])

    def test_zypper_update_and_patch_are_detected(self):
        # Formato real de `zypper list-updates`: las filas empiezan por "v ".
        updates_text = (
            "S | Repository | Name  | Version | Arch\n"
            "--+----------+-------+---------+-------\n"
            "v | updates   | zsh   | 5.9-1   | x86_64\n"
        )
        self.assertEqual(parse_zypper_list_updates(updates_text), ["zsh"])
        patches_text = (
            "S | Repository | Name | Category | Severity | Arch\n"
            "--+----------+------+---------+----------+-------\n"
            "v | security   | zsh  | security | important | x86_64\n"
        )
        self.assertEqual(parse_zypper_list_patches(patches_text), 1)

    def test_security_updates_raise_the_severity(self):
        # Con parches de seguridad el hallazgo es ALTA; sin ellos, MEDIA.
        lista = "Listing...\nfoo/noble-security 1.0 amd64 [upgradable from: 0.9]\n"
        simulacion = "Inst foo [0.9] (1.0 Ubuntu:22.04/noble-security)\n"

        def fake_run(cmd, timeout=300):
            if "list" in cmd:
                return mock.Mock(returncode=0, stdout=lista, stderr="")
            return mock.Mock(returncode=0, stdout=simulacion, stderr="")

        with mock.patch.object(updates, "run_command", side_effect=fake_run):
            with mock.patch.object(updates, "resolve_binary", return_value="/usr/bin/apt-get"):
                findings = updates.comprobar_actualizaciones(DISTRO)
        self.assertEqual(findings[0].severity, Severidad.ALTA)

    def test_normal_updates_severity_follows_the_count(self):
        # Pocos paquetes sin seguridad → BAJA; muchos → MEDIA.
        def findings_for(total: int):
            lista = "Listing...\n" + "".join(
                f"pkg{i}/noble-updates 1.0 amd64 [upgradable from: 0.9]\n"
                for i in range(total)
            )
            simulacion = "Inst pkg [0.9] (1.0 Ubuntu:22.04/noble-updates)\n"

            def fake_run(cmd, timeout=300):
                if "list" in cmd:
                    return mock.Mock(returncode=0, stdout=lista, stderr="")
                return mock.Mock(returncode=0, stdout=simulacion, stderr="")

            with mock.patch.object(updates, "run_command", side_effect=fake_run):
                with mock.patch.object(
                    updates, "resolve_binary", return_value="/usr/bin/apt-get"
                ):
                    return updates.comprobar_actualizaciones(DISTRO)

        self.assertEqual(findings_for(1)[0].severity, Severidad.BAJA)
        self.assertEqual(findings_for(12)[0].severity, Severidad.MEDIA)


class PermissionsDetectionTests(unittest.TestCase):
    """Los casos peligrosos de /etc y de sshd se ven."""

    def test_extra_uid_zero_is_detected(self):
        lines = [
            "root:x:0:0:root:/root:/bin/bash\n",
            "servicio:x:0:0:servicio:/srv:/bin/false\n",
        ]
        self.assertEqual(uid_zero_names(lines), ["root", "servicio"])

    def test_account_without_password_is_detected(self):
        lines = ["root:$6$hash:19000:0:99999:7:::\n", "vacio::19000:0:99999:7:::\n"]
        self.assertEqual(accounts_without_password(lines), ["vacio"])

    def test_locked_account_is_not_without_password(self):
        lines = ["root:!:19000:0:99999:7:::\n", "x:*:19000:0:99999:7:::\n"]
        self.assertEqual(accounts_without_password(lines), [])

    def test_sudo_group_members_are_detected(self):
        lines = ["sudo:x:27:alice,bob,alice\n"]
        groups, members = sudo_members(lines)
        self.assertEqual(groups, ["sudo"])
        self.assertEqual(members, ["alice", "bob"])

    def test_uid_zero_finding_is_critica(self):
        # Solo root con UID 0 es lo esperado (INFO); un segundo UID 0, no.
        with mock.patch.object(
            permissions, "_read_lines", return_value=["root:x:0:0::/root:/bin/bash\n"]
        ):
            findings = permissions._check_uid_zero()
        self.assertEqual(findings[0].severity, Severidad.INFO)
        with mock.patch.object(
            permissions,
            "_read_lines",
            return_value=["root:x:0:0::/root:/bin/bash\n", "servicio:x:0:0::/srv:/bin/false\n"],
        ):
            findings = permissions._check_uid_zero()
        self.assertEqual(findings[0].severity, Severidad.CRITICA)
        self.assertIn("servicio", findings[0].evidence)

    def test_empty_password_finding_is_critica(self):
        with mock.patch.object(permissions, "_read_lines", return_value=["vacio::1:2:::\n"]):
            findings = permissions._check_empty_passwords()
        self.assertEqual(findings[0].severity, Severidad.CRITICA)

    def test_sshd_root_login_is_detected(self):
        with mock.patch.object(
            permissions, "_read_lines", return_value=["PermitRootLogin yes\n"]
        ):
            findings = permissions._check_sshd_config()
        self.assertTrue(any(f.severity == Severidad.ALTA for f in findings))

    def test_sshd_password_auth_is_detected(self):
        with mock.patch.object(
            permissions, "_read_lines", return_value=["PasswordAuthentication yes\n"]
        ):
            findings = permissions._check_sshd_config()
        self.assertTrue(any(f.severity == Severidad.MEDIA for f in findings))

    def test_unreadable_passwd_is_reported_not_ignored(self):
        # Un fichero que no se puede leer NO es "todo bien": se dice.
        with mock.patch.object(permissions, "_read_lines", return_value=None):
            findings = permissions._check_uid_zero()
        self.assertEqual(findings[0].severity, Severidad.BAJA)
        self.assertIn("No se pudo leer", findings[0].title)


class ServicesDetectionTests(unittest.TestCase):
    """Los servicios de acceso remoto heredado se detectan."""

    def test_risky_services_are_detected(self):
        names = risky_service_names(
            ["telnetd.service", "tftp.service", "rsh.service", "rlogin.service"]
        )
        self.assertEqual(len(names), 4)

    def test_templated_unit_is_detected(self):
        self.assertEqual(risky_service_names(["tftp@.service"]), ["tftp@.service"])

    def test_lookalike_is_not_a_false_positive(self):
        # "rshim" contiene "rsh" pero no es un servicio de acceso remoto.
        self.assertEqual(risky_service_names(["rshim.service"]), [])

    def test_normal_services_are_not_flagged(self):
        self.assertEqual(risky_service_names(["sshd.service", "cron.service"]), [])

    def test_enabled_service_finding_is_produced(self):
        with mock.patch.object(
            services, "resolve_binary", return_value="/usr/bin/systemctl"
        ):
            with mock.patch.object(
                services,
                "run_command",
                return_value=mock.Mock(returncode=0, stdout="telnetd.service enabled\n"),
            ):
                findings = services.comprobar_servicios(DISTRO)
        self.assertTrue(any("telnet" in f.title.lower() for f in findings))


if __name__ == "__main__":
    unittest.main()
