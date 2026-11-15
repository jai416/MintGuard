"""Fuzz de los parsers: entradas adversarias, ninguna debe romper nada.

Un parser roto produce falsos negativos de seguridad, que es el peor
fallo posible de esta herramienta. Aquí se les pasa basura (bytes no
UTF-8, escapes ANSI, líneas de 10 000 caracteres, campos vacíos, números
absurdos) y se comprueba que:

1. ninguno lanza una excepción;
2. el resultado tiene el tipo y el tamaño que se espera (sin amplificar
   la entrada: un parser que devuelve 3000 elementos por una línea está
   tan roto como uno que revienta);
3. el contrato de privacidad se cumple siempre: una IP concreta en el
   texto NUNCA sobrevive al enmascarado.

El azar va con semilla fija: si un caso falla, falla siempre igual.
"""

import random
import unittest

from mintguard.checks.firewall import (
    parse_firewall_cmd_state,
    parse_systemctl_is_active,
    parse_ufw_status,
)
from mintguard.checks.hardening import (
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
from mintguard.checks.permissions import (
    external_sshd_includes,
    merge_sshd_texts,
    sshd_match_blocks,
    sshd_settings,
    sudo_members,
    uid_zero_names,
)
from mintguard.checks.services import enabled_service_names, risky_service_names
from mintguard.checks.updates import (
    parse_apt_sim_security,
    parse_apt_upgradable,
    parse_dnf_check_update,
    parse_pacman_sync_qu,
    parse_zypper_list_patches,
    parse_zypper_list_updates,
)
from mintguard.core.expected_services import classify, context_is_authentic
from mintguard.core.exposure import (
    classify_address,
    interface_nature,
    parse_ss_line,
    service_name,
    socket_nature,
    worst_nature,
)
from mintguard.core.prioritizer import (
    Finding,
    Severidad,
    priorizar,
    resumen,
    riesgo_global,
)
from mintguard.core.text import sanitize
from mintguard.reporting.reporter import _mask_concrete_ips

SEED = 20261115

_ADVERSARIAL = [
    "",
    " ",
    "\n",
    "\r\n",
    "\t\t",
    "\x00",
    "\x1b[31mrojo\x1b[0m",
    "\x1b]0;window title\x07",
    "�",
    "áéíóúñÜ",
    "\U0001d54a",  # fuera del BMP
    "a" * 10000,
    ("a\n" * 500),
    ("a:b:c:d:e:f\n" * 100),
    "0",
    "-1",
    "999999999999999999999999",
    "0x1f",
    "::",
    ":::",
    "::ffff:127.0.0.1",
    "0.0.0.0%",
    "%zone",
    "100.99.183.44%tailscale0:443",
    "fd7a:9918:1e6c::cd45:22",
    'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=2))',
    'users:(("name with spaces",pid=42,fd=3))',
    "sudo vim *",
    "NOPASSWD: ALL",
    "Inst foo -security",
    "tcp LISTEN 0 4096 0.0.0.0:99999 0.0.0.0:*",
    "tcp LISTEN 0 4096 0.0.0.0:-1 0.0.0.0:*",
    "tcp LISTEN 0 4096 0.0.0.0:abc 0.0.0.0:*",
    "one two",
    "root:x:0:0:root:/root:/bin/bash",
    "root::0:0:root:/root:/bin/bash",
    ":x:0:0:::",
    "PermitRootLogin yes",
    "Match User foo",
    "Include /etc/ssh/sshd_config.d/*.conf",
    "Core file size  0  unlimited  bytes",
    "Core file size",
    "|handler %P",
    "Vulnerable: spectre",
    "Not affected",
    "Mitigation: IBRS",
    "1",
    "4097",
    "8193",
    "-1",
    "65536",
    "0100007F:1F90",
]


def _garbage(rng: random.Random) -> str:
    """Línea aleatoria con mezcla de clases de caracteres."""
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        " \t:;/,.=*@#$%^&()[]{}<>|\\\"'-+_~"
        "áéíóúñÁÉÍÓÚÑ€·—…"
        "\x00\x01\x1b\x7f"
    )
    length = rng.randint(0, 120)
    return "".join(rng.choice(alphabet) for _ in range(length))


class ParserRobustnessTests(unittest.TestCase):
    """Ningún parser revienta con basura; el tamaño de salida es razonable."""

    def _corpus(self) -> list[str]:
        rng = random.Random(SEED)
        return _ADVERSARIAL + [_garbage(rng) for _ in range(120)]

    def _assert_no_crash(self, name: str, func, *args) -> None:
        for case in self._corpus():
            with self.subTest(parser=name, case=case[:40]):
                func(*args, case)

    def test_apt_parsers_survive_garbage(self):
        self._assert_no_crash("parse_apt_upgradable", parse_apt_upgradable)
        self._assert_no_crash("parse_apt_sim_security", parse_apt_sim_security)

    def test_dnf_pacman_zypper_parsers_survive_garbage(self):
        self._assert_no_crash("parse_dnf_check_update", parse_dnf_check_update)
        self._assert_no_crash("parse_pacman_sync_qu", parse_pacman_sync_qu)
        self._assert_no_crash("parse_zypper_list_updates", parse_zypper_list_updates)
        self._assert_no_crash("parse_zypper_list_patches", parse_zypper_list_patches)

    def test_firewall_parsers_survive_garbage(self):
        self._assert_no_crash("parse_ufw_status", parse_ufw_status)
        self._assert_no_crash("parse_firewall_cmd_state", parse_firewall_cmd_state)
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                parse_systemctl_is_active(case, 0)
                parse_systemctl_is_active(case, 1)

    def test_services_parsers_survive_garbage(self):
        self._assert_no_crash("enabled_service_names", enabled_service_names)
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                risky_service_names([case])

    def test_permissions_parsers_survive_garbage(self):
        self._assert_no_crash("sshd_settings", sshd_settings)
        self._assert_no_crash("sshd_match_blocks", sshd_match_blocks)
        self._assert_no_crash("external_sshd_includes", external_sshd_includes)
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                uid_zero_names([case])
                sudo_members([case])
                merge_sshd_texts([case], [[case]])

    def test_exposure_parsers_survive_garbage(self):
        self._assert_no_crash("parse_ss_line", parse_ss_line)
        self._assert_no_crash("classify_address", classify_address)
        self._assert_no_crash("socket_nature", socket_nature)
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                interface_nature(case, case)
                classify(case, case, 0, case)
                context_is_authentic(case, 1, case)
                service_name(22, case)

    def test_hardening_parsers_survive_garbage(self):
        self._assert_no_crash("parse_tainted", parse_tainted)
        self._assert_no_crash("parse_core_limit", parse_core_limit)
        self._assert_no_crash("parse_vulnerability_status", parse_vulnerability_status)
        self._assert_no_crash("parse_apparmor_profiles", parse_apparmor_profiles)
        self._assert_no_crash("parse_kernel_errors", parse_kernel_errors)
        self._assert_no_crash("parse_desktop_exec", parse_desktop_exec)
        self._assert_no_crash("parse_suspicious_commands", parse_suspicious_commands)
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                parse_sudoers_rules([case])
                parse_sudoers_aliases([case])

    def test_sanitize_never_raises(self):
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                self.assertIsInstance(sanitize(case), str)


class OutputInvariantsTests(unittest.TestCase):
    """El tipo y el tamaño de la salida son los esperados."""

    _SCOPES = {"todas", "local", "interfaz"}
    _NATURES = {
        "public",
        "lan",
        "cgnat",
        "loopback",
        "link-local",
        "virtual",
        "unknown",
    }
    _TAGS = {"tailscale", "libvirt", "avahi"}

    def _corpus(self) -> list[str]:
        rng = random.Random(SEED + 1)
        return _ADVERSARIAL + [_garbage(rng) for _ in range(120)]

    def test_ss_parser_returns_a_sane_socket_or_none(self):
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                socket = parse_ss_line(case)
                if socket is None:
                    continue
                self.assertIn(socket.scope, self._SCOPES)
                self.assertIsInstance(socket.port, int)
                self.assertGreaterEqual(socket.port, 0)
                self.assertLessEqual(socket.port, 65535)
                self.assertIn(socket.protocol, {"tcp", "udp", "tcp6", "udp6", "raw"})

    def test_classifiers_return_known_values(self):
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                self.assertIn(classify_address(case), self._SCOPES)
                self.assertIn(interface_nature(case, case), self._NATURES)
                self.assertIn(socket_nature(case), self._NATURES)
                self.assertIn(worst_nature([case]), self._NATURES)
                tag = classify(case, case, 22, case)
                self.assertIn(tag, self._TAGS | {None})
                self.assertIsInstance(context_is_authentic(case, 1, tag), bool)

    def test_parsers_do_not_amplify_their_input(self):
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                lines = case.splitlines()
                self.assertLessEqual(len(parse_apt_upgradable(case)), max(len(lines), 1))
                self.assertLessEqual(len(enabled_service_names(case)), max(len(lines), 1))
                self.assertLessEqual(len(external_sshd_includes(case)), max(len(lines), 1))
                packages, security = parse_dnf_check_update(case)
                self.assertLessEqual(len(packages), max(len(lines), 1))
                self.assertIsInstance(security, int)

    def test_merge_sshd_texts_keeps_every_line(self):
        # Las líneas del principal siempre sobreviven; los drop-ins solo
        # se mezclan si el principal incluye el directorio (y la basura
        # puede traer su propio "include", que también cuenta).
        for case in self._corpus():
            with self.subTest(case=case[:40]):
                merged = merge_sshd_texts([case], [[case], [case]])
                self.assertIn(case, merged)
                self.assertIn(len(merged), (1, 3))


class PrivacyPropertyTests(unittest.TestCase):
    """Una IP concreta en el texto NUNCA sobrevive al enmascarado.

    Es el contrato de privacidad del reporte: si esto se rompe, el
    informe filtraría la dirección de la máquina de quien lo genera.
    """

    def _addresses(self) -> list[str]:
        rng = random.Random(SEED + 2)
        addresses = [
            "192.168.1.5",
            "10.0.0.100",
            "172.16.254.3",
            "100.99.183.44",
            "8.8.8.8",
            "203.0.113.77",
            "fd7a:9918:1e6c::cd45",
            "fd00::5",
            "fe80::250:56ff:fec0:1",
            "2601:646:9e00:abcd:1234:5678:9abc:def0",
            "2001:db8:85a3::8a2e:370:7334",
        ]
        for _ in range(40):
            addresses.append(f"{rng.randint(1, 254)}.{rng.randint(0, 255)}."
                             f"{rng.randint(0, 255)}.{rng.randint(1, 254)}")
            addresses.append("fd" + ":".join(f"{rng.randrange(0x10000):04x}" for _ in range(3))
                             + "::" + f"{rng.randrange(0x10000):x}")
        return addresses

    def test_concrete_addresses_never_survive_masking(self):
        for address in self._addresses():
            for template in (
                "Escuchando en {a}:443",
                "TCP {a}:22",
                "origen {a}, destino {a}:80",
                "{a}",
                "en la interfaz {a} desde {a}",
            ):
                text = template.format(a=address)
                masked = _mask_concrete_ips(text)
                with self.subTest(address=address, template=template):
                    self.assertNotIn(address, masked)

    def test_masking_never_grows_the_text_hugely(self):
        for address in self._addresses():
            text = f"TCP {address}:443"
            masked = _mask_concrete_ips(text)
            self.assertLessEqual(len(masked), len(text) + 8)

    def test_wildcards_and_zones_stay_visible(self):
        # El comodín y la zona son estructurales: no son datos identificativos.
        for text in (
            "TCP 0.0.0.0:22",
            "UDP :::41641",
            "UDP 0.0.0.0%virbr0:67",
            "TCP 0.0.0.0%tailscale0:443",
        ):
            with self.subTest(text=text):
                self.assertEqual(_mask_concrete_ips(text), text)


class PrioritizerFuzzTests(unittest.TestCase):
    """priorizar/resumen/riesgo_global con hallazgos raros."""

    def test_empty_and_duplicate_findings(self):
        self.assertEqual(priorizar([]), [])
        self.assertEqual(resumen([]), {s.name: 0 for s in Severidad})
        self.assertEqual(riesgo_global([]), "SIN DATOS")
        finding = Finding(title="x", severity=Severidad.INFO)
        self.assertEqual(priorizar([finding, finding]), [finding, finding])

    def test_findings_with_odd_fields(self):
        findings = [
            Finding(title="", severity=Severidad.ALTA, detail="", evidence=[], suggestion=""),
            Finding(title="\x1b[31m", severity=Severidad.BAJA, evidence=["x" * 5000]),
        ]
        ordered = priorizar(findings)
        self.assertEqual(len(ordered), 2)
        self.assertEqual(ordered[0].severity, Severidad.ALTA)
        self.assertEqual(sum(resumen(findings).values()), 2)


if __name__ == "__main__":
    unittest.main()
