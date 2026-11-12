"""Tests for the severity model and prioritization."""

import unittest

from mintguard.core.prioritizer import Finding, Severidad, priorizar, resumen, riesgo_global


def _finding(severity: Severidad, title: str = "t") -> Finding:
    return Finding(title=title, severity=severity, source="test")


class PriorizarTests(unittest.TestCase):
    def test_sorted_from_worst_to_best(self):
        findings = [
            _finding(Severidad.INFO, "info"),
            _finding(Severidad.CRITICA, "critica"),
            _finding(Severidad.MEDIA, "media"),
            _finding(Severidad.BAJA, "baja"),
            _finding(Severidad.ALTA, "alta"),
        ]
        ordered = priorizar(findings)
        self.assertEqual(
            [f.severity for f in ordered],
            [Severidad.CRITICA, Severidad.ALTA, Severidad.MEDIA, Severidad.BAJA, Severidad.INFO],
        )


class ResumenTests(unittest.TestCase):
    def test_counts_every_severity_key(self):
        counts = resumen([_finding(Severidad.MEDIA), _finding(Severidad.MEDIA), _finding(Severidad.CRITICA)])
        self.assertEqual(counts["MEDIA"], 2)
        self.assertEqual(counts["CRITICA"], 1)
        self.assertEqual(counts["ALTA"], 0)
        self.assertEqual(set(counts), {"INFO", "BAJA", "MEDIA", "ALTA", "CRITICA"})


class RiesgoGlobalTests(unittest.TestCase):
    def test_no_findings(self):
        self.assertEqual(riesgo_global([]), "SIN DATOS")

    def test_worst_wins(self):
        self.assertEqual(riesgo_global([_finding(Severidad.INFO), _finding(Severidad.ALTA)]), "ALTA")


if __name__ == "__main__":
    unittest.main()
