import unittest
from detector import Detector


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


def syn(src, dst, dport, category="web", risk="LOW", app="HTTPS"):
    return {"src_ip": src, "dst_ip": dst, "src_port": 40000, "dst_port": dport,
            "protocol": "TCP", "tcp_flags": "SYN", "category": category,
            "risk": risk, "app_protocol": app,
            "risk_reason": "Administración remota: objetivo habitual de fuerza bruta"}


def ssh(src="10.0.0.5", dst="45.33.32.156"):
    return syn(src, dst, 22, "acceso_remoto", "MEDIUM", "SSH")


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.clk = FakeClock()
        self.d = Detector(clock=self.clk)

    def test_trafico_normal_no_alerta(self):
        self.assertEqual(self.d.analyze(syn("10.0.0.5", "1.1.1.1", 443)), [])

    def test_paquetes_no_syn_se_ignoran(self):
        ev = ssh(); ev["tcp_flags"] = "SYN,ACK"
        self.assertEqual(self.d.analyze(ev), [])
        ev["tcp_flags"] = "ACK,PSH"
        self.assertEqual(self.d.analyze(ev), [])

    def test_primer_ssh_da_medium(self):
        a = self.d.analyze(ssh())
        self.assertEqual([x.severity for x in a], ["MEDIUM"])
        self.assertEqual(a[0].rule, "remote_access")

    def test_fuerza_bruta_da_high(self):
        sev = []
        for _ in range(5):
            sev += [x.severity for x in self.d.analyze(ssh())]
            self.clk.t += 2
        self.assertEqual(sev, ["MEDIUM", "HIGH"])

    def test_cooldown_evita_spam(self):
        total = []
        for _ in range(20):
            total += self.d.analyze(ssh())
            self.clk.t += 1
        self.assertEqual(len(total), 2)  # 1 MEDIUM + 1 HIGH

    def test_ventana_expira(self):
        for _ in range(4):
            self.d.analyze(ssh()); self.clk.t += 1
        self.clk.t += 120  # los 4 intentos salen de la ventana
        self.assertEqual([x.rule for x in self.d.analyze(ssh())], ["remote_access"])

    def test_escaneo_de_puertos(self):
        rules = []
        for p in range(20, 32):
            rules += [x.rule for x in self.d.analyze(syn("10.0.0.5", "45.33.32.156", p))]
            self.clk.t += 0.5
        self.assertEqual(rules, ["port_scan"])

    def test_mismo_puerto_no_es_escaneo(self):
        for _ in range(30):
            self.assertNotIn("port_scan",
                             [x.rule for x in self.d.analyze(syn("10.0.0.5", "1.1.1.1", 443))])
            self.clk.t += 0.5


if __name__ == "__main__":
    unittest.main()