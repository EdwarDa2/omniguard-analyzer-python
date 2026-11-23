import unittest
from unittest.mock import MagicMock, patch
import requests

from detector import Alert
from notifier import CoreBackendNotifier


class CoreBackendNotifierTests(unittest.TestCase):
    def setUp(self):
        self.notifier = CoreBackendNotifier(
            base_url="http://omniguard-core:8080/api/v1",
            internal_token="secret_token_123"
        )
        self.sample_event = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "src_port": 50000,
            "dst_port": 22,
            "protocol": "TCP",
            "category": "acceso_remoto",
            "app_protocol": "SSH",
            "tcp_flags": "SYN"
        }
        self.sample_alert = Alert(
            severity="HIGH",
            rule="bruteforce",
            title="Posible fuerza bruta sobre SSH",
            description="5 intentos en 60s",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
            dst_port=22,
            event=self.sample_event
        )

    def test_alert_properties(self):
        self.assertEqual(self.sample_alert.category, "acceso_remoto")
        self.assertEqual(self.sample_alert.protocol, "TCP")
        self.assertEqual(self.sample_alert.app_protocol, "SSH")

    def test_alert_properties_default(self):
        raw_alert = Alert(
            severity="MEDIUM",
            rule="remote_access",
            title="Acceso remoto",
            description="desc",
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            dst_port=80,
            event={}
        )
        self.assertEqual(raw_alert.category, "remote_access")
        self.assertEqual(raw_alert.protocol, "TCP")
        self.assertEqual(raw_alert.app_protocol, "Desconocido")

    @patch("notifier.requests.post")
    def test_send_alert_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_post.return_value = mock_response

        success = self.notifier.send(self.sample_alert)
        self.assertTrue(success)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "http://omniguard-core:8080/api/v1/internal/alerts")
        self.assertEqual(kwargs["headers"]["X-Internal-Token"], "secret_token_123")
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")

        payload = kwargs["json"]
        self.assertEqual(payload["threat_type"], "acceso_remoto")
        self.assertEqual(payload["rule"], "bruteforce")
        self.assertEqual(payload["severity"], "HIGH")
        self.assertEqual(payload["title"], "Posible fuerza bruta sobre SSH")
        self.assertEqual(payload["source_ip"], "10.0.0.5")
        self.assertEqual(payload["destination_ip"], "10.0.0.9")
        self.assertEqual(payload["destination_port"], 22)
        self.assertEqual(payload["protocol"], "TCP")
        self.assertEqual(payload["app_protocol"], "SSH")
        self.assertEqual(payload["raw_event"], self.sample_event)

    @patch("notifier.requests.post")
    def test_send_alert_network_failure_does_not_crash(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("Connection refused")

        success = self.notifier.send(self.sample_alert)
        self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()
