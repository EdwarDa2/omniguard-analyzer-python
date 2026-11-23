import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from persistence import PostgreSQLPersistence


class PostgreSQLPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.store = PostgreSQLPersistence()

    def test_acepta_ipv4_valida(self):
        self.assertTrue(self.store.valid_ip("192.168.1.10"))

    def test_rechaza_ip_invalida(self):
        self.assertFalse(self.store.valid_ip("no-es-ip"))

    def test_evento_invalido_no_intenta_conectar(self):
        output = io.StringIO()
        with redirect_stdout(output):
            with patch.object(self.store, "connect") as connect:
                self.store.record_event({
                    "src_ip": "invalida",
                    "dst_ip": "10.0.0.9",
                })
        connect.assert_not_called()
        self.assertIn("IP origen/destino inválida", output.getvalue())

    def test_record_event_upsert_activos_y_servicio(self):
        cursor = MagicMock()
        cursor.fetchone.return_value = (42,)
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False

        connection = MagicMock()
        connection.cursor.return_value = cursor_context
        connection_context = MagicMock()
        connection_context.__enter__.return_value = connection
        connection_context.__exit__.return_value = False

        with patch.object(self.store, "connect", return_value=connection_context):
            self.store.record_event({
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.9",
                "dst_port": 22,
                "protocol": "TCP",
                "app_protocol": "SSH",
            })

        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("assets.network_assets", sql)
        self.assertIn("assets.services", sql)

    def test_record_event_guarda_cpe_y_version(self):
        cursor = MagicMock()
        cursor.fetchone.return_value = (42,)
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False

        connection = MagicMock()
        connection.cursor.return_value = cursor_context
        connection_context = MagicMock()
        connection_context.__enter__.return_value = connection
        connection_context.__exit__.return_value = False

        with patch.object(self.store, "connect", return_value=connection_context):
            self.store.record_event({
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.9",
                "dst_port": 22,
                "protocol": "TCP",
                "app_protocol": "SSH",
                "product_version": "9.2",
                "cpe_name": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
            })

        values = cursor.execute.call_args_list[-1].args[1]
        self.assertIn("cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*", values)
        self.assertIn("9.2", values)


if __name__ == "__main__":
    unittest.main()
