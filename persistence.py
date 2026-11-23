import ipaddress
import json
import os

import psycopg


class PostgreSQLPersistence:
    def __init__(self):
        self.host = os.getenv("POSTGRES_HOST", "postgres")
        self.port = int(os.getenv("POSTGRES_PORT", "5432"))
        self.database = os.getenv("POSTGRES_DB", "omniguard")
        self.user = os.getenv("POSTGRES_USER", "omniguard")
        self.password = os.getenv("POSTGRES_PASSWORD")

    def connect(self):
        return psycopg.connect(
            host=self.host,
            port=self.port,
            dbname=self.database,
            user=self.user,
            password=self.password,
            connect_timeout=10,
        )

    @staticmethod
    def valid_ip(value):
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False

    def record_event(self, event):
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        if not self.valid_ip(src_ip) or not self.valid_ip(dst_ip):
            print("[POSTGRES] Evento ignorado: IP origen/destino inválida", flush=True)
            return

        dst_port = event.get("dst_port")
        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except (TypeError, ValueError):
            dst_port = None

        protocol = str(event.get("protocol", "UNKNOWN")).upper()
        app_protocol = str(event.get("app_protocol", "Desconocido"))

        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO assets.network_assets (ip_address)
                    VALUES (%s::inet)
                    ON CONFLICT (ip_address) DO UPDATE
                    SET last_seen_at = CURRENT_TIMESTAMP
                    """,
                    (src_ip,),
                )
                cursor.execute(
                    """
                    INSERT INTO assets.network_assets (ip_address)
                    VALUES (%s::inet)
                    ON CONFLICT (ip_address) DO UPDATE
                    SET last_seen_at = CURRENT_TIMESTAMP
                    RETURNING id
                    """,
                    (dst_ip,),
                )
                asset_id = cursor.fetchone()[0]

                if dst_port is not None:
                    cursor.execute(
                        """
                        INSERT INTO assets.services (
                                asset_id, port, protocol, app_protocol,
                                cpe_name, product_version
                        )
                            VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (asset_id, port, protocol) DO UPDATE
                        SET app_protocol = EXCLUDED.app_protocol,
                                cpe_name = COALESCE(EXCLUDED.cpe_name, assets.services.cpe_name),
                                product_version = COALESCE(EXCLUDED.product_version, assets.services.product_version),
                            last_seen_at = CURRENT_TIMESTAMP
                        """,
                            (
                                asset_id,
                                dst_port,
                                protocol,
                                app_protocol,
                                event.get("cpe_name") or None,
                                event.get("product_version") or None,
                            ),
                    )

    def record_alert(self, alert):
        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO alerts.events (
                        rule, severity, title, description,
                        source_ip, destination_ip, destination_port,
                        protocol, app_protocol, raw_event
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s::inet, %s::inet, %s,
                        %s, %s, %s::jsonb
                    )
                    """,
                    (
                        alert.rule,
                        alert.severity,
                        alert.title,
                        alert.description,
                        alert.src_ip,
                        alert.dst_ip,
                        alert.dst_port,
                        alert.event.get("protocol"),
                        alert.event.get("app_protocol"),
                        json.dumps(alert.event),
                    ),
                )
