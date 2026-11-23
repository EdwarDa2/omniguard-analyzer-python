"""Envío de alertas a Discord mediante Webhook."""
import time
import requests

COLORS = {"MEDIUM": 0xF1C40F, "HIGH": 0xE74C3C}


class DiscordNotifier:
    def __init__(self, webhook_url: str):
        self._url = webhook_url  # nunca se imprime ni se registra

    def send(self, alert) -> bool:
        ev = alert.event
        embed = {
            "title": f"[{alert.severity}] {alert.title}",
            "description": alert.description,
            "color": COLORS.get(alert.severity, 0x95A5A6),
            "fields": [
                {"name": "Origen", "value": f"`{alert.src_ip}`", "inline": True},
                {"name": "Destino", "value": f"`{alert.dst_ip}:{alert.dst_port}`", "inline": True},
                {"name": "Protocolo", "value": f"{ev.get('protocol', '?')} / {ev.get('app_protocol', '?')}", "inline": True},
                {"name": "Regla", "value": alert.rule, "inline": True},
            ],
            "footer": {"text": "OmniGuard SOC · sensor-cpp"},
        }
        payload = {"username": "OmniGuard Sensor", "embeds": [embed]}

        for _ in range(2):  # un reintento si Discord pide esperar (429)
            try:
                r = requests.post(self._url, json=payload, timeout=10)
            except requests.RequestException as exc:
                print(f"[DISCORD] Error de red: {type(exc).__name__}")
                return False
            if r.status_code in (200, 204):
                return True
            if r.status_code == 429:
                time.sleep(min(float(r.json().get("retry_after", 1)), 10))
                continue
            print(f"[DISCORD] Respuesta inesperada: HTTP {r.status_code}")
            return False
        return False


class CoreBackendNotifier:
    """Envío de alertas al Core Backend Java mediante HTTP REST M2M."""

    def __init__(self, base_url: str, internal_token: str):
        self.endpoint = f"{base_url.rstrip('/')}/internal/alerts"
        self.token = internal_token

    def send(self, alert) -> bool:
        headers = {
            "Content-Type": "application/json",
            "X-Internal-Token": self.token,
            "User-Agent": "OmniGuard-Analyzer-Python/1.0",
        }
        payload = {
            "threat_type": alert.category,
            "rule": alert.rule,
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "source_ip": alert.src_ip,
            "destination_ip": alert.dst_ip,
            "destination_port": alert.dst_port,
            "protocol": alert.protocol,
            "app_protocol": alert.app_protocol,
            "raw_event": alert.event,
        }
        try:
            r = requests.post(self.endpoint, json=payload, headers=headers, timeout=5)
            if r.status_code in (200, 201):
                return True
            print(f"[CORE-API] Advertencia: HTTP {r.status_code} al enviar alerta: {r.text}", flush=True)
            return False
        except requests.RequestException as exc:
            print(f"[CORE-API] Advertencia: no se pudo conectar con el Core Backend ({type(exc).__name__}). Continuando...", flush=True)
            return False