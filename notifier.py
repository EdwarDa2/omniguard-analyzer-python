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