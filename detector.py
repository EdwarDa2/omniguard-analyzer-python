"""Motor de detección de OmniGuard: convierte eventos de red en alertas.

Reglas:
  1. Primer intento de conexión a un servicio de acceso remoto (SSH, RDP...) -> MEDIUM
  2. Muchos intentos (SYN) de una IP al mismo servicio en una ventana  -> HIGH (fuerza bruta)
  3. Una IP que toca muchos puertos distintos en una ventana           -> HIGH (escaneo de puertos)

Solo se cuentan SYN puros (inicio de conexión), no las respuestas del servidor,
para no generar una alerta por cada paquete.
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class Alert:
    severity: str          # "MEDIUM" | "HIGH"
    rule: str              # "remote_access" | "bruteforce" | "port_scan"
    title: str
    description: str
    src_ip: str
    dst_ip: str
    dst_port: int
    event: dict = field(default_factory=dict)


class Detector:
    def __init__(self,
                 bruteforce_threshold=5, bruteforce_window=60,
                 scan_port_threshold=10, scan_window=30,
                 cooldown=60, clock=time.time):
        self.bf_threshold = bruteforce_threshold
        self.bf_window = bruteforce_window
        self.scan_threshold = scan_port_threshold
        self.scan_window = scan_window
        self.cooldown = cooldown
        self.clock = clock
        self._attempts = defaultdict(deque)   # (src, dst, dport) -> tiempos de SYN
        self._touched = defaultdict(deque)    # src -> (tiempo, (dst, dport))
        self._last_alert = {}                 # clave de alerta -> último envío
        self._seen = 0

    # ── API pública ──────────────────────────────────────────────────────────
    def analyze(self, ev: dict) -> list:
        """Devuelve las alertas (0, 1 o más) que provoca este evento."""
        if ev.get("protocol") != "TCP" or ev.get("tcp_flags") != "SYN":
            return []

        now = self.clock()
        src, dst = ev.get("src_ip", ""), ev.get("dst_ip", "")
        dport = int(ev.get("dst_port", 0))
        alerts = []

        # Registro de intentos
        att = self._attempts[(src, dst, dport)]
        att.append(now)
        self._prune(att, now - self.bf_window)

        touched = self._touched[src]
        touched.append((now, (dst, dport)))
        while touched and touched[0][0] < now - self.scan_window:
            touched.popleft()

        remote = ev.get("category") == "acceso_remoto"
        service = ev.get("app_protocol", f"puerto {dport}")

        # Regla 2: fuerza bruta (tiene prioridad sobre la 1)
        if remote and len(att) >= self.bf_threshold:
            if self._allowed(("bruteforce", src, dst, dport), now):
                alerts.append(Alert(
                    "HIGH", "bruteforce",
                    f"Posible fuerza bruta sobre {service}",
                    f"{len(att)} intentos de conexión desde {src} hacia "
                    f"{dst}:{dport} en {self.bf_window} s.",
                    src, dst, dport, ev))
        # Regla 1: primer contacto con un servicio de acceso remoto
        elif remote and ev.get("risk") in ("MEDIUM", "HIGH"):
            if self._allowed(("remote_access", src, dst, dport), now):
                alerts.append(Alert(
                    "MEDIUM", "remote_access",
                    f"Conexión a servicio de administración remota ({service})",
                    ev.get("risk_reason", "Servicio sensible"),
                    src, dst, dport, ev))

        # Regla 3: escaneo de puertos
        distinct = {t for _, t in touched}
        if len(distinct) >= self.scan_threshold:
            if self._allowed(("port_scan", src), now):
                alerts.append(Alert(
                    "HIGH", "port_scan",
                    "Posible escaneo de puertos",
                    f"{src} contactó {len(distinct)} destinos/puertos distintos "
                    f"en {self.scan_window} s.",
                    src, dst, dport, ev))

        self._seen += 1
        if self._seen % 5000 == 0:
            self._gc(now)
        return alerts

    # ── Internos ─────────────────────────────────────────────────────────────
    @staticmethod
    def _prune(dq, limit):
        while dq and dq[0] < limit:
            dq.popleft()

    def _allowed(self, key, now):
        """Anti-spam: una alerta por clave cada 'cooldown' segundos."""
        last = self._last_alert.get(key)
        if last is not None and now - last < self.cooldown:
            return False
        self._last_alert[key] = now
        return True

    def _gc(self, now):
        """Libera memoria de claves antiguas."""
        for k in [k for k, d in self._attempts.items()
                  if not d or d[-1] < now - self.bf_window]:
            del self._attempts[k]
        for k in [k for k, d in self._touched.items()
                  if not d or d[-1][0] < now - self.scan_window]:
            del self._touched[k]
        for k in [k for k, t in self._last_alert.items()
                  if now - t > self.cooldown]:
            del self._last_alert[k]