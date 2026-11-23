"""OmniGuard Analyzer: consume eventos de Redis, detecta amenazas y alerta."""
import argparse
import json
import os
import sys
import time

import redis
from dotenv import load_dotenv
import psycopg

from detector import Detector
from notifier import CoreBackendNotifier, DiscordNotifier
from persistence import PostgreSQLPersistence


def main():
    parser = argparse.ArgumentParser(description="OmniGuard Analyzer")
    parser.add_argument("--dry-run", action="store_true",
                        help="No envía a Discord; imprime las alertas en consola")
    args = parser.parse_args()

    load_dotenv()
    host = os.getenv("REDIS_HOST", "127.0.0.1")
    port = int(os.getenv("REDIS_PORT", "6379"))
    channel = os.getenv("REDIS_CHANNEL", "network_events")
    webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    core_api_url = os.getenv("CORE_API_URL", "").strip()
    internal_token = os.getenv("INTERNAL_API_TOKEN", "").strip()

    discord_notifier = None
    if not args.dry_run:
        if not webhook:
            print("[ANALYZER] DISCORD_WEBHOOK_URL no configurado; notificaciones Discord desactivadas.", flush=True)
        else:
            discord_notifier = DiscordNotifier(webhook)

    core_notifier = None
    if core_api_url:
        core_notifier = CoreBackendNotifier(core_api_url, internal_token)
        print(f"[ANALYZER] Integración Core API activa hacia {core_api_url}", flush=True)

    detector = Detector()
    persistence = PostgreSQLPersistence()
    print(f"[ANALYZER] Escuchando '{channel}' en {host}:{port} "
          f"({'dry-run' if args.dry_run else 'Discord activo'})")

    while True:
        try:
            r = redis.Redis(host=host, port=port, decode_responses=True)
            pubsub = r.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(channel)
            for msg in pubsub.listen():
                try:
                    event = json.loads(msg["data"])
                except (json.JSONDecodeError, TypeError):
                    continue
                try:
                    persistence.record_event(event)
                except psycopg.Error as exc:
                    print(f"[POSTGRES] Error al guardar el evento: {exc}", flush=True)
                for alert in detector.analyze(event):
                    print(f"[ALERTA {alert.severity}] {alert.title} | "
                          f"{alert.src_ip} -> {alert.dst_ip}:{alert.dst_port}")
                    try:
                        persistence.record_alert(alert)
                    except psycopg.Error as exc:
                        print(f"[POSTGRES] Error al guardar la alerta: {exc}", flush=True)
                    if core_notifier:
                        try:
                            if core_notifier.send(alert):
                                print(f"[CORE-API] Alerta despachada exitosamente al Backend Java", flush=True)
                        except Exception as exc:
                            print(f"[CORE-API] Error inesperado al enviar alerta: {exc}", flush=True)
                    if discord_notifier:
                        discord_notifier.send(alert)
        except redis.ConnectionError:
            print("[ANALYZER] Sin conexión a Redis, reintentando en 3 s...")
            time.sleep(3)
        except KeyboardInterrupt:
            print("\n[ANALYZER] Detenido.")
            break


if __name__ == "__main__":
    main()