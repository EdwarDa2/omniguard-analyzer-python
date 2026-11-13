"""OmniGuard Analyzer: consume eventos de Redis, detecta amenazas y alerta."""
import argparse
import json
import os
import sys
import time

import redis
from dotenv import load_dotenv

from detector import Detector
from notifier import DiscordNotifier


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

    notifier = None
    if not args.dry_run:
        if not webhook:
            sys.exit("Falta DISCORD_WEBHOOK_URL en .env (o usa --dry-run).")
        notifier = DiscordNotifier(webhook)

    detector = Detector()
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
                for alert in detector.analyze(event):
                    print(f"[ALERTA {alert.severity}] {alert.title} | "
                          f"{alert.src_ip} -> {alert.dst_ip}:{alert.dst_port}")
                    if notifier:
                        notifier.send(alert)
        except redis.ConnectionError:
            print("[ANALYZER] Sin conexión a Redis, reintentando en 3 s...")
            time.sleep(3)
        except KeyboardInterrupt:
            print("\n[ANALYZER] Detenido.")
            break


if __name__ == "__main__":
    main()