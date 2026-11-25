"""Local-only TCP scan worker for OmniGuard scan commands."""

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv
from redis.asyncio import Redis
from redis.exceptions import RedisError


LOGGER = logging.getLogger("omniguard.scan_worker")
DEFAULT_ALLOWED_TARGETS = "127.0.0.1,::1"
MAX_SCAN_TIMEOUT_SECONDS = 0.5
MAX_SCAN_CONCURRENCY = 64
MAX_PORTS_PER_SCAN = 1024
MAX_BANNER_BYTES = 512
HTTP_PROBE_PORTS = frozenset({80, 8000, 8080, 8888})
KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP",
    8080: "HTTP",
    8888: "HTTP",
}


@dataclass(frozen=True)
class ScanWorkerConfig:
    redis_host: str
    redis_port: int
    scan_channel: str
    core_api_url: str
    internal_token: str
    allowed_targets: frozenset[str]
    timeout_seconds: float
    concurrency: int
    max_ports: int

    @property
    def scan_results_url(self) -> str:
        return f"{self.core_api_url.rstrip('/')}/internal/assets/scan-results"


def _normalize_ip(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target debe ser una dirección IP")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("target debe ser una dirección IP literal") from exc
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        raise ValueError("target debe ser una dirección unicast válida")
    return str(address)


def parse_ports(port_spec: object, max_ports: int = MAX_PORTS_PER_SCAN) -> list[int]:
    if not isinstance(port_spec, str) or not port_spec.strip():
        raise ValueError("ports debe ser un rango o lista de puertos")
    if len(port_spec) > 4096:
        raise ValueError("ports excede el tamaño máximo permitido")
    if max_ports < 1 or max_ports > MAX_PORTS_PER_SCAN:
        raise ValueError(f"max_ports debe estar entre 1 y {MAX_PORTS_PER_SCAN}")

    ports: set[int] = set()
    for item in port_spec.split(","):
        token = item.strip()
        if not token:
            raise ValueError("ports contiene un elemento vacío")

        if "-" in token:
            endpoints = token.split("-")
            if len(endpoints) != 2 or not all(part.strip().isdigit() for part in endpoints):
                raise ValueError(f"rango de puertos inválido: {token}")
            start, end = (int(part.strip()) for part in endpoints)
            if start > end:
                raise ValueError(f"rango de puertos descendente: {token}")
            if end - start + 1 > max_ports:
                raise ValueError(f"el escaneo excede el límite de {max_ports} puertos")
            requested = range(start, end + 1)
        else:
            if not token.isdigit():
                raise ValueError(f"puerto inválido: {token}")
            requested = (int(token),)

        for port in requested:
            if port < 1 or port > 65535:
                raise ValueError(f"puerto fuera de rango: {port}")
            ports.add(port)
            if len(ports) > max_ports:
                raise ValueError(f"el escaneo excede el límite de {max_ports} puertos")

    return sorted(ports)


def load_config() -> ScanWorkerConfig:
    core_api_url = os.getenv("CORE_API_URL", "").strip().rstrip("/")
    internal_token = os.getenv("INTERNAL_API_TOKEN", "").strip()
    if not core_api_url:
        raise ValueError("CORE_API_URL es obligatorio para enviar los resultados")
    if not internal_token:
        raise ValueError("INTERNAL_API_TOKEN es obligatorio para enviar los resultados")

    parsed_url = urlsplit(core_api_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("CORE_API_URL debe ser una URL HTTP o HTTPS válida")
    if parsed_url.username or parsed_url.password:
        raise ValueError("CORE_API_URL no debe incluir credenciales")
    if parsed_url.query or parsed_url.fragment:
        raise ValueError("CORE_API_URL no debe incluir query ni fragmento")
    if not parsed_url.path.rstrip("/").endswith("/api/v1"):
        raise ValueError("CORE_API_URL debe incluir la ruta /api/v1")

    allowed_values = os.getenv("SCAN_ALLOWED_TARGETS", DEFAULT_ALLOWED_TARGETS)
    allowed_targets = frozenset(
        _normalize_ip(value) for value in allowed_values.split(",") if value.strip()
    )
    if not allowed_targets:
        raise ValueError("SCAN_ALLOWED_TARGETS debe incluir al menos una IP autorizada")

    redis_port = _env_int("REDIS_PORT", 6379, 1, 65535)
    timeout_seconds = _env_float("SCAN_TIMEOUT_SECONDS", 0.5, 0.01, MAX_SCAN_TIMEOUT_SECONDS)
    concurrency = _env_int("SCAN_CONCURRENCY", 32, 1, MAX_SCAN_CONCURRENCY)
    max_ports = _env_int("SCAN_MAX_PORTS", MAX_PORTS_PER_SCAN, 1, MAX_PORTS_PER_SCAN)

    return ScanWorkerConfig(
        redis_host=os.getenv("REDIS_HOST", "redis").strip() or "redis",
        redis_port=redis_port,
        scan_channel=os.getenv("SCAN_COMMANDS_CHANNEL", "scan_commands_channel").strip()
        or "scan_commands_channel",
        core_api_url=core_api_url,
        internal_token=internal_token,
        allowed_targets=allowed_targets,
        timeout_seconds=timeout_seconds,
        concurrency=concurrency,
        max_ports=max_ports,
    )


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.getenv(name, str(default)).strip()
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} debe ser un entero") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} debe estar entre {minimum} y {maximum}")
    return value


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw_value = os.getenv(name, str(default)).strip()
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} debe ser un número") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} debe estar entre {minimum} y {maximum} segundos")
    return value


def _clean_banner(data: bytes) -> str:
    decoded = data.decode("utf-8", errors="replace")
    return "".join(character for character in decoded if character.isprintable() or character in "\r\n\t").strip()


async def _read_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target: str,
    port: int,
    timeout_seconds: float,
) -> str:
    if port in HTTP_PROBE_PORTS:
        writer.write(
            f"HEAD / HTTP/1.0\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        await writer.drain()

    try:
        data = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout_seconds)
    except asyncio.TimeoutError:
        return ""
    return _clean_banner(data)


def _identify_service(port: int, banner: str) -> tuple[str, str]:
    lowered = banner.lower()
    if lowered.startswith("ssh-"):
        match = re.search(r"OpenSSH[_ ]([^\s]+)", banner, re.IGNORECASE)
        version = f"OpenSSH {match.group(1)}" if match else ""
        return "SSH", version

    if lowered.startswith("http/"):
        server = re.search(r"(?im)^server:\s*([^\r\n]+)", banner)
        return "HTTP", server.group(1).strip() if server else ""

    return KNOWN_PORTS.get(port, "TCP"), ""


async def scan_port(target: str, port: int, timeout_seconds: float) -> dict[str, object] | None:
    started_at = asyncio.get_running_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout_seconds,
        )
    except (OSError, asyncio.TimeoutError):
        return None

    try:
        remaining = max(
            0.0,
            timeout_seconds - (asyncio.get_running_loop().time() - started_at),
        )
        banner = await _read_banner(
            reader,
            writer,
            target,
            port,
            min(0.25, remaining),
        ) if remaining > 0 else ""
        app_protocol, product_version = _identify_service(port, banner)
        return {
            "port": port,
            "protocol": "TCP",
            "app_protocol": app_protocol,
            "product_version": product_version,
            "banner": banner[:MAX_BANNER_BYTES],
            "status": "ABIERTO",
        }
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def scan_ports(
    target: str,
    ports: list[int],
    timeout_seconds: float,
    concurrency: int,
) -> list[dict[str, object]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_limited(port: int) -> dict[str, object] | None:
        async with semaphore:
            return await scan_port(target, port, timeout_seconds)

    results = await asyncio.gather(*(scan_limited(port) for port in ports))
    return sorted((result for result in results if result is not None), key=lambda item: int(item["port"]))


async def execute_scan(
    command: object,
    config: ScanWorkerConfig,
) -> dict[str, object]:
    if not isinstance(command, dict):
        raise ValueError("la orden debe ser un objeto JSON")
    try:
        scan_id = str(uuid.UUID(str(command.get("scan_id", ""))))
    except (ValueError, AttributeError) as exc:
        raise ValueError("scan_id debe ser un UUID válido") from exc

    target = _normalize_ip(command.get("target"))
    if target not in config.allowed_targets:
        raise ValueError("target no está en SCAN_ALLOWED_TARGETS")
    ports = parse_ports(command.get("ports", "1-1024"), config.max_ports)
    open_ports = await scan_ports(
        target,
        ports,
        config.timeout_seconds,
        config.concurrency,
    )
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "scan_id": scan_id,
        "target_ip": target,
        "status": "COMPLETED",
        "scanned_at": scanned_at,
        "open_ports": open_ports,
    }


def post_scan_result(result: dict[str, object], config: ScanWorkerConfig) -> None:
    response = requests.post(
        config.scan_results_url,
        json=result,
        headers={
            "X-Internal-Token": config.internal_token,
            "Content-Type": "application/json",
            "User-Agent": "OmniGuard-Scan-Worker/1.0",
        },
        timeout=5,
        allow_redirects=False,
    )
    if not 200 <= response.status_code < 300:
        raise RuntimeError(f"Core API respondió HTTP {response.status_code}")


async def submit_scan_result(
    result: dict[str, object],
    config: ScanWorkerConfig,
) -> None:
    for attempt in range(3):
        try:
            await asyncio.to_thread(post_scan_result, result, config)
            return
        except (requests.RequestException, RuntimeError) as exc:
            if attempt == 2:
                raise
            LOGGER.warning(
                "No se pudo enviar scan_id=%s (intento %d/3): %s",
                result["scan_id"],
                attempt + 1,
                type(exc).__name__,
            )
            await asyncio.sleep(0.5 * (2**attempt))


async def process_message(raw_message: object, config: ScanWorkerConfig) -> None:
    try:
        command = json.loads(raw_message)
        result = await execute_scan(command, config)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        LOGGER.warning("Orden de escaneo rechazada: %s", exc)
        return

    LOGGER.info(
        "Escaneo completado: scan_id=%s target=%s puertos_abiertos=%d",
        result["scan_id"],
        result["target_ip"],
        len(result["open_ports"]),
    )
    try:
        await submit_scan_result(result, config)
    except (requests.RequestException, RuntimeError) as exc:
        LOGGER.error(
            "Resultado scan_id=%s no entregado al Core API tras 3 intentos: %s",
            result["scan_id"],
            type(exc).__name__,
        )


async def run_worker(config: ScanWorkerConfig) -> None:
    while True:
        client = Redis(
            host=config.redis_host,
            port=config.redis_port,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        pubsub = client.pubsub()
        try:
            await pubsub.subscribe(config.scan_channel)
            LOGGER.info(
                "Escuchando órdenes locales en Redis %s:%d canal=%s",
                config.redis_host,
                config.redis_port,
                config.scan_channel,
            )
            async for message in pubsub.listen():
                if message.get("type") == "message":
                    await process_message(message.get("data"), config)
        except (RedisError, OSError) as exc:
            LOGGER.error("Conexión Redis perdida: %s; reintento en 3 s", type(exc).__name__)
            await asyncio.sleep(3)
        finally:
            await pubsub.aclose()
            await client.aclose()


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_dotenv()
    parser = argparse.ArgumentParser(description="OmniGuard local-only scan worker")
    parser.parse_args()

    try:
        config = load_config()
    except ValueError as exc:
        parser.error(str(exc))
    asyncio.run(run_worker(config))


if __name__ == "__main__":
    main()
