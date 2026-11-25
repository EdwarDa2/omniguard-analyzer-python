import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from scan_worker import (
    ScanWorkerConfig,
    execute_scan,
    parse_ports,
    post_scan_result,
)


def worker_config(**overrides):
    values = {
        "redis_host": "redis",
        "redis_port": 6379,
        "scan_channel": "scan_commands_channel",
        "core_api_url": "http://core:8080/api/v1",
        "internal_token": "test-internal-token",
        "allowed_targets": frozenset({"127.0.0.1"}),
        "timeout_seconds": 0.5,
        "concurrency": 8,
        "max_ports": 1024,
    }
    values.update(overrides)
    return ScanWorkerConfig(**values)


class ScanWorkerTests(unittest.IsolatedAsyncioTestCase):
    def test_parse_ports_supports_ranges_and_lists(self):
        self.assertEqual(parse_ports("22,80-82,443"), [22, 80, 81, 82, 443])

    def test_parse_ports_rejects_unbounded_or_invalid_ranges(self):
        for ports in ("1-1025", "80-22", "0", "65536", "22,,80"):
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    parse_ports(ports)

    async def test_execute_scan_rejects_target_outside_allowlist(self):
        with patch("scan_worker.scan_ports", new_callable=AsyncMock) as scan:
            with self.assertRaisesRegex(ValueError, "SCAN_ALLOWED_TARGETS"):
                await execute_scan(
                    {
                        "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                        "target": "127.0.0.2",
                        "ports": "80",
                    },
                    worker_config(),
                )
        scan.assert_not_awaited()

    async def test_execute_scan_rejects_reserved_target_even_if_allowlisted(self):
        with patch("scan_worker.scan_ports", new_callable=AsyncMock) as scan:
            with self.assertRaisesRegex(ValueError, "unicast"):
                await execute_scan(
                    {
                        "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                        "target": "255.255.255.255",
                        "ports": "80",
                    },
                    worker_config(allowed_targets=frozenset({"255.255.255.255"})),
                )
        scan.assert_not_awaited()

    async def test_scan_port_reads_real_local_ssh_banner(self):
        async def send_banner(_reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(send_banner, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            result = await execute_scan(
                {
                    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                    "target": "127.0.0.1",
                    "ports": str(port),
                },
                worker_config(),
            )
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(len(result["open_ports"]), 1)
        self.assertEqual(result["open_ports"][0]["app_protocol"], "SSH")
        self.assertEqual(result["open_ports"][0]["product_version"], "OpenSSH 9.6")
        self.assertIn("SSH-2.0-OpenSSH_9.6", result["open_ports"][0]["banner"])

    def test_post_scan_result_uses_internal_token_and_expected_endpoint(self):
        response = MagicMock(status_code=202)
        config = worker_config()
        result = {"scan_id": "550e8400-e29b-41d4-a716-446655440000"}

        with patch("scan_worker.requests.post", return_value=response) as post:
            post_scan_result(result, config)

        post.assert_called_once_with(
            "http://core:8080/api/v1/internal/assets/scan-results",
            json=result,
            headers={
                "X-Internal-Token": "test-internal-token",
                "Content-Type": "application/json",
                "User-Agent": "OmniGuard-Scan-Worker/1.0",
            },
            timeout=5,
            allow_redirects=False,
        )


if __name__ == "__main__":
    unittest.main()
