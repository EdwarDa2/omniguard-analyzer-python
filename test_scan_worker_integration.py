import asyncio
import json
import os
import unittest
import uuid

from redis.asyncio import Redis

from scan_worker import ScanWorkerConfig, run_worker


REDIS_PORT = os.getenv("SCAN_WORKER_TEST_REDIS_PORT")


@unittest.skipUnless(
    REDIS_PORT,
    "Set SCAN_WORKER_TEST_REDIS_PORT to run the Redis integration test",
)
class ScanWorkerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_redis_command_scans_loopback_and_posts_to_http_contract(self):
        redis_host = os.getenv("SCAN_WORKER_TEST_REDIS_HOST", "127.0.0.1")
        channel = f"scan_worker_test_{uuid.uuid4().hex}"
        redis_client = Redis(
            host=redis_host,
            port=int(REDIS_PORT),
            decode_responses=True,
        )
        received_result = asyncio.get_running_loop().create_future()

        async def service_greeting(_, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def handle_http_request(reader, writer):
            request_line = (await reader.readline()).decode("ascii").strip()
            headers = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b""):
                    break
                name, value = line.decode("latin-1").split(":", 1)
                headers[name.lower()] = value.strip()

            body = await reader.readexactly(int(headers.get("content-length", "0")))
            received_result.set_result(
                {
                    "request_line": request_line,
                    "headers": headers,
                    "payload": json.loads(body),
                }
            )
            writer.write(
                b"HTTP/1.1 202 Accepted\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        service = await asyncio.start_server(service_greeting, "127.0.0.1", 0)
        http_server = await asyncio.start_server(handle_http_request, "127.0.0.1", 0)
        service_port = service.sockets[0].getsockname()[1]
        http_port = http_server.sockets[0].getsockname()[1]
        config = ScanWorkerConfig(
            redis_host=redis_host,
            redis_port=int(REDIS_PORT),
            scan_channel=channel,
            core_api_url=f"http://127.0.0.1:{http_port}/api/v1",
            internal_token="integration-test-token",
            allowed_targets=frozenset({"127.0.0.1"}),
            timeout_seconds=0.5,
            concurrency=4,
            max_ports=16,
        )
        worker_task = asyncio.create_task(run_worker(config))

        try:
            await self._wait_for_subscription(redis_client, channel)
            scan_id = str(uuid.uuid4())
            await redis_client.publish(
                channel,
                json.dumps(
                    {
                        "scan_id": scan_id,
                        "target": "127.0.0.1",
                        "ports": str(service_port),
                    }
                ),
            )
            callback = await asyncio.wait_for(received_result, timeout=5)

            self.assertEqual(
                callback["request_line"],
                "POST /api/v1/internal/assets/scan-results HTTP/1.1",
            )
            self.assertEqual(callback["headers"]["x-internal-token"], "integration-test-token")
            self.assertEqual(callback["payload"]["scan_id"], scan_id)
            self.assertEqual(callback["payload"]["target_ip"], "127.0.0.1")
            self.assertEqual(callback["payload"]["status"], "COMPLETED")
            self.assertEqual(callback["payload"]["open_ports"][0]["port"], service_port)
            self.assertEqual(callback["payload"]["open_ports"][0]["app_protocol"], "SSH")
        finally:
            worker_task.cancel()
            try:
                await worker_task
            except asyncio.CancelledError:
                pass
            service.close()
            http_server.close()
            await service.wait_closed()
            await http_server.wait_closed()
            await redis_client.aclose()

    async def _wait_for_subscription(self, client, channel):
        deadline = asyncio.get_running_loop().time() + 5
        while asyncio.get_running_loop().time() < deadline:
            subscriptions = await client.pubsub_numsub(channel)
            if subscriptions and subscriptions[0][1] > 0:
                return
            await asyncio.sleep(0.05)
        self.fail(f"Worker did not subscribe to Redis channel {channel}")


if __name__ == "__main__":
    unittest.main()
