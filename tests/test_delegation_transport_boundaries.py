"""Real unix-socket deadline regression; no Manager, OAuth credentials or model calls."""
from __future__ import annotations
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from coding_tools_mcp.delegation_ingress import DelegationCaller, DelegationGateway, _Unavailable
from coding_tools_mcp.errors import JsonRpcError


class DelegationTransportBoundaryTests(unittest.TestCase):
    def test_slow_partial_reply_cannot_extend_total_deadline(self):
        with tempfile.TemporaryDirectory(prefix="zamm-dgt-", dir="/tmp") as tmp:
            path = str(Path(tmp) / "slow.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(server.close)
            server.bind(path)
            server.listen(1)
            stopped = threading.Event()

            def drip():
                conn, _ = server.accept()
                with conn:
                    conn.recv(4096)
                    for _ in range(15):
                        if stopped.wait(0.035):
                            break
                        try:
                            conn.sendall(b" ")
                        except OSError:
                            break

            worker = threading.Thread(target=drip)
            worker.start()
            gateway = object.__new__(DelegationGateway)
            started = time.monotonic()
            try:
                with self.assertRaises(_Unavailable) as raised:
                    gateway._exchange({"socketPath": path}, {"op": "hello"}, 0.16)
                self.assertEqual(raised.exception.kind, "lost")
                self.assertLess(time.monotonic() - started, 0.4)
            finally:
                stopped.set()
                server.close()
                worker.join(2)
                self.assertFalse(worker.is_alive())

    def test_invalid_wait_bounds_are_refused_before_owner_connection(self):
        gateway = object.__new__(DelegationGateway)
        caller = DelegationCaller("test", "client", "session", "consumer")
        with patch.object(gateway, "_descriptor") as connect:
            for value in [-1, 25001, 10**30, True, 1.5, "25000"]:
                with self.subTest(value=value), self.assertRaises(JsonRpcError):
                    gateway.call(caller, "work_wait", {"workIds": ["work:test"], "waitMs": value})
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
