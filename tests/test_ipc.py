from __future__ import annotations

import io
import json
import queue
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cd_sniffer.ipc import GuiIpcServer, send_gui_command


class FakeClientSocket:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.sent = b""
        self.shutdown_called = False

    def __enter__(self) -> "FakeClientSocket":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def shutdown(self, _how: int) -> None:
        self.shutdown_called = True

    def makefile(self, *_args: object, **_kwargs: object) -> io.StringIO:
        return io.StringIO(json.dumps(self.response) + "\n")


@unittest.skipUnless(hasattr(socket, "socketpair"), "socketpair unavailable")
class GuiIpcTests(unittest.TestCase):
    def test_gui_ipc_rejects_missing_or_wrong_token(self):
        server = GuiIpcServer(state_provider=lambda: {"status": "idle"}, command_queue=queue.Queue())
        server.token = "expected-token"
        left, right = socket.socketpair()
        try:
            right.sendall(json.dumps({"command": "start", "token": "wrong-token"}).encode("utf-8") + b"\n")
            server.handle_client(left)
            response = json.loads(right.recv(4096).decode("utf-8").strip())
        finally:
            left.close()
            right.close()

        self.assertFalse(response["ok"])
        self.assertIn("Unauthorized", response["error"])
        self.assertTrue(server.command_queue.empty())

    def test_send_gui_command_refuses_stale_pid(self):
        with patch(
            "cd_sniffer.ipc.read_gui_ipc_state",
            return_value={"host": "127.0.0.1", "port": 1234, "pid": 999999, "token": "token"},
        ), patch("cd_sniffer.ipc._ipc_pid_is_running", return_value=False), patch(
            "cd_sniffer.ipc.socket.create_connection"
        ) as create_connection:
            response = send_gui_command("status")

        self.assertFalse(response["ok"])
        self.assertIn("Stale CDSniffer GUI IPC endpoint", response["error"])
        create_connection.assert_not_called()

    def test_send_gui_command_includes_auth_token(self):
        fake_client = FakeClientSocket({"ok": True})
        with patch(
            "cd_sniffer.ipc.read_gui_ipc_state",
            return_value={"host": "127.0.0.1", "port": 1234, "pid": 42, "token": "secret-token"},
        ), patch("cd_sniffer.ipc._ipc_pid_is_running", return_value=True), patch(
            "cd_sniffer.ipc.socket.create_connection", return_value=fake_client
        ):
            response = send_gui_command("status")

        request = json.loads(fake_client.sent.decode("utf-8").strip())
        self.assertTrue(response["ok"])
        self.assertEqual(request["token"], "secret-token")
        self.assertEqual(request["command"], "status")
        self.assertTrue(fake_client.shutdown_called)


if __name__ == "__main__":
    unittest.main()
