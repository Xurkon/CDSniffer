from __future__ import annotations

import json
import queue
import os
import socket
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


GUI_IPC_STATE_FILE = Path(tempfile.gettempdir()) / "cdsniffer_gui_ipc.json"


@dataclass(frozen=True)
class GuiCommand:
    command: str
    payload: dict[str, Any]


class GuiIpcServer(threading.Thread):
    def __init__(
        self,
        *,
        state_provider: Callable[[], dict[str, Any]],
        command_queue: "queue.Queue[GuiCommand]",
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        super().__init__(daemon=True)
        self.state_provider = state_provider
        self.command_queue = command_queue
        self.host = host
        self.port = port
        self._stop_event = threading.Event()
        self._server_socket: socket.socket | None = None
        self.bound_port: int | None = None

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def write_state_file(self) -> None:
        if self.bound_port is None:
            return
        payload = {
            "host": self.host,
            "port": self.bound_port,
            "pid": os.getpid(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        GUI_IPC_STATE_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def remove_state_file(self) -> None:
        try:
            if GUI_IPC_STATE_FILE.exists():
                GUI_IPC_STATE_FILE.unlink()
        except OSError:
            pass

    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            self._server_socket = server
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(4)
            server.settimeout(0.25)
            self.bound_port = int(server.getsockname()[1])
            self.write_state_file()
            while not self._stop_event.is_set():
                try:
                    client, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with client:
                    self.handle_client(client)
        self.remove_state_file()

    def handle_client(self, client: socket.socket) -> None:
        try:
            file = client.makefile("rwb")
            raw = file.readline().decode("utf-8").strip()
            if not raw:
                return
            request = json.loads(raw)
            command = str(request.get("command", "")).strip()
            payload = dict(request.get("payload") or {})
            response: dict[str, Any]
            if command == "status":
                response = {"ok": True, "state": self.state_provider()}
            elif command in {"start", "stop", "show", "hide", "open-settings", "refresh", "apply-settings", "select-tab"}:
                self.command_queue.put(GuiCommand(command=command, payload=payload))
                response = {"ok": True, "queued": True}
            else:
                response = {"ok": False, "error": f"Unknown command: {command}"}
            file.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            file.flush()
        except Exception as exc:
            try:
                client.sendall((json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False) + "\n").encode("utf-8"))
            except OSError:
                pass


def read_gui_ipc_state() -> dict[str, Any] | None:
    try:
        if not GUI_IPC_STATE_FILE.exists():
            return None
        return json.loads(GUI_IPC_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def send_gui_command(command: str, payload: dict[str, Any] | None = None, timeout: float = 1.5) -> dict[str, Any]:
    state = read_gui_ipc_state()
    if not state:
        return {"ok": False, "error": "No CDSniffer GUI IPC endpoint found."}
    host = str(state.get("host", "127.0.0.1"))
    port = int(state.get("port", 0))
    if port <= 0:
        return {"ok": False, "error": "Invalid GUI IPC port."}
    request = {"command": command, "payload": payload or {}}
    with socket.create_connection((host, port), timeout=timeout) as client:
        client.sendall((json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8"))
        client.shutdown(socket.SHUT_WR)
        file = client.makefile("r", encoding="utf-8")
        raw = file.readline().strip()
        if not raw:
            return {"ok": False, "error": "Empty response from GUI."}
        return json.loads(raw)
