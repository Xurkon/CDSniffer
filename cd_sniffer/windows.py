from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
try:
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
except OSError:  # pragma: no cover - Windows normally has psapi.
    psapi = None

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
SYNCHRONIZE = 0x00100000

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

LIST_MODULES_ALL = 0x03

WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", wintypes.LPVOID),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", wintypes.LPVOID),
    ]


WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

_VK_MAP = {
    "BACKSPACE": 0x08,
    "TAB": 0x09,
    "ENTER": 0x0D,
    "RETURN": 0x0D,
    "SHIFT": 0x10,
    "CTRL": 0x11,
    "CONTROL": 0x11,
    "ALT": 0x12,
    "PAUSE": 0x13,
    "CAPSLOCK": 0x14,
    "ESC": 0x1B,
    "ESCAPE": 0x1B,
    "SPACE": 0x20,
    "PAGEUP": 0x21,
    "PAGEDOWN": 0x22,
    "END": 0x23,
    "HOME": 0x24,
    "LEFT": 0x25,
    "UP": 0x26,
    "RIGHT": 0x27,
    "DOWN": 0x28,
    "INSERT": 0x2D,
    "DELETE": 0x2E,
    "0": 0x30,
    "1": 0x31,
    "2": 0x32,
    "3": 0x33,
    "4": 0x34,
    "5": 0x35,
    "6": 0x36,
    "7": 0x37,
    "8": 0x38,
    "9": 0x39,
}

_VK_MAP.update({chr(code): code for code in range(0x41, 0x5B)})
_VK_MAP.update({f"F{index}": 0x6F + index for index in range(1, 13)})
_VK_MAP.update({f"NUMPAD{index}": 0x60 + index for index in range(10)})

def open_process(pid: int) -> int:
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle

def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)

def iter_memory_regions(handle: int):
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    size = ctypes.sizeof(mbi)
    while True:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), size)
        if not result:
            break
        base = int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0)
        region_size = int(mbi.RegionSize)
        yield mbi
        next_address = base + region_size
        if next_address <= address:
            break
        address = next_address

def read_memory(handle: int, address: int, size: int) -> bytes:
    buffer = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not ok:
        return b""
    return bytes(buffer[: bytes_read.value])

def is_readable_region(mbi: MEMORY_BASIC_INFORMATION) -> bool:
    if mbi.State != MEM_COMMIT:
        return False
    if mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS):
        return False
    if mbi.Type not in (MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE):
        return False
    return True


def memory_type_name(memory_type: int) -> str:
    names = {
        MEM_IMAGE: "MEM_IMAGE",
        MEM_MAPPED: "MEM_MAPPED",
        MEM_PRIVATE: "MEM_PRIVATE",
    }
    return names.get(int(memory_type), f"0x{int(memory_type):X}")


def memory_state_name(state: int) -> str:
    names = {
        MEM_COMMIT: "MEM_COMMIT",
    }
    return names.get(int(state), f"0x{int(state):X}")


def protection_name(protect: int) -> str:
    protect = int(protect)
    base = protect & 0xFF
    names = {
        PAGE_NOACCESS: "PAGE_NOACCESS",
        PAGE_READONLY: "PAGE_READONLY",
        PAGE_READWRITE: "PAGE_READWRITE",
        PAGE_WRITECOPY: "PAGE_WRITECOPY",
        PAGE_EXECUTE: "PAGE_EXECUTE",
        PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
        PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
        PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
    }
    parts = [names.get(base, f"0x{base:X}")]
    if protect & PAGE_GUARD:
        parts.append("PAGE_GUARD")
    return "|".join(parts)


def list_process_modules(handle: int) -> list[dict[str, object]]:
    if psapi is None:
        return []
    if not all(
        hasattr(psapi, name)
        for name in ("EnumProcessModulesEx", "GetModuleInformation", "GetModuleFileNameExW")
    ):
        return []

    module_size = ctypes.sizeof(ctypes.c_void_p)
    needed = wintypes.DWORD()
    count = 256
    modules = None
    while True:
        modules = (ctypes.c_void_p * count)()
        ok = psapi.EnumProcessModulesEx(
            wintypes.HANDLE(handle),
            modules,
            ctypes.sizeof(modules),
            ctypes.byref(needed),
            LIST_MODULES_ALL,
        )
        if not ok:
            return []
        needed_count = max(0, needed.value // module_size)
        if needed_count <= count:
            break
        count = needed_count

    results: list[dict[str, object]] = []
    for module in list(modules)[:needed_count]:
        if not module:
            continue
        info = MODULEINFO()
        ok = psapi.GetModuleInformation(
            wintypes.HANDLE(handle),
            ctypes.c_void_p(module),
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            continue
        buffer = ctypes.create_unicode_buffer(32768)
        length = psapi.GetModuleFileNameExW(
            wintypes.HANDLE(handle),
            ctypes.c_void_p(module),
            buffer,
            len(buffer),
        )
        path = buffer.value[:length] if length else ""
        base_address = int(ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value or 0)
        size = int(info.SizeOfImage)
        results.append(
            {
                "name": Path(path).name if path else "",
                "path": path,
                "base_address": base_address,
                "size": size,
                "end_address": base_address + size,
                "entry_point": int(ctypes.cast(info.EntryPoint, ctypes.c_void_p).value or 0),
            }
        )
    return sorted(results, key=lambda item: int(item["base_address"]))


def enum_windows() -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []

    @WNDENUMPROC
    def callback(hwnd, lparam):
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, length + 1)
        title = buffer.value.strip()
        if title:
            results.append((int(hwnd), title))
        return True

    user32.EnumWindows(callback, 0)
    return results


def get_window_pid(hwnd: int) -> int | None:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(pid))
    return int(pid.value) or None


def find_pids_by_window_title(pattern: str) -> list[int]:
    needle = pattern.lower()
    pids: list[int] = []
    for hwnd, title in enum_windows():
        if needle in title.lower():
            pid = get_window_pid(hwnd)
            if pid and pid not in pids:
                pids.append(pid)
    return pids


def is_key_down(vk_code: int) -> bool:
    state = user32.GetAsyncKeyState(vk_code)
    return bool(state & 0x8000)


def is_process_running(handle: int) -> bool:
    exit_code = wintypes.DWORD()
    if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        return False
    return exit_code.value == 259


def is_pid_running(pid: int) -> bool:
    try:
        handle = open_process(pid)
    except Exception:
        return False
    try:
        return is_process_running(handle)
    finally:
        close_handle(handle)


def vk_from_name(name: str) -> int:
    normalized = name.upper().strip()
    if normalized not in _VK_MAP:
        raise ValueError(f"Unsupported hotkey: {name}")
    return _VK_MAP[normalized]
