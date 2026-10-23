#!/usr/bin/env python3
"""
Javelin Project - Python Anti-Cheat Monitor (anti_cheat.py)
Implements baseline anti-cheat protection:
  1. Debugger detection (sys.gettrace, Windows Win32 APIs, Linux /proc/self/status TracerPid, loaded debugger modules)
  2. Suspicious process detection (Cheat Engine, x64dbg, OllyDbg, IDA, Scylla, Process Hacker, HTTP Debugger, etc.)
  3. Immediate application termination when a debugger or suspicious process is detected.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Set

TAG = "[Javelin AntiCheat] "

EXIT_OK = 0
EXIT_DEBUGGER_DETECTED = 10
EXIT_SUSPICIOUS_PROCESS = 11
EXIT_INTEGRITY_FAILED = 12

SUSPICIOUS_PROCESSES: Sequence[str] = (
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "idag.exe",
    "idaw.exe",
    "scylla.exe",
    "scylla_x64.exe",
    "processhacker.exe",
    "windbg.exe",
    "ghidra.exe",
)

DEBUGGER_MODULES: Set[str] = {
    "pdb",
    "pydevd",
    "debugpy",
    "bdb",
    "ipdb",
    "rpdb",
    "winpdb",
}


def _normalize_process_name(name: str) -> str:
    cleaned = name.strip().lower()
    if "/" in cleaned or "\\" in cleaned:
        cleaned = os.path.basename(cleaned.replace("\\", "/"))
    return cleaned


def _strip_exe(name: str) -> str:
    norm = _normalize_process_name(name)
    return norm[:-4] if norm.endswith(".exe") else norm


def build_suspicious_set(extra_processes: Optional[Iterable[str]] = None) -> Set[str]:
    names: Set[str] = set()
    for proc in SUSPICIOUS_PROCESSES:
        norm = _normalize_process_name(proc)
        if norm:
            names.add(norm)
            names.add(_strip_exe(norm))
    if extra_processes:
        for proc in extra_processes:
            norm = _normalize_process_name(proc)
            if norm:
                names.add(norm)
                names.add(_strip_exe(norm))
    return names


def check_debugger(
    *,
    trace_getter: Optional[Callable[[], object]] = None,
    proc_status_path: Optional[str] = "/proc/self/status",
    check_loaded_modules: bool = False,
) -> bool:
    """
    Return True if an attached debugger is detected.
    Checks:
      1. Environment simulation variable JAVELIN_SIMULATE_DEBUGGER
      2. Python trace hook via sys.gettrace()
      3. Windows Kernel32 IsDebuggerPresent() and CheckRemoteDebuggerPresent()
      4. Linux /proc/self/status TracerPid != 0
      5. Optional active debugger module check
    """
    sim = os.environ.get("JAVELIN_SIMULATE_DEBUGGER", "").strip().lower()
    if sim in {"1", "true", "yes"}:
        return True

    getter = trace_getter or getattr(sys, "gettrace", None)
    if callable(getter) and getter() is not None:
        return True

    if check_loaded_modules:
        for mod_name in DEBUGGER_MODULES:
            if mod_name in sys.modules:
                return True

    if platform.system().lower() == "windows":
        try:
            kernel32 = getattr(ctypes, "windll", None)
            if kernel32 is not None:
                if kernel32.kernel32.IsDebuggerPresent() != 0:
                    return True
                is_remote = ctypes.c_int(0)
                handle = kernel32.kernel32.GetCurrentProcess()
                if (
                    kernel32.kernel32.CheckRemoteDebuggerPresent(
                        handle, ctypes.byref(is_remote)
                    )
                    != 0
                    and is_remote.value != 0
                ):
                    return True
        except Exception:
            pass

    if proc_status_path and os.path.exists(proc_status_path):
        try:
            with open(proc_status_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        parts = line.split(":", 1)[1].strip().split()
                        if parts and int(parts[0]) != 0:
                            return True
                        break
        except Exception:
            pass

    return False


def list_running_processes() -> List[str]:
    """
    Enumerate running process names across Windows, Linux, and macOS without requiring third-party packages.
    Uses /proc/<pid>/comm on Linux, tasklist on Windows, and ps as fallback.
    """
    processes: List[str] = []

    sim_procs = os.environ.get("JAVELIN_SIMULATE_PROCESSES", "").strip()
    if sim_procs:
        processes.extend(p.strip() for p in sim_procs.split(",") if p.strip())

    # 1. Linux /proc enumeration
    proc_root = Path("/proc")
    if proc_root.is_dir():
        self_pid = str(os.getpid())
        try:
            for entry in os.scandir(proc_root):
                if not entry.name.isdigit() or entry.name == self_pid:
                    continue
                comm_file = proc_root / entry.name / "comm"
                try:
                    name = comm_file.read_text(encoding="utf-8", errors="ignore").strip()
                    if name:
                        processes.append(name)
                except OSError:
                    continue
        except OSError:
            pass
        if processes:
            return processes

    # 2. Windows tasklist fallback
    if platform.system().lower() == "windows":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                first_col = line.split(",")[0].strip().strip('"')
                if first_col:
                    processes.append(first_col)
            return processes
        except Exception:
            pass

    # 3. POSIX ps fallback
    try:
        out = subprocess.check_output(
            ["ps", "-eo", "comm="],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        for line in out.splitlines():
            name = line.strip()
            if name:
                processes.append(name)
    except Exception:
        pass

    return processes


def find_suspicious_process(
    *,
    extra_processes: Optional[Iterable[str]] = None,
    process_provider: Optional[Callable[[], Iterable[str]]] = None,
) -> Optional[str]:
    """
    Return the first detected suspicious process name, or None if clean.
    """
    targets = build_suspicious_set(extra_processes)
    provider = process_provider or list_running_processes
    for raw_name in provider():
        norm = _normalize_process_name(raw_name)
        if not norm:
            continue
        if norm in targets or _strip_exe(norm) in targets:
            return raw_name.strip()
    return None


def check_suspicious_processes(
    *,
    extra_processes: Optional[Iterable[str]] = None,
    process_provider: Optional[Callable[[], Iterable[str]]] = None,
) -> bool:
    """
    Return True if any known cheat/debugging process is currently running.
    """
    return (
        find_suspicious_process(
            extra_processes=extra_processes,
            process_provider=process_provider,
        )
        is not None
    )


def compute_sha256(file_path: Optional[str] = None) -> str:
    target = Path(file_path) if file_path else Path(__file__).resolve()
    h = hashlib.sha256()
    with open(target, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.write(chunk)
    return h.hexdigest()


def check_self_integrity(
    expected_sha256: Optional[str] = None,
    file_path: Optional[str] = None,
) -> bool:
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip()
    )
    if not expected:
        return True
    try:
        actual = compute_sha256(file_path)
    except OSError:
        return False
    return actual.lower() == expected.strip().lower()


def run_anticheat_checks(
    *,
    exit_on_failure: bool = True,
    extra_suspicious_processes: Optional[Iterable[str]] = None,
    process_provider: Optional[Callable[[], Iterable[str]]] = None,
    trace_getter: Optional[Callable[[], object]] = None,
    proc_status_path: Optional[str] = "/proc/self/status",
    expected_sha256: Optional[str] = None,
) -> int:
    print(f"{TAG}starting checks...")

    if check_debugger(trace_getter=trace_getter, proc_status_path=proc_status_path):
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        if exit_on_failure:
            sys.exit(EXIT_DEBUGGER_DETECTED)
        return EXIT_DEBUGGER_DETECTED

    detected_proc = find_suspicious_process(
        extra_processes=extra_suspicious_processes,
        process_provider=process_provider,
    )
    if detected_proc is not None:
        print(
            f"{TAG}Suspicious process detected ({detected_proc}). Exiting.",
            file=sys.stderr,
        )
        if exit_on_failure:
            sys.exit(EXIT_SUSPICIOUS_PROCESS)
        return EXIT_SUSPICIOUS_PROCESS

    if not check_self_integrity(expected_sha256=expected_sha256):
        print(
            f"{TAG}Integrity check failed (hash mismatch). Exiting.",
            file=sys.stderr,
        )
        if exit_on_failure:
            sys.exit(EXIT_INTEGRITY_FAILED)
        return EXIT_INTEGRITY_FAILED

    print(f"{TAG}All clear. Continue.")
    return EXIT_OK


def main() -> int:
    return run_anticheat_checks(exit_on_failure=True)


if __name__ == "__main__":
    main()
