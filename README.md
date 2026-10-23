# py-workedtask — Javelin Anti-Cheat Protection

Baseline anti-cheat protection for the **Javelin Project** implemented in both C++ (`AntiCheat.cpp`) and Python (`anti_cheat.py` / `AntiCheat.py`).

## Features

1. **Debugger Detection**
   - **C++ (`AntiCheat.cpp`)**: Checks `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`, and PEB `BeingDebugged` on Windows, plus `/proc/self/status` `TracerPid` on Linux/POSIX.
   - **Python (`anti_cheat.py`)**: Checks `sys.gettrace()`, Win32 `IsDebuggerPresent()` / `CheckRemoteDebuggerPresent()`, and `/proc/self/status` `TracerPid`.
   - Immediately terminates with exit code `10` (`EXIT_DEBUGGER_DETECTED`) when a debugger is attached.

2. **Suspicious Process Detection**
   - Scans active processes for known cheat and reverse-engineering tools (`cheatengine.exe`, `x64dbg.exe`, `ollydbg.exe`, `ida.exe`, `ida64.exe`, `scylla.exe`, `processhacker.exe`, `httpdebuggerui.exe`, `windbg.exe`, `ghidra.exe`).
   - Immediately terminates with exit code `11` (`EXIT_SUSPICIOUS_PROCESS`) when a prohibited process is found.

3. **Self-Integrity Verification**
   - Supports optional CRC32 (`JAVELIN_EXPECTED_CRC32` in C++) and SHA-256 (`JAVELIN_EXPECTED_SHA256` in Python) runtime self-integrity checks.

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
