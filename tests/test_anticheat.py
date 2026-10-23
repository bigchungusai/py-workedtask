import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import anti_cheat
import AntiCheat


class TestBasicAntiCheatProtection(unittest.TestCase):
    def setUp(self):
        os.environ.pop("JAVELIN_SIMULATE_DEBUGGER", None)
        os.environ.pop("JAVELIN_SIMULATE_PROCESSES", None)
        os.environ.pop("JAVELIN_EXPECTED_SHA256", None)

    def test_module_parity(self):
        self.assertEqual(anti_cheat.SUSPICIOUS_PROCESSES, AntiCheat.SUSPICIOUS_PROCESSES)

    def test_debugger_detection_via_trace_hook(self):
        self.assertFalse(
            anti_cheat.check_debugger(
                trace_getter=lambda: None,
                proc_status_path=None,
            )
        )
        self.assertTrue(
            anti_cheat.check_debugger(
                trace_getter=lambda: object(),
                proc_status_path=None,
            )
        )

    def test_debugger_detection_via_proc_status_tracer_pid(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write("Name:\tpython3\nState:\tR (running)\nTracerPid:\t4242\n")
            status_path = tmp.name
        try:
            self.assertTrue(
                anti_cheat.check_debugger(
                    trace_getter=lambda: None,
                    proc_status_path=status_path,
                )
            )
        finally:
            os.unlink(status_path)

    def test_suspicious_process_detection_blocks_known_cheat_tools(self):
        for tool in ("CheatEngine.exe", "x64dbg.exe", "ollydbg.exe", "ida64", "C:\\Tools\\scylla.exe"):
            self.assertTrue(
                anti_cheat.check_suspicious_processes(
                    process_provider=lambda t=tool: ["explorer.exe", t, "python.exe"]
                ),
                f"Expected {tool} to be flagged as suspicious",
            )

        self.assertFalse(
            anti_cheat.check_suspicious_processes(
                process_provider=lambda: ["systemd", "bash", "python3", "explorer.exe"]
            )
        )

    def test_application_exits_when_debugger_detected(self):
        with self.assertRaises(SystemExit) as ctx:
            anti_cheat.run_anticheat_checks(
                exit_on_failure=True,
                trace_getter=lambda: object(),
                proc_status_path=None,
                process_provider=lambda: [],
            )
        self.assertEqual(ctx.exception.code, anti_cheat.EXIT_DEBUGGER_DETECTED)

    def test_application_exits_when_suspicious_process_found(self):
        with self.assertRaises(SystemExit) as ctx:
            anti_cheat.run_anticheat_checks(
                exit_on_failure=True,
                trace_getter=lambda: None,
                proc_status_path=None,
                process_provider=lambda: ["notepad.exe", "x64dbg.exe"],
            )
        self.assertEqual(ctx.exception.code, anti_cheat.EXIT_SUSPICIOUS_PROCESS)

    def test_clean_run_succeeds(self):
        code = anti_cheat.run_anticheat_checks(
            exit_on_failure=False,
            trace_getter=lambda: None,
            proc_status_path=None,
            process_provider=lambda: ["init", "python3"],
        )
        self.assertEqual(code, anti_cheat.EXIT_OK)

    def test_cli_subprocess_exits_on_debugger_and_suspicious_process(self):
        script = str(Path(__file__).resolve().parent.parent / "anti_cheat.py")

        env_clean = os.environ.copy()
        res_clean = subprocess.run([sys.executable, script], env=env_clean, capture_output=True, text=True)
        self.assertEqual(res_clean.returncode, 0)
        self.assertIn("All clear", res_clean.stdout)

        env_dbg = os.environ.copy()
        env_dbg["JAVELIN_SIMULATE_DEBUGGER"] = "1"
        res_dbg = subprocess.run([sys.executable, script], env=env_dbg, capture_output=True, text=True)
        self.assertEqual(res_dbg.returncode, anti_cheat.EXIT_DEBUGGER_DETECTED)
        self.assertIn("Debugger detected", res_dbg.stderr)

        env_proc = os.environ.copy()
        env_proc["JAVELIN_SIMULATE_PROCESSES"] = " explorer.exe, CheatEngine.exe "
        res_proc = subprocess.run([sys.executable, script], env=env_proc, capture_output=True, text=True)
        self.assertEqual(res_proc.returncode, anti_cheat.EXIT_SUSPICIOUS_PROCESS)
        self.assertIn("Suspicious process detected", res_proc.stderr)

    @unittest.skipUnless(shutil.which("g++"), "g++ not installed")
    def test_cpp_client_builds_and_enforces_guards(self):
        cpp_src = Path(__file__).resolve().parent.parent / "AntiCheat.cpp"
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_path = Path(tmpdir) / "anticheat_bin"
            subprocess.check_call(["g++", "-std=c++17", "-O2", str(cpp_src), "-o", str(bin_path)])

            res_ok = subprocess.run([str(bin_path)], capture_output=True, text=True)
            self.assertEqual(res_ok.returncode, 0)
            self.assertIn("All clear", res_ok.stdout)

            env_dbg = os.environ.copy()
            env_dbg["JAVELIN_SIMULATE_DEBUGGER"] = "1"
            res_dbg = subprocess.run([str(bin_path)], env=env_dbg, capture_output=True, text=True)
            self.assertEqual(res_dbg.returncode, 10)
            self.assertIn("Debugger detected", res_dbg.stderr)

            env_proc = os.environ.copy()
            env_proc["JAVELIN_SIMULATE_PROCESSES"] = "ollydbg.exe"
            res_proc = subprocess.run([str(bin_path)], env=env_proc, capture_output=True, text=True)
            self.assertEqual(res_proc.returncode, 11)
            self.assertIn("Suspicious process detected", res_proc.stderr)


if __name__ == "__main__":
    unittest.main()
