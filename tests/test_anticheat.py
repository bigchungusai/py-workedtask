import os
import subprocess
import sys
import unittest
from pathlib import Path

import AntiCheat


class TestAntiCheatIntegrity(unittest.TestCase):
    def test_unset_env_passes(self):
        env = os.environ.copy()
        env.pop("JAVELIN_EXPECTED_SHA256", None)
        proc = subprocess.run(
            [sys.executable, "AntiCheat.py"],
            cwd=Path(__file__).resolve().parent.parent,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("All clear. Continue.", proc.stdout)

    def test_matching_sha256_passes(self):
        script = Path(__file__).resolve().parent.parent / "AntiCheat.py"
        expected = AntiCheat.compute_file_sha256(script)
        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = expected
        proc = subprocess.run(
            [sys.executable, str(script)],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("All clear. Continue.", proc.stdout)

    def test_mismatching_sha256_exits_guarded(self):
        script = Path(__file__).resolve().parent.parent / "AntiCheat.py"
        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = "0" * 64
        proc = subprocess.run(
            [sys.executable, str(script)],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Integrity check failed", proc.stderr)


if __name__ == "__main__":
    unittest.main()
