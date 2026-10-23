# py-workedtask — Javelin Anti-Cheat

Minimal anti-cheat guards for C++ and Python applications:
- **Debugger detection**
- **Suspicious process detection**
- **Optional self-integrity verification** (CRC32 / SHA-256 for the running C++ executable, and SHA-256 via `JAVELIN_EXPECTED_SHA256` for the Python script)

---

## Setting Expected Integrity Hashes

### 1. Python (`JAVELIN_EXPECTED_SHA256`)

Compute the SHA-256 hash of `AntiCheat.py` and pass it via the `JAVELIN_EXPECTED_SHA256` environment variable:

```bash
# Compute the SHA-256 digest
export JAVELIN_EXPECTED_SHA256="$(sha256sum AntiCheat.py | awk '{print $1}')"

# Run with integrity verification enabled (exits with 0 if unmodified)
python3 AntiCheat.py

# Simulate tampering (non-matching hash triggers guarded exit)
JAVELIN_EXPECTED_SHA256="0000000000000000000000000000000000000000000000000000000000000000" python3 AntiCheat.py
```

If `JAVELIN_EXPECTED_SHA256` is unset or empty, the optional integrity check is skipped.

### 2. C++ (`JAVELIN_EXPECTED_CRC32` or `JAVELIN_EXPECTED_SHA256`)

Compile `AntiCheat.cpp` with either `JAVELIN_EXPECTED_CRC32` (32-bit unsigned integer) or `JAVELIN_EXPECTED_SHA256` (64-character hex string) defined at build time:

```bash
# Build with a target SHA-256 or CRC32 constant
g++ -std=c++17 -O2 -DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp -o anticheat
# or with SHA-256:
g++ -std=c++17 -O2 -DJAVELIN_EXPECTED_SHA256=\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\" AntiCheat.cpp -o anticheat
```

 Note: Because embedding a hash inside the binary changes the binary itself, production pipelines either store the baseline hash in an external signed manifest or patch a reserved section post-build; passing a non-matching build-time constant immediately exercises the guarded exit path.

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
