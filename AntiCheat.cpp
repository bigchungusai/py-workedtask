// AntiCheat.cpp
// Javelin Project - Baseline Anti-Cheat Guards (Issue #2)
// Features:
//   1. Debugger detection (Windows IsDebuggerPresent / CheckRemoteDebuggerPresent / PEB BeingDebugged + Linux TracerPid + env override for testing)
//   2. Suspicious process detection (Cheat Engine, x64dbg, OllyDbg, IDA, Scylla, Process Hacker, HTTP Debugger)
//   3. Self-integrity verification (CRC32)

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static const char* kTag = "[Javelin AntiCheat] ";

static const int kExitDebuggerDetected = 10;
static const int kExitSuspiciousProcess = 11;
static const int kExitIntegrityFailed = 12;

// --- Configurable lists ---
static std::vector<std::string> kSuspiciousProcesses = {
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
    "ghidra.exe"
};

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string stripExeSuffix(const std::string& name) {
    std::string lower = toLower(name);
    if (lower.size() > 4 && lower.substr(lower.size() - 4) == ".exe") {
        return lower.substr(0, lower.size() - 4);
    }
    return lower;
}

static bool matchesSuspiciousProcessName(const std::string& rawCandidate) {
    if (rawCandidate.empty()) return false;
    std::string candidate = toLower(rawCandidate);
    // Extract basename if path was provided
    size_t slashPos = candidate.find_last_of("/\\");
    if (slashPos != std::string::npos) {
        candidate = candidate.substr(slashPos + 1);
    }
    std::string candidateBase = stripExeSuffix(candidate);

    for (const auto& bad : kSuspiciousProcesses) {
        std::string badLower = toLower(bad);
        std::string badBase = stripExeSuffix(badLower);
        if (candidate == badLower || (!badBase.empty() && candidateBase == badBase)) {
            return true;
        }
    }
    return false;
}

// Simple CRC32 (polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

// --- Checks ---
static bool checkDebugger() {
    // Allow deterministic test simulation via environment variable
    if (const char* sim = std::getenv("JAVELIN_SIMULATE_DEBUGGER")) {
        std::string val = toLower(sim);
        if (val == "1" || val == "true" || val == "yes") {
            return true;
        }
    }

#ifdef _WIN32
    if (IsDebuggerPresent()) return true;

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
#ifdef _M_IX86
    __try {
        BYTE* peb = *(BYTE**)_readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64)
    __try {
        BYTE* peb = *(BYTE**)_readgsqword(0x60);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
#else
    // POSIX / Linux: inspect TracerPid in /proc/self/status
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::istringstream iss(line.substr(10));
            int tracerPid = 0;
            if (iss >> tracerPid && tracerPid != 0) {
                return true;
            }
            break;
        }
    }
#endif

    return false;
}

static bool checkSuspiciousProcesses() {
    // Allow deterministic test simulation via comma-separated process list
    if (const char* simProcs = std::getenv("JAVELIN_SIMULATE_PROCESSES")) {
        std::istringstream ss(simProcs);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (matchesSuspiciousProcessName(item)) {
                return true;
            }
        }
    }

#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::string name = toLower(pe.szExeFile);
        if (matchesSuspiciousProcessName(name)) {
            CloseHandle(snap);
            return true;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
#else
    DIR* procDir = opendir("/proc");
    if (!procDir) return false;

    struct dirent* entry = nullptr;
    pid_t selfPid = getpid();
    while ((entry = readdir(procDir)) != nullptr) {
        const char* dname = entry->d_name;
        if (!std::isdigit(static_cast<unsigned char>(dname[0]))) continue;
        pid_t pid = static_cast<pid_t>(std::atol(dname));
        if (pid <= 0 || pid == selfPid) continue;

        std::string commPath = std::string("/proc/") + dname + "/comm";
        std::ifstream commFile(commPath);
        std::string commName;
        if (std::getline(commFile, commName) && matchesSuspiciousProcessName(commName)) {
            closedir(procDir);
            return true;
        }
    }
    closedir(procDir);
    return false;
#endif
}

static bool checkSelfIntegrity(uint32_t expectedCrc) {
#ifdef _WIN32
    wchar_t path[MAX_PATH]{};
    DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;
    std::ifstream f(path, std::ios::binary);
#else
    char path[PATH_MAX]{};
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0 || static_cast<size_t>(len) >= sizeof(path) - 1) return false;
    path[len] = '\0';
    std::ifstream f(path, std::ios::binary);
#endif
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(bytes.data()), size)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebuggerDetected;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitSuspiciousProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrity(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return kExitIntegrityFailed;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
