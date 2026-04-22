# coff_parser: Advanced Standalone BOF Loader & Evasion Arsenal

**coff_parser** is a production-grade, standalone Beacon Object File (BOF) loader written in pure, defensive C. It is designed to execute custom, minimalistic BOFs directly in memory without relying on an active C2 framework, making it an ideal tool for local privilege escalation, evasion testing, and targeted red team operations.

Unlike massive C2 agents, `coff_parser` implements a strict, lightweight subset of the standard Cobalt Strike Beacon API (e.g., `BeaconPrintf`, `BeaconDataParse`). This enforces a "bring-your-own-API" philosophy where BOFs independently resolve their necessary Windows APIs via standard `DECLSPEC_IMPORT` patterns, resulting in highly controlled and OPSEC-safe execution.

## 🛡️ Core Architecture & OPSEC

The loader implements a strict **4-Pass Architecture** to safely map and execute objects:
1. **Size Calculation:** Calculates page-aligned memory requirements using safe integer math to prevent overflow attacks.
2. **Section Mapping:** Maps raw data into the allocated virtual memory buffer.
3. **Relocations:** Resolves symbols and applies AMD64/i386 relocations.
4. **Memory Protection & Execution:** Applies granular memory protections (`RX`, `RW`, `R`) via `VirtualProtect` before execution. **No lazy `RWX` memory is allocated.**

### Security Features
* **Defensive C Programming:** Utilizes custom `safe_math` helpers and `memcpy_s` to prevent buffer overflows and memory layout corruption.
* **Fail-Fast Resolution:** API resolution strictly enforces the `DLL$Function` syntax or a hardcoded whitelist. Unqualified symbols safely abort the loading process.
* **SEH Protection:** Payload execution is wrapped in a native `__try / __except` block (Structured Exception Handling) to prevent the loader from crashing if the BOF fails.
* **Least Privilege:** `SeDebugPrivilege` is only requested when explicitly required by the payload or user via CLI arguments.

## ⚔️ Included Evasion Arsenal

This repository includes a collection of advanced Red Team BOFs demonstrating modern EDR evasion and MITRE ATT&CK techniques:

* **`whoami_all.c` (T1033)**: Extracts and parses the current Process Token to print User, Groups, and Privileges natively without spawning `cmd.exe`.
* **`token_steal.c` (T1134.001)**: Demonstrates Access Token Manipulation. Opens `winlogon.exe`, duplicates the `NT AUTHORITY\SYSTEM` token, and applies it to the current thread via Impersonation.
* **`lsass_snapshot.c` (T1003.001)**: Advanced OS Credential Dumping. Evades direct `ReadProcessMemory` hooks by using the `PssCaptureSnapshot` API to create a hidden VA clone of LSASS before dumping.
* **`werfault_dump.c` (T1003.001)**: Silent Process Exit evasion. Modifies IFEO registry keys and triggers the undocumented `RtlReportSilentProcessExit` API, forcing the legitimate `WerFault.exe` to dump LSASS.
* **`super_bof_lsass.c`**: An autonomous attack chain. Dynamically resolves PIDs, steals the SYSTEM token from `winlogon.exe`, and performs a PSS Snapshot dump of LSASS, followed by full OPSEC cleanup (`RevertToSelf`).
* **`direct_syscall.c` (T1106)**: Pure-C implementation of the Halo's Gate technique. Dynamically parses the PEB and Export Directory to resolve NTDLL bases in-memory, extracts System Service Numbers (SSNs), and executes `syscall` instructions via a `.text` section stub to bypass user-land EDR hooks.

## 🛠️ Writing Custom BOFs

When writing your own payloads for `coff_parser`, adhere to the following rules:
1. **Entrypoint:** Your code must contain a `void go(char* args, int len)` function.
2. **Strict API Imports:** Explicitly declare which DLL contains the Windows API function using the `DECLSPEC_IMPORT` macro and the `DLLNAME$FunctionName` syntax (e.g., `KERNEL32$OpenProcess`).
3. **No CRT Dependencies:** Do not use standard C library functions (`strlen`, `malloc`, `printf`). Use native Windows APIs (`lstrlenA`, `HeapAlloc`).
4. **Supported Beacon APIs:** This loader deliberately implements a minimal, OPSEC-safe API subset. Supported functions are limited to: `BeaconPrintf`, `BeaconErrorPrintf`, `BeaconDataParse`, `BeaconDataInt`, `BeaconDataExtract`, and `BeaconIsAdmin`. *(Note: Heavy third-party frameworks like TrustedSec BOFs that rely on `BeaconFormat*` or external `base.c` helpers will need to be adapted to this minimalist core).*

## ⚙️ Compilation

The codebase is written in Pure C and utilizes native Windows SEH. No external C++ exception flags are required.

### 1. Compiling the Loader
Compile the loader using MSVC. The project is designed to compile cleanly without warnings on level 4 (`/W4`).

```cmd
cl.exe /O2 /W4 parser.c /Fecoff_parser.exe
```

### 2. Compiling the BOFs
**CRITICAL:** BOFs must be compiled without the C Standard Library (CRT). You *must* disable stack security cookies (`/GS-`), otherwise the BOF will trigger an Access Violation (`0xC0000005`) upon execution completion.

**MSVC:**
```cmd
cl.exe /c /GS- lsass_snapshot.c
```

## 🚀 Usage

Execute the loader and pass the compiled `.obj` file. 

```text
Usage: coff_parser.exe <file.obj> [-p PID] [-e]
  -p PID : Pass a target PID to the BOF (automatically requests SeDebugPrivilege)
  -e     : Explicitly request SeDebugPrivilege elevation (for autonomous BOFs)
```
 
**Examples:**
```cmd
:: Run a basic enumeration BOF
coff_parser.exe whoami_all.obj

:: Run a targeted BOF (e.g., steal token from PID 1234)
coff_parser.exe token_steal.obj -p 1234

:: Run an autonomous attack chain requiring elevation
coff_parser.exe super_bof_lsass.obj -e
```
