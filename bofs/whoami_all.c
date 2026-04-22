#include <windows.h>
#include "beacon.h"

// --- DYNAMIC API RESOLUTION ---
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);

// --- MEMORY HELPERS ---
void* allocate_memory(SIZE_T size) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void free_memory(void* ptr) {
    if (ptr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ptr);
}

// --- UTILITY TO PRINT SIDs ---
void PrintSidName(PSID sid, const char* prefix) {
    char name[256];
    char domain[256];
    DWORD nameSize = 256;
    DWORD domainSize = 256;
    SID_NAME_USE sidUse;

    if (ADVAPI32$LookupAccountSidA(NULL, sid, name, &nameSize, domain, &domainSize, &sidUse)) {
        BeaconPrintf(CALLBACK_OUTPUT, "    %-15s %s\\%s", prefix, domain, name);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "    %-15s [Unknown SID]", prefix);
    }
}

// --- BOF ENTRYPOINT ---
void go(char* args, int len) {
    HANDLE hToken = NULL;
    DWORD dwSize = 0;

    // Открываем токен текущего процесса (лоадера)
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process token. Error: %d", KERNEL32$GetLastError());
        return;
    }

    // 1. ЧТЕНИЕ ИНФОРМАЦИИ О ПОЛЬЗОВАТЕЛЕ
    BeaconPrintf(CALLBACK_OUTPUT, "=== USER INFORMATION ===");
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)allocate_memory(dwSize);
    if (pTokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        PrintSidName(pTokenUser->User.Sid, "User Name:");
    }
    free_memory(pTokenUser);

    // 2. ЧТЕНИЕ ИНФОРМАЦИИ О ГРУППАХ
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== GROUP INFORMATION ===");
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    PTOKEN_GROUPS pTokenGroups = (PTOKEN_GROUPS)allocate_memory(dwSize);
    if (pTokenGroups && ADVAPI32$GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize, &dwSize)) {
        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
            DWORD attr = pTokenGroups->Groups[i].Attributes;
            // Пропускаем Logon SID, чтобы не замусоривать вывод (это стандартное поведение)
            if ((attr & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) continue; 
            PrintSidName(pTokenGroups->Groups[i].Sid, "Group:");
        }
    }
    free_memory(pTokenGroups);

    // 3. ЧТЕНИЕ ИНФОРМАЦИИ О ПРИВИЛЕГИЯХ
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== PRIVILEGES INFORMATION ===");
    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    PTOKEN_PRIVILEGES pTokenPriv = (PTOKEN_PRIVILEGES)allocate_memory(dwSize);
    if (pTokenPriv && ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, pTokenPriv, dwSize, &dwSize)) {
        for (DWORD i = 0; i < pTokenPriv->PrivilegeCount; i++) {
            char name[256];
            DWORD nameSize = 256;
            if (ADVAPI32$LookupPrivilegeNameA(NULL, &pTokenPriv->Privileges[i].Luid, name, &nameSize)) {
                DWORD attr = pTokenPriv->Privileges[i].Attributes;
                const char* state = (attr & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled";
                BeaconPrintf(CALLBACK_OUTPUT, "    %-35s %s", name, state);
            }
        }
    }
    free_memory(pTokenPriv);

    KERNEL32$CloseHandle(hToken);
}