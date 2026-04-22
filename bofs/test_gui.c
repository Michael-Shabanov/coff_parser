#include <windows.h>
#include "beacon.h"

// Объявляем функцию в формате Библиотека$Функция
DECLSPEC_IMPORT int WINAPI USER32$MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting to display a MessageBox via USER32...");

    // Вызываем функцию. Если лоадер сработал, адрес будет верным.
    USER32$MessageBoxA(NULL, "BOF Loader: Dynamic DLL Loading Successful!", "Pwned", MB_OK | MB_ICONINFORMATION);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] MessageBox closed.");
}