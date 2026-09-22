#include <windows.h>
#include <stdio.h>
#include <winternl.h>

/* Определение типа указателя на функцию */
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

int main(void) {
    /* Инициализация переменных в начале блока (хороший тон в C) */
    HMODULE hNtdll = NULL;
    pNtQueryInformationProcess NtQuery = NULL;
    DWORD debugFlags = -1; /* Инициализируем не нулем, чтобы избежать ложных срабатываний */
    HANDLE debugObject = NULL;

    /* Получаем хэндл системной библиотеки */
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("Error: Could not get handle to ntdll.dll\n");
        return 1;
    }

    /* Получаем адрес функции */
    NtQuery = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (NtQuery == NULL) {
        printf("Error: Could not find NtQueryInformationProcess\n");
        return 1;
    }

    /* 0x1F = ProcessDebugFlags (если флаг равен 0, отладчик присутствует) */
    NtQuery(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F, &debugFlags, sizeof(debugFlags), NULL);
    
    /* 0x1E = ProcessDebugObjectHandle (если хэндл не NULL, отладчик присутствует) */
    NtQuery(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &debugObject, sizeof(debugObject), NULL);

    /* Проверка результатов */
    if (debugFlags == 0 || debugObject != NULL) {
        printf("[NtQueryInformationProcess] Debugger detected via DebugFlags/ObjectHandle!\n");
    } else {
        printf("[NtQueryInformationProcess] No debugger.\n");
    }

    return 0;
}