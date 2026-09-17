#include <windows.h>
#include <stdio.h>

BOOL isDebugged = TRUE;

// Пользовательский фильтр необработанных исключений
LONG WINAPI CustomUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionPointers) {
    isDebugged = FALSE; // Сработает, только если нет отладчика
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void) {
    SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);

    // Провоцируем фейковый сбой (исключение)
    RaiseException(EXCEPTION_INT_DIVIDE_BY_ZERO, 0, 0, NULL);

    if (isDebugged) {
        printf("[!] Debugger intercepted the exception!\n");
        char arr[10];
        scanf("%s", &arr);
    }

    printf("[+] No debugger - unhandled exception filter ran!\n");
    char arr[10];
    scanf("%s", &arr);
    return 0;
}