#include <windows.h>
#include <stdio.h>

int main(void) {
    // __readgsqword(0x60) получает адрес PEB в 64-битных процессах
    BYTE* pBeingDebugged = (BYTE*)(__readgsqword(0x60) + 2);

    if (*pBeingDebugged) {
        printf("[PEB->BeingDebugged] Debugger detected!\n");
    } else {
        printf("[PEB->BeingDebugged] No debugger.\n");
    }
    
    return 0;
}