#include <stdio.h>
#include <string.h>

// Макрос для кроссплатформенного вызова CPUID
#ifdef _MSC_VER
    #include <intrin.h> // Для MSVC (Windows)
    void get_cpuid(unsigned int leaf, unsigned int* eax, unsigned int* ebx, unsigned int* ecx, unsigned int* edx) {
        int info[4];
        __cpuid(info, leaf);
        *eax = info[0]; *ebx = info[1]; *ecx = info[2]; *edx = info[3];
    }
#else
    #include <cpuid.h> // Для GCC/Clang
    void get_cpuid(unsigned int leaf, unsigned int* eax, unsigned int* ebx, unsigned int* ecx, unsigned int* edx) {
        __cpuid(leaf, *eax, *ebx, *ecx, *edx);
    }
#endif

void check_hypervisor_details() {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

    // 1. Сначала проверяем 31-й бит, чтобы узнать, активен ли гипервизор вообще
    get_cpuid(1, &eax, &ebx, &ecx, &edx);
    if (!((ecx >> 31) & 1)) {
        printf("Hypervisor NOT detected. You are on a pure Host machine.\n");
        return;
    }
    printf("Hypervisor present bit is set (1).\n");

    // 2. Получаем вендора гипервизора (EAX = 0x40000000)
    get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx);

    char vendor[13]; // 12 байт + нуль-терминатор
    // ВАЖНО: Порядок регистров для гипервизора — EBX, ECX, EDX
    // (в отличие от процессоров, где порядок EBX, EDX, ECX)
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = '\0'; // Завершаем строку

    printf("Hypervisor Vendor: '%s'\n", vendor);

    // 3. Отличаем настоящую виртуалку Hyper-V от Хоста Windows (Root Partition)
    if (strcmp(vendor, "Microsoft Hv") == 0) {
        // Если это Microsoft, запрашиваем привилегии раздела гипервизора (Leaf 0x40000003)
        get_cpuid(0x40000003, &eax, &ebx, &ecx, &edx);
        
        // Согласно спецификации Hyper-V TLFS, 12-й бит в регистре EBX 
        // означает наличие привилегий управления процессором (CpuManagement flag).
        // Эти привилегии есть ТОЛЬКО у корневого раздела (Root Partition), т.е. у Хоста.
        if ((ebx >> 12) & 1) {
            printf("-> Verdict: You are on the PHYSICAL HOST OS with VBS/Hyper-V enabled in the background.\n");
        } else {
            printf("-> Verdict: You are inside a true GUEST Virtual Machine.\n");
        }
    }
}

int main() {
    check_hypervisor_details();
    return 0;
}