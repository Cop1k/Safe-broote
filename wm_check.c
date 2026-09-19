#if defined(_WIN32) //Windows
    //Сетевые библиотеки Windows
    #include <winsock2.h>
    #include <windows.h>
    #include <iphlpapi.h>

    #if defined(_MSC_VER) //MSVC
        #include <intrin.h>
        #pragma comment(lib, "iphlpapi.lib") //Для получения MAC-адресса
        #pragma comment(lib, "ws2_32.lib") //Для работы остальног 
    #else
        #include <cpuid.h> //Для получения данных о гипервизоре
    #endif

#elif defined(__linux__) //Linux
    //Сетевые библиотеки Linux
    #include <sys/types.h>
    #include <ifaddrs.h>
    #include <netpacket/packet.h>
    #include <cpuid.h>
#endif

// Проверяем OUI (первые 3 байта). Используем платформонезависимый тип uint8_t
const char* check_mac_oui(const uint8_t* mac) {
    if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) return "VMware";
    if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) return "VMware";
    if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14) return "VMware";
    if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) return "VMware";
    if (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) return "VirtualBox";
    if (mac[0] == 0x52 && mac[1] == 0x54 && mac[2] == 0x00) return "QEMU / KVM";
    if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) return "Microsoft Hyper-V";
    if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42) return "Parallels";

    return NULL;
}

// =========================================================
// ПЛАТФОРМОЗАВИСИМЫЕ ФУНКЦИИ СКАНИРОВАНИЯ СЕТИ
// =========================================================

void scan_mac_addresses(int *vm_detected) {
#ifdef _WIN32
    ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    
    if (pAdapterInfo == NULL) return;

    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
        if (pAdapterInfo == NULL) return;
    }

    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->AddressLength == 6) {
                uint8_t* mac = (uint8_t*)pAdapter->Address;
                printf("Adapter: %s\n", pAdapter->Description);
                printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", 
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

                const char* vm_name = check_mac_oui(mac);
                if (vm_name != NULL) {
                    printf("[!] DETECTED VM OUI: %s\n", vm_name);
                    *vm_detected = 1;
                } else {
                    printf("[+] Looks like a physical device.\n");
                }
                printf("----------------------------------------\n");
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);

#elif defined(__linux__)
    // --- РЕАЛИЗАЦИЯ ДЛЯ LINUX ---
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;

    // Получаем связный список всех сетевых интерфейсов
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // Ищем интерфейсы, относящиеся к физическому уровню (AF_PACKET)
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            
            // Проверяем, что длина адреса 6 байт (Ethernet MAC)
            if (s->sll_halen == 6) {
                uint8_t *mac = (uint8_t *)s->sll_addr;
                
                // Игнорируем loopback-интерфейс (обычно MAC 00:00:00:00:00:00)
                if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0) continue;

                printf("Adapter: %s\n", ifa->ifa_name);
                printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", 
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

                const char* vm_name = check_mac_oui(mac);
                if (vm_name != NULL) {
                    printf("[!] DETECTED VM OUI: %s\n", vm_name);
                    *vm_detected = 1;
                } else {
                    printf("[+] Looks like a physical device.\n");
                }
                printf("----------------------------------------\n");
            }
        }
    }
    freeifaddrs(ifaddr);
#endif
}

bool cpu_check(); //Функция для проверка наличия бита гипервизора
int check_hypervisor_bit(); //Функция для проверка наличия бита гипервизора
bool vm_decision(); //Функция для принятия решения

//Функция для проверка наличия бита гипервизора
bool cpu_check() {
    if (check_hypervisor_bit()) return 1; //Обнаружен гипервизор
    return 0; //Не обнражуен гипервизор
}
//Вспомогательная функция для проверка наличия бита гипервизора
int check_hypervisor_bit() {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

    #ifdef _MSC_VER
        int cpu_info_arr[4]; //Массив для регистров EAX, EBX, ECX, EDX
        __cpuid(cpu_info_arr, 1); //Вызов CPUID с параметром EAX = 1 (запрос ифнормации о ЦП)
        ecx = (unsigned int)cpu_info_arr[2]; //Регистр ECX содержит в себе бит гипервизора
    #else
        __cpuid(1, eax, ebx, ecx, edx); //Аналогично, но для GCC
    #endif

    return (ecx >> 31) & 1; //Сдвиг битов регистра так, чтобы получить 32 бит (бит гипервизора)
}
//Функция для принятия решения
bool vm_decision(){
    if (cpu_check()) return 1;
    return 0;
}
