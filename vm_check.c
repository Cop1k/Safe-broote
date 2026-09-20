#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#if defined(_WIN32) //Windows
    #include <cpuid.h> //Для получения данных о гипервизоре
    //Сетевые библиотеки Windows
    #include <winsock2.h>
    #include <windows.h>
    #include <iphlpapi.h>

#elif defined(__linux__) //Linux
    //Сетевые библиотеки Linux
    #include <sys/types.h>
    #include <ifaddrs.h>
    #include <netpacket/packet.h>
    #include <cpuid.h>
    #include <stdlib.h>
#endif

bool mac_check(); //Функция для проверки MAC-адресов сетевых интерфейсов
bool scan_mac(uint8_t* mac); //Функция для проверки первых 3 байт MAC-адреса
bool cpu_check(); //Функция для проверка наличия бита гипервизора
int check_hypervisor_bit(); //Функция для проверка наличия бита гипервизора
bool vm_decision(); //Функция для принятия решения

// Перевод строки в нижний регистр
void to_lowercase(char* str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

// Проверка строки на наличие известных маркеров виртуальных машин
int check_for_vm_markers(const char* data, const char* field_name) {
    if (data == NULL || strlen(data) == 0) return 0;

    char lower_data[256];
    // Безопасное копирование строки
    snprintf(lower_data, sizeof(lower_data), "%s", data);
    to_lowercase(lower_data);

    const char* vm_markers[] = {
        "vmware",
        "virtualbox",
        "innotek",
        "qemu",
        "bochs",
        "parallels",
        "microsoft corporation", // В сочетании с Virtual Machine
        "virtual machine"
    };

    int num_markers = sizeof(vm_markers) / sizeof(vm_markers[0]);

    for (int i = 0; i < num_markers; i++) {
        if (strstr(lower_data, vm_markers[i]) != NULL) {
            printf("[!] VM DETECTED in %s: '%s' contains marker '%s'\n", field_name, data, vm_markers[i]);
            return 1;
        }
    }
    
    printf("[+] %s looks clean: '%s'\n", field_name, data);
    return 0;
}

// =========================================================
// ПЛАТФОРМОЗАВИСИМЫЕ ФУНКЦИИ ЧТЕНИЯ ДАННЫХ
// =========================================================

#ifdef _WIN32
// --- РЕАЛИЗАЦИЯ ДЛЯ WINDOWS (Через реестр) ---
int read_os_string(const char* key_path, const char* value_name, char* outBuffer, size_t bufferSize) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type;
        DWORD size = (DWORD)bufferSize;
        if (RegQueryValueExA(hKey, value_name, NULL, &type, (LPBYTE)outBuffer, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return 1;
        }
        RegCloseKey(hKey);
    }
    return 0;
}

void scan_motherboard(int *vm_score) {
    const char* bios_key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    char buffer[256];

    if (read_os_string(bios_key, "SystemManufacturer", buffer, sizeof(buffer)))
        *vm_score += check_for_vm_markers(buffer, "SystemManufacturer");

    if (read_os_string(bios_key, "SystemProductName", buffer, sizeof(buffer)))
        *vm_score += check_for_vm_markers(buffer, "SystemProductName");

    if (read_os_string(bios_key, "BaseBoardManufacturer", buffer, sizeof(buffer)))
        *vm_score += check_for_vm_markers(buffer, "BaseBoardManufacturer");
}

#elif defined(__linux__)
// --- РЕАЛИЗАЦИЯ ДЛЯ LINUX (Через файловую систему sysfs) ---
int read_os_string(const char* filepath, char* outBuffer, size_t bufferSize) {
    FILE* file = fopen(filepath, "r");
    if (file != NULL) {
        if (fgets(outBuffer, bufferSize, file) != NULL) {
            // Удаляем символ переноса строки (\n) в конце, если он есть
            outBuffer[strcspn(outBuffer, "\r\n")] = 0;
            fclose(file);
            return 1;
        }
        fclose(file);
    }
    return 0; // Не удалось открыть файл или прочитать
}

void scan_motherboard(int *vm_score) {
    char buffer[256];

    // Производитель системы (Sys Vendor)
    if (read_os_string("/sys/class/dmi/id/sys_vendor", buffer, sizeof(buffer)))
        *vm_score += check_for_vm_markers(buffer, "sys_vendor");

    // Имя продукта (Product Name)
    if (read_os_string("/sys/class/dmi/id/product_name", buffer, sizeof(buffer)))
        *vm_score += check_for_vm_markers(buffer, "product_name");

    // Производитель материнской платы (Board Vendor)
    if (read_os_string("/sys/class/dmi/id/board_vendor", buffer, sizeof(buffer)))
        *vm_score += check_for_vm_markers(buffer, "board_vendor");
        
    // Название материнской платы (Board Name)
    if (read_os_string("/sys/class/dmi/id/board_name", buffer, sizeof(buffer)))
        *vm_score += check_for_vm_markers(buffer, "board_name");
}
#endif

//Функция для проверки MAC-адресов сетевых интерфейсов
bool mac_check(){
    #ifdef _WIN32
        //Выделение памяти под IP-адрес 
        ULONG ip_buf = sizeof(IP_ADAPTER_INFO); //Структура для работы с IP-адресом
        PIP_ADAPTER_INFO net_info = (IP_ADAPTER_INFO*)malloc(ip_buf);
        if (net_info == NULL) return 0;

        //Если на устройстве больше одного сетевого интерфейса
        if (GetAdaptersInfo(net_info, &ip_buf) == ERROR_BUFFER_OVERFLOW){
            void *temp = realloc(net_info, ip_buf);
            if (temp == NULL){
                free(net_info);
                return 0; 
            }
            net_info = (IP_ADAPTER_INFO*)temp;
        }

        //Получение данных о всех сетевых интерфейсах
        if (GetAdaptersInfo(net_info, &ip_buf) == NO_ERROR){
            PIP_ADAPTER_INFO net_card = net_info;
            while (net_card){
                if (net_card->AddressLength == 6){ //Стандартные сетевые интерфейсы
                    uint8_t* mac = (uint8_t*)net_card->Address; //Получение MAC-адреса
                    if(scan_mac(mac)) return 1;
                }
                net_card = net_card->Next;
            }
        }
        free(net_info);
    
    #elif defined(__linux__)
        struct ifaddrs *net_info = NULL; //Струтктура с информацией о сетевых интерфейсах
        struct ifaddrs *next = NULL; //Указатель на текущий элемент

        //Получение списка всех сетевых интерфейсов
        if (getifaddrs(&net_info) == -1){ 
            return 0;
        }

        next = net_info;
        while (next){
            //Получение MAC-адреса сетевого интерфейса
            if (next->ifa_addr != NULL && next->ifa_addr->sa_family == AF_PACKET){
                struct sockaddr_ll *node = (struct sockaddr_ll*)next->ifa_addr;
                if (node->sll_halen == 6){ //Проверка длины MAC-адреса
                    uint8_t *mac = (uint8_t *)node->sll_addr;
                    if(scan_mac(mac)) return 1;
                }
            }
            next = next->ifa_next;
        }
        freeifaddrs(net_info);
    #endif
    return 0;
}
//Функция для проверки первых 3 байт MAC-адреса
bool scan_mac(uint8_t* mac) {
    if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) return 1; //VMware
    if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) return 1; //VMware
    if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14) return 1; //VMware
    if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) return 1; //VMware
    if (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) return 1; //VirtualBox
    if (mac[0] == 0x52 && mac[1] == 0x54 && mac[2] == 0x00) return 1; //QEMU or KVM
    if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) return 1; //Microsoft Hyper-V
    if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42) return 1; //Parallels

    return 0;
}
//Функция для проверки наличия бита гипервизора
bool cpu_check(){
    if (check_hypervisor_bit()) return 1; //Обнаружен гипервизор
    return 0; //Не обнражуен гипервизор
}
//Вспомогательная функция для проверка наличия бита гипервизора
int check_hypervisor_bit(){
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid(1, eax, ebx, ecx, edx); //Аналогично, но для GCC
    return (ecx >> 31) & 1; //Сдвиг битов регистра так, чтобы получить 32 бит (бит гипервизора)
}
//Функция для принятия решения
bool vm_decision(){
    if (cpu_check()) return 1; //Проверка бита гипервизора
    if (mac_check()) return 1; //Проверка сетвой карты

    return 0;
}
