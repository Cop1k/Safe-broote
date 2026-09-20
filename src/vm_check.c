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

bool motherboard_check(); //Функция для проверки имени оборудования
bool read_os_string(char* key_path, char* value_name, char* buff, size_t buff_size); //Функция для чтения данных об оборудовании
int check_for_vm_markers(char* data, char* field_name); //Функция для проверки строки на наличие маркеров виртуальных машин
void to_lower(char* str); //Процедура для перевода строки в нижний регистр
bool mac_check(); //Функция для проверки MAC-адресов сетевых интерфейсов
bool scan_mac(uint8_t* mac); //Функция для проверки первых 3 байт MAC-адреса
bool cpu_check(); //Функция для проверка наличия бита гипервизора
int check_hypervisor_bit(); //Вспомогательная функция для проверка наличия бита гипервизора
static bool vm_decision(); //Функция для принятия решения

#ifdef _WIN32
    //Функция для проверки имени оборудования
    bool motherboard_check(){
        char key[] = "HARDWARE\\DESCRIPTION\\System\\BIOS";
        char buffer[256];

        if(read_os_string(key, "SystemManufacturer", buffer, 256)){
            if(check_for_vm_markers(buffer, "SystemManufacturer")) return 1;
        }
        if(read_os_string(key, "SystemProductName", buffer, 256)){
            if(check_for_vm_markers(buffer, "SystemProductName")) return 1;
        }
        if(read_os_string(key, "BaseBoardManufacturer", buffer, 256)){
            if(check_for_vm_markers(buffer, "BaseBoardManufacturer")) return 1;
        }
    }
    //Функция для чтения данных из реестра
    bool read_os_string(char* key_path, char* value_name, char* buff, size_t buff_size){
        HKEY key; //Ключ реестра
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &key) == ERROR_SUCCESS){ //Открытие ключа реестра
            DWORD type;
            DWORD size = (DWORD)buff_size;
            if(RegQueryValueExA(key, value_name, NULL, &type, (LPBYTE)buff, &size) == ERROR_SUCCESS){ //Чтение параметров ключа
                RegCloseKey(key); //Закрытие ключа реестра
                return 1;
            }
            RegCloseKey(key); //Закрытие ключа реестра
        }
        return 0;
    }
    
#elif defined(__linux__)
    //Функция для проверки имени оборудования
    bool motherboard_check(){
        char key[256] = "sys/class/dmi/id/";
        char buffer[256];

        if(read_os_string(key, "sys_vendor", buffer, 256)){
            if(check_for_vm_markers(buffer, "sys_vendor")) return 1;
        }
        if(read_os_string(key, "product_name", buffer, 256)){
            if(check_for_vm_markers(buffer, "product_name")) return 1;
        }
        if(read_os_string(key, "board_vendor", buffer, 256)){
            if(check_for_vm_markers(buffer, "board_vendor")) return 1;
        }
    }
    //Функция для чтения данных об оборудовании
    bool read_os_string(char* key_path, char* value_name, char* buff, size_t buff_size){
        strcat(key_path, value_name);
        FILE* file = fopen(key_path, "r");
        if(file != NULL){
            if(fgets(buff, buff_size, file) != NULL){
                buff[strcspn(buff, "\r\n")] = 0;
                fclose(file);
                return 1;
            }
            fclose(file);
        }
        return 0;
    }
#endif

//Функция для проверки строки на наличие маркеров виртуальных машин
int check_for_vm_markers(char* data, char* field_name){
    char lower_data[256];
    snprintf(lower_data, 256, "%s", data);
    to_lower(lower_data);

    //Маркеры виртуальных машин
    char* vm_markers[9] = {
        "vmware",
        "virtualbox",
        "innotek",
        "qemu",
        "bochs",
        "parallels",
        "microsoft corporation",
        "virtual machine",
        "oracle"
    };

    for (int i = 0; i < 9; i++){
        if (strstr(lower_data, vm_markers[i]) != NULL){
            return 1;
        }
    }
    return 0;
}
//Процедура для перевода строки в нижний регистр
void to_lower(char* str){
    int len = strlen(str);
    for (int i = 0; i != len; i++){
        if (str[i] > 64 && str[i] < 91){
            str[i] -= 32;
        }
    }
}
//Функция для проверки MAC-адресов сетевых интерфейсов
bool mac_check(){
    #ifdef _WIN32
        //Выделение памяти под IP-адрес 
        ULONG ip_buf = sizeof(IP_ADAPTER_INFO); //Структура для работы с IP-адресом
        PIP_ADAPTER_INFO net_info = (IP_ADAPTER_INFO*)malloc(ip_buf);
        if(net_info == NULL) return 0;

        //Если на устройстве больше одного сетевого интерфейса
        if(GetAdaptersInfo(net_info, &ip_buf) == ERROR_BUFFER_OVERFLOW){
            void *temp = realloc(net_info, ip_buf);
            if (temp == NULL){
                free(net_info);
                return 0; 
            }
            net_info = (IP_ADAPTER_INFO*)temp;
        }

        //Получение данных о всех сетевых интерфейсах
        if(GetAdaptersInfo(net_info, &ip_buf) == NO_ERROR){
            PIP_ADAPTER_INFO net_card = net_info;
            while(net_card){
                if(net_card->AddressLength == 6){ //Стандартные сетевые интерфейсы
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
        if(getifaddrs(&net_info) == -1){ 
            return 0;
        }

        next = net_info;
        while(next){
            //Получение MAC-адреса сетевого интерфейса
            if(next->ifa_addr != NULL && next->ifa_addr->sa_family == AF_PACKET){
                struct sockaddr_ll *node = (struct sockaddr_ll*)next->ifa_addr;
                if(node->sll_halen == 6){ //Проверка длины MAC-адреса
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
bool scan_mac(uint8_t* mac){
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
static bool vm_decision(){
    if (cpu_check()) return 1; //Проверка бита гипервизора
    if (mac_check()) return 1; //Проверка сетвой карты
    if (motherboard_check()) return 1; //Проверка названия материнской платы

    return 0;
}
