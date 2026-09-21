#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "decrypt.h"

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

#define MAX_LEN 256

static bool motherboard_check(); //Функция для проверки имени оборудования
static bool read_os_string(char* hex_value_name, char* buff, size_t buff_size); //Функция для чтения данных об оборудовании
static int check_for_vm_markers(char* data, char* field_name); //Функция для проверки строки на наличие маркеров виртуальных машин
static void to_lower(char* str); //Процедура для перевода строки в нижний регистр
static bool mac_check(); //Функция для проверки MAC-адресов сетевых интерфейсов
static bool scan_mac(uint8_t* mac); //Функция для проверки первых 3 байт MAC-адреса
static bool cpu_check(); //Функция для проверка наличия бита гипервизора
static int check_hypervisor_bit(); //Вспомогательная функция для проверка наличия бита гипервизора
bool vm_decision(); //Функция для принятия решения

//Функция для проверки имени оборудования
static bool motherboard_check(){
    char buffer[MAX_LEN] = {0};
    
    #ifdef _WIN32
        if(read_os_string("587E78796A725266737A6B6668797A776A77", buffer, MAX_LEN)){ //SystemManufacturer
            if(check_for_vm_markers(buffer, "587E78796A725266737A6B6668797A776A77")) return 1; //SystemManufacturer
        }
        if(read_os_string("587E78796A72557774697A68795366726A", buffer, MAX_LEN)){ //SystemProductName
            if(check_for_vm_markers(buffer, "587E78796A72557774697A68795366726A")) return 1; //SystemProductName
        }
        if(read_os_string("4766786A47746677695266737A6B6668797A776A77", buffer, MAX_LEN)){ //BaseBoardManufacturer
            if(check_for_vm_markers(buffer, "4766786A47746677695266737A6B6668797A776A77")) return 1; //BaseBoardManufacturer
        }

    #elif defined(__linux__)
        if(read_os_string("787E78647B6A73697477", buffer, MAX_LEN)){ //sys_vendor
            if(check_for_vm_markers(buffer, "787E78647B6A73697477")) return 1; //sys_vendor
        }
        if(read_os_string("757774697A6879647366726A", buffer, MAX_LEN)){ //product_name
            if(check_for_vm_markers(buffer, "757774697A6879647366726A")) return 1; //product_name
        }
        if(read_os_string("6774667769647B6A73697477", buffer, MAX_LEN)){ //board_vendor
            if(check_for_vm_markers(buffer, "6774667769647B6A73697477")) return 1; //board_vendor
        }
    #endif

    return 0;
}
//Функция для чтения данных из реестра
static bool read_os_string(char* hex_value_name, char* buff, size_t buff_size){
    char key_path[MAX_LEN] = {0};

    #ifdef _WIN32
        HKEY key; //Ключ реестра
        char key_path[MAX_LEN] = {0};
        decode_cesar(key_path, "4D4657495C46574A61494A5848574E55594E545361587E78796A7261474E5458"); //HARDWARE\\DESCRIPTION\\System\\BIOS
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &key) == ERROR_SUCCESS){ //Открытие ключа реестра
            DWORD type;
            DWORD size = (DWORD)buff_size;

            char value_name[MAX_LEN] = {0};
            decode_cesar(value_name, hex_value_name);
            if(RegQueryValueExA(key, value_name, NULL, &type, (LPBYTE)buff, &size) == ERROR_SUCCESS){ //Чтение параметров ключа
                RegCloseKey(key); //Закрытие ключа реестра
                memset(key_path, 0, MAX_LEN);
                memset(value_name, 0, MAX_LEN);
                return 1;
            }
            memset(value_name, 0, MAX_LEN);
            RegCloseKey(key); //Закрытие ключа реестра
        }
        
    #elif defined(__linux__)
        char value_name[MAX_LEN] = {0};
        decode_cesar(value_name, hex_value_name);
        decode_cesar(key_path, "34787E783468716678783469726E346E6934"); ///sys/class/dmi/id/
        strcat(key_path, value_name);

        FILE* file = fopen(key_path, "r");
        if(file != NULL){
            if(fgets(buff, buff_size, file) != NULL){
                buff[strcspn(buff, "\r\n")] = 0;
                fclose(file);
                memset(key_path, 0, MAX_LEN);
                memset(value_name, 0, MAX_LEN);
                return 1;
            }
            fclose(file);
        }
        memset(value_name, 0, MAX_LEN);
        
    #endif

    memset(key_path, 0, MAX_LEN);
    return 0;
}
//Функция для проверки строки на наличие маркеров виртуальных машин
static int check_for_vm_markers(char* data, char* field_name){
    char lower_data[256];
    snprintf(lower_data, 256, "%s", data);
    to_lower(lower_data);

    //Маркеры виртуальных машин
    char* vm_markers[9] = {
        "7B727C66776A", //vmware
        "7B6E77797A667167747D", //virtualbox
        "6E737374796A70", //innotek
        "766A727A", //qemu
        "6774686D78", //bochs
        "7566776671716A7178", //parallels
        "726E68777478746B792568747775747766796E7473", //microsoft corporation
        "7B6E77797A6671257266686D6E736A", //virtual machine 
        "74776668716A" //oracle
    };

    for (int i = 0; i < 9; i++){
        char ascii_vm[MAX_LEN] = {0};
        decode_cesar(ascii_vm, vm_markers[i]);
        if (strstr(lower_data, ascii_vm) != NULL){
            memset(ascii_vm, 0, MAX_LEN);
            return 1;
        }
        memset(ascii_vm, 0, MAX_LEN);
    }
    return 0;
}
//Процедура для перевода строки в нижний регистр
static void to_lower(char* str){
    int len = strlen(str);
    for (int i = 0; i != len; i++){
        if (str[i] > 64 && str[i] < 91){
            str[i] += 32;
        }
    }
}
//Функция для проверки MAC-адресов сетевых интерфейсов
static bool mac_check(){
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
static bool scan_mac(uint8_t* mac){
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
static bool cpu_check(){
    if (check_hypervisor_bit()) return 1; //Обнаружен гипервизор
    return 0; //Не обнражуен гипервизор
}
//Вспомогательная функция для проверка наличия бита гипервизора
static int check_hypervisor_bit(){
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid(1, eax, ebx, ecx, edx); //Аналогично, но для GCC
    return (ecx >> 31) & 1; //Сдвиг битов регистра так, чтобы получить 32 бит (бит гипервизора)
}
//Функция для принятия решения
bool vm_decision(){
    if (cpu_check()) return 1; //Проверка бита гипервизора
    if (mac_check()) return 1; //Проверка сетвой карты
    if (motherboard_check()) return 1; //Проверка названия материнской платы

    return 0;
}
