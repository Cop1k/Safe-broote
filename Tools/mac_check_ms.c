#include <stdio.h>
#include <string.h>
#include <ctype.h>

// =========================================================
// ПОДКЛЮЧЕНИЕ ПЛАТФОРМОЗАВИСИМЫХ БИБЛИОТЕК
// =========================================================
#ifdef _WIN32
    #include <windows.h>
#elif defined(__linux__)
    #include <stdlib.h> // В Linux для чтения файлов достаточно стандартной библиотеки
#else
    #error "Unsupported Operating System!"
#endif

// =========================================================
// ОБЩИЙ КОД (Платформонезависимый)
// =========================================================

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

// =========================================================
// ТОЧКА ВХОДА
// =========================================================

int main() {
    int vm_score = 0;

    printf("Scanning Motherboard/SMBIOS info for VM signatures...\n\n");
    
    // Функция сама выберет нужную ОС
    scan_motherboard(&vm_score);

    if (vm_score > 0) {
        printf("\nRESULT: Virtual Machine DETECTED! (Score: %d)\n", vm_score);
    } else {
        printf("\nRESULT: No VM markers found in Motherboard info.\n");
    }

    return 0;
}