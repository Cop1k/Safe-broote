# Safe broote

Учебный проект, демонстрирующий набор методов защиты программного обеспечения от отладки, дизассемблирования и запуска в виртуальных машинах.

Проект написан на C с использованием ассемберных вставок (GCC inline asm) и ориентирован на Windows (основная платформа).

> ⚠️ **Внимание:** проект создан исключительно в образовательных целях.
> Все методы защиты являются учебными демонстрациями и **не предназначены** для использования в реальных продуктах. Код не является вредоносным и не собирает данные пользователя.

---

## Содержание

- [Краткое описание файлов](#краткое-описание-файлов)
- [Сборка](#сборка)
- [Принцип работы](#принцип-работы)
- [Методы защиты](#методы-защиты)
  - [1. Обфускация строк (Цезарь + XOR)](#1-обфускация-строк-цезарь--xor)
  - [2. Проверка PEB (BeingDebugged)](#2-проверка-peb-beingdebugged)
  - [3. VEH / SEH / сигналы](#3-veh--seh--сигналы)
  - [4. Проверка гипервизора через CPUID](#4-проверка-гипервизора-через-cpuid)
  - [5. Проверка MAC-адресов](#5-проверка-mac-адресов)
  - [6. Проверка DMI/SMBIOS](#6-проверка-dmismbios)
  - [7. Anti-disassembly трюки](#7-anti-disassembly-трюки)
  - [8. CRC-проверка функций](#8-crc-проверка-функций)
  - [9. Проверка ProcessDebugObjectHandle / ProcessDebugFlags](#9-проверка-processdebugobjecthandle--processdebugflags)
- [Лицензия](#лицензия)

---

### Краткое описание файлов

| Файл | Назначение |
|---|---|
| `main.c` | Основная логика: перебор MD5, чтение пароля, CRC-контроль, генерация серийного номера, анти-отладочные проверки |
| `vm_check.c` | Определение виртуальной машины по CPUID, MAC-адресу и DMI/SMBIOS; обработчики VEH и сигналов |
| `decrypt.c` | Расшифровка HEX-строк: шифр Цезаря и XOR |
| `decrypt.h` | Прототипы функций дешифровки |
| `vm_check.h` | Прототипы функций детекта VM |
| `encrypt.c` | Утилита для шифрования строк |

---

## Сборка

### MinGW (GCC)
```bash
gcc -o md5-broote.exe main.c vm_check.c decrypt.c -lws2_32 -liphlpapi
```

### MSVC
```bash
cl /Fe:md5-broote.exe main.c vm_check.c decrypt.c ws2_32.lib iphlpapi.lib
```

Требования:
- `winsock2.h`, `windows.h`, `iphlpapi.h` (входят в Windows SDK)
- `cpuid.h` (GCC) или `intrin.h` (MSVC)

---

## Принцип работы
1. Программа запускается и выполняет **Return Pointer Abuse** в `main()` — модификацию адреса возврата на стеке для затруднения дизассемблирования.
2. Устанавливается пользовательский обработчик исключений (`SetUnhandledExceptionFilter`).
3. Загружается `ntdll.dll` и адрес `NtQueryInformationProcess`.
4. Вызывается `vm_decision()` — комплексная проверка на виртуальную машину.
5. Вычисляются CRC-суммы защитных функций (`crc(0)`).
6. Из файла `password.txt` читается пароль и проверяется:
   - сначала фиктивной проверкой (`fake_check`);
   - затем реальной (`password_check`), которая использует XOR-дешифровку.
7. При верном пароле генерируется серийный номер `KEY$_Monstr1k_$` и сохраняется в `serial.txt`.
8. Пользователю предлагается ввести MD5-хеш, программа начинает хэшировать заданные строки (пароли) из словаря. В случае совпадения, подорбранный пароль выводится на экран

---

## Методы защиты

### 1. Обфускация строк (Цезарь + XOR)
**Файл:** `decrypt.c`

Все строковые константы в проекте хранятся в HEX-виде и зашифрованы шифром Цезаря со сдвигом `CESAR_KEY = 5`. XOR-ключ для `decode_xor` также зашифрован Цезарем.

```c
void decode_cesar(char* res_str, char* hex_str);
void decode_xor(char* res_str, unsigned char *data, int data_len);
```

**Назначение:** скрыть читаемые строки от утилиты `strings`.

---

### 2. Проверка PEB (BeingDebugged)
**Файл:** `decrypt.c`

```c
BYTE* pBeingDebugged = (BYTE*)(__readgsqword(0x60) + 2);
if(*pBeingDebugged) { /* вывод сообщения */ }
```

**Назначение:** обнаружить отладчик через флаг `BeingDebugged` в PEB.

---

### 3. VEH / SEH / сигналы

**Файл:** `vm_check.c`

Обработчик проверяет регистры `Dr0..Dr3` на наличие аппаратных точек останова.

```c
LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo){
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    if(ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0){
        // Stop debugging program
        exit(1);
    }
    VEH_handle = true;
    ctx->Rip += 2;
    serial_const[0] = '\x05';
    serial_const[1] = '\x20';
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

**Назначение:** обнаружить аппаратные точки останова (HW BP) через отладочные регистры.

---

### 4. Проверка гипервизора через CPUID

**Файл:** `vm_check.c`

```c
__cpuid(1, eax, ebx, ecx, edx);
if (!((ecx >> 31) & 1)) return 0; // Бит гипервизора не выставлен

__cpuid(0x40000000, eax, ebx, ecx, edx);
// Сравнение вендора с "Microsoft Hv"

if (strcmp(hyper_vendor, "Microsoft Hv") == 0) {
    __cpuid(0x40000003, eax, ebx, ecx, edx);
    if ((ebx >> 12) & 1) return 0; // CpuManagement — только у хоста Hyper-V
}
```

**Назначение:** определить, запущена ли программа под гипервизором, и отличить хост Hyper-V (Windows 11 с VBS/HVCI) от гостя.

---

### 5. Проверка MAC-адресов

**Файл:** `vm_check.c`

Сравнение первых 3 байт MAC-адреса сетевых интерфейсов с известными OUI:

| OUI | Вендор |
|---|---|
| `00:05:69` | VMware |
| `00:0C:29` | VMware |
| `00:1C:14` | VMware |
| `00:50:56` | VMware |
| `08:00:27` | VirtualBox |
| `52:54:00` | QEMU / KVM |
| `00:15:5D` | Microsoft Hyper-V |
| `00:1C:42` | Parallels |

```c
static bool mac_check();
static bool scan_mac(uint8_t* mac);
```

**Назначение:** обнаружить VM по MAC-адресу сетевого адаптера.

---

### 6. Проверка DMI/SMBIOS

**Файл:** `vm_check.c`

Чтение строк DMI/SMBIOS и поиск маркеров виртуальных машин через реестр: `HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS` (`SystemManufacturer`, `SystemProductName`, `BaseBoardManufacturer`).

Маркеры: `vmware`, `virtualbox`, `innotek`, `qemu`, `bochs`, `parallels`, `microsoft corporation`, `virtual machine`, `oracle`.

```c
static bool motherboard_check();
static bool read_os_string(char* hex_value_name, char* buff, size_t buff_size);
static bool check_for_vm_markers(char* data, char* field_name);
```

**Назначение:** обнаружить VM по именам производителя материнской платы.

---

### 7. Anti-disassembly трюки
#### 7.1. Impossible Disassembly
**Файл:** `main.c`

Комбинация байт `EB 05` интерпретируется линейным дизассемблером как `jmp +5`, что уводит его в сторону от реального потока исполнения.

```c
__asm__ volatile(
    "movw $0x05EB, %%ax \n\t"
    "xorl %%eax, %%eax \n\t"
    "jz .-4 \n\t"
    ".byte 0xE8 \n\t"
    : : : "eax", "cc"
);
```
**Назначение:** затруднить статический анализ.

#### 7.2. Return Pointer Abuse
**Файл:** `main.c`

```c
__asm__ volatile(
    "call 1f \n\t"
    "1: \n\t"
    "addq $(2f - 1b), (%%rsp) \n\t"
    "ret \n\t"
    ".byte 0xE8 \n\t"
    "2: \n\t"
    : : : "cc"
);
```
**Назначение:** разрушить граф программы в дизассемблере.

#### 7.3. Самомодифицирующийся код (в `save_print`)
**Файл:** `main.c`

Функция `save_print` через `VirtualProtect` меняет безусловный `JMP` (`0xEB`) на условный `JZ` (`0x74`) во время исполнения.

```c
if (VirtualProtect(trap_addr, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
  unsigned char *opcode = (unsigned char *)trap_addr; //Замена безусловного JMP (0xEB) на условный JZ (0x74)
  *opcode = 0x74; 
  VirtualProtect(trap_addr, 2, oldProtect, &oldProtect); //Восстановление старых прав памяти
  __asm__ volatile (
    "mov $1, %%eax \n\t"
    "test %%eax, %%eax \n\t"
    : : : "eax", "cc"
  );
  trap_label:
  __asm__ volatile (".byte 0xEB, 0xFE \n\t"); 
}

```

**Назначение:** затруднить статический анализ.

---

### 8. CRC-проверка функций
**Файл:** `main.c`
Вычисление CRC32 от байтов защитных функций и сравнение с сохранёнными значениями:

Покрываемые функции: `fake_check`, `second_fake_check`, `password_check`, `password_second_check`, `dummy_len_check`.

```c
crc_fake_check_1 = calculate_crc32(fake_check_1, fake_check_2 - fake_check_1);
crc_fake_check_2 = calculate_crc32(fake_check_2, check_1 - fake_check_2);
crc_check_1      = calculate_crc32(check_1, check_2 - check_1);
crc_check_2      = calculate_crc32(check_2, end - check_2);
```

**Назначение:** обнаружить патч защитных функций (`jmp`, `ret`, замена инструкций) сделанный "на ходу".

---

### 9. Проверка ProcessDebugObjectHandle / ProcessDebugFlags
**Файл:** `main.c`

```c
NtQuery(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F, &debugFlags, ...);
// ProcessDebugFlags

NtQuery(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &debugObject, ...);
// ProcessDebugObjectHandle
```

**Назначение:** обнаружить отладчик через недокументированные классы
`NtQueryInformationProcess`.

---

## Лицензия

Проект распространяется в образовательных целях. Использование кода в
коммерческих продуктах, вредоносном ПО или для обхода защиты чужих
программ **запрещено**.

Автор не несёт ответственности за любое использование кода третьими лицами.
