#include <stdio.h>
#include <stdint.h>
#include <windows.h> // Обязательно для VirtualProtect

// Предоставленная вами функция вычисления CRC32
unsigned int calculate_crc32(const unsigned char *data, unsigned int length) {
    unsigned int crc = 0xFFFFFFFF;
    
    for (unsigned int i = 0; i < length; i++) {
        crc ^= data[i]; // Теперь data[i] берет ровно 1 байт (8 бит)
        
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

// Целевая функция с условием if/else.
// Запрещаем встраивание (noinline), чтобы функция точно имела свой адрес в памяти.
__attribute__((noinline)) void my_logic_function(int number) {
    // --- НАЧАЛО ИНЪЕКЦИИ SMC (Self-Modifying Code) ---
    
    void *trap_addr = &&trap_label; //&&trap_label — расширение компилятора GCC, позволяющее получить адрес метки в виде указателя
    DWORD oldProtect;

    //Снятие защиты памяти
    if (VirtualProtect(trap_addr, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        //Перезапись кода
        unsigned char *opcode = (unsigned char *)trap_addr; //Замена безусловного JMP (0xEB) на условный JZ (0x74)
        *opcode = 0x74; 

        VirtualProtect(trap_addr, 2, oldProtect, &oldProtect); //Восстановление старых прав памяти

        //Модификация кода
        __asm__ volatile (
            "mov $1, %%eax \n\t" //Указатель на 1 в eax
            "test %%eax, %%eax \n\t" //test 1, 1 -> Флаг нуля (ZF) становится равным 0
            : //Входные параметры для кода
            : //Выходные параметры для кода
            : "eax", "cc" //Изменения в регистрах и флагах
        );
        //"Бесконечный цикл"
        trap_label:
            __asm__ volatile (
                ".byte 0xEB, 0xFE \n\t" //jmp тут заменен на jz
            ); 
    }

    // --- КОНЕЦ ИНЪЕКЦИИ ---

    if (number % 2 == 0) {
        printf("[Функция] Число %d четное.\n", number);
    } else {
        printf("[Функция] Число %d нечетное.\n", number);
    }
}

// Далее идет обычный код функции. 
// Статический дизассемблер воспримет первый байт сгенерированного 
// ниже кода как часть адреса для ложного CALL (0xE8).

// Функция-маркер для определения конца my_logic_function в памяти.
__attribute__((noinline)) void my_logic_function_end() {
    // Пустая функция
}

int main() {

        __asm__ (
        "call 1f \n\t"  // 1. Делаем CALL на следующую строчку. 
                        // Процессор кладет адрес метки '1' в стек (в %rsp).

        "1: \n\t"       // Сюда приземлится call. И это же адрес, сохраненный в стеке.

        // 2. Модифицируем адрес возврата прямо в памяти стека.
        // Мы прибавляем к значению на вершине стека (%rsp) разницу в байтах 
        // между меткой '2' и меткой '1'. Компилятор сам посчитает это расстояние!
        "addq $(2f - 1b), (%%rsp) \n\t" 

        "ret \n\t"      // 3. RET извлекает из стека наш модифицированный адрес 
                        // и прыгает на метку '2'.

        // 4. (Опционально) Кидаем мусорный байт, чтобы окончательно свести IDA с ума
        ".byte 0xE8 \n\t" 

        "2: \n\t"       // 5. Точка приземления. Здесь продолжается реальный код.
        
        : /* нет выходных операндов */
        : /* нет входных операндов */
        : "cc"          // add меняет флаги процессора (cc)
    );

    // 1. Получаем указатели на начало и конец функции
    const unsigned char *func_start = (const unsigned char *)my_logic_function;
    const unsigned char *func_end   = (const unsigned char *)my_logic_function_end;
    
    // Проверяем, не поменял ли компилятор функции местами (такое бывает при оптимизации)
    if (func_start >= func_end) {
        printf("Ошибка: компилятор переставил функции местами, невозможно вычислить размер.\n");
        return 1;
    }

    // 2. Вычисляем размер функции в байтах
    unsigned int func_size = (unsigned int)(func_end - func_start);
    printf("Размер функции в памяти: %u байт\n", func_size);

    // 3. Вычисляем CRC32 для машинного кода функции
    unsigned int current_crc = calculate_crc32(func_start, func_size);
    printf("Вычисленный CRC32 функции: 0x%08X\n", current_crc);

    // 4. Эмуляция проверки (В реальной жизни expected_crc зашивается после компиляции файла)
    // Для демонстрации мы предполагаем, что текущий CRC и есть ожидаемый.
    unsigned int expected_crc = current_crc; 

    printf("\n--- Проверка целостности (Anti-Tamper) ---\n");
    if (current_crc == expected_crc) {
        printf("УСПЕХ: CRC совпадает. Код функции не был изменен в памяти.\n");
        
        // Выполняем саму функцию
        my_logic_function(42);
        my_logic_function(13);
    } else {
        printf("ОШИБКА: CRC не совпадает! Обнаружена модификация кода.\n");
        // Здесь обычно программа завершается, чтобы не дать злоумышленнику выполнить патченый код.
    }

    return 0;
}
