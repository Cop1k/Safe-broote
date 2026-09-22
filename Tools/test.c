#include <stdio.h>
#include <stdint.h>

// Ваша функция вычисления CRC32
unsigned int calculate_crc32(const unsigned char *data, unsigned int length) {
    unsigned int crc = 0xFFFFFFFF;
    
    for (unsigned int i = 0; i < length; i++) {
        crc ^= data[i]; 
        
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
// Запрещаем встраивание (noinline), чтобы функция имела собственный выделенный адрес.
__attribute__((noinline)) void my_logic_function(int number) {
    if (number % 2 == 0) {
        printf("[Функция] Число %d четное.\n", number);
    } else {
        printf("[Функция] Число %d нечетное.\n", number);
    }
}

// Функция-маркер для определения размера my_logic_function.
__attribute__((noinline)) void my_logic_function_end() {
    // Пустая функция
}

int main() {
    // Получаем адреса начала и конца целевой функции
    const unsigned char *func_start = (const unsigned char *)my_logic_function;
    const unsigned char *func_end   = (const unsigned char *)my_logic_function_end;
    
    if (func_start >= func_end) {
        printf("Ошибка: компилятор переставил функции местами. Отключите оптимизацию (например, -O0).\n");
        return 1;
    }

    // Определяем размер функции в памяти
    unsigned int func_size = (unsigned int)(func_end - func_start);
    printf("Размер функции в памяти: %u байт\n\n", func_size);

    // 1. Вычисляем CRC32 ДО запуска функции
    unsigned int crc_before = calculate_crc32(func_start, func_size);
    printf("CRC32 ДО запуска:    0x%08X\n", crc_before);

    // 2. Выполняем функцию
    printf("\n--- Выполнение функции ---\n");
    my_logic_function(10);
    my_logic_function(7);
    printf("--------------------------\n\n");

    // 3. Вычисляем CRC32 ПОСЛЕ запуска функции
    unsigned int crc_after = calculate_crc32(func_start, func_size);
    printf("CRC32 ПОСЛЕ запуска: 0x%08X\n", crc_after);

    // 4. Сравниваем результаты
    if (crc_before != crc_after) {
        printf("\n[!!!] ОШИБКА: Контрольная сумма изменилась!\n");
        printf("Обнаружена модификация машинного кода в памяти во время выполнения программы.\n");
    } else {
        printf("\n[ОК] УСПЕХ: Контрольные суммы совпадают. Код функции не был изменен.\n");
    }

    return 0;
}