#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 65536 // Буфер 64 КБ (идеально для очень больших файлов)

// Собственная функция построчного чтения.
// В отличие от стандартной fgets, она возвращает точное количество 
// считанных байтов, что позволяет не бояться появления '\0' при XOR-шифровании.
size_t read_line(char *buffer, size_t max_len, FILE *f) {
    size_t i = 0;
    int ch;
    
    // Читаем посимвольно до переноса строки, конца файла или заполнения буфера
    while (i < max_len && (ch = fgetc(f)) != EOF) {
        buffer[i++] = (char)ch;
        if (ch == '\n') {
            break;
        }
    }
    return i;
}

int main() {
    // 1. Указываем файлы и ключ явно в коде
    const char *input_file = "Pwdb_top-10000000.txt";
    const char *output_file = "output.txt";
    const char *key = "jXeKstr1Tz"; 
    
    size_t key_len = strlen(key);
    if (key_len == 0) {
        fprintf(stderr, "Ошибка: Ключ шифрования не может быть пустым.\n");
        return 1;
    }

    // 2. Открываем файлы в бинарном режиме, чтобы избежать искажения данных
    FILE *fin = fopen(input_file, "r");
    if (!fin) {
        perror("Ошибка: Не удалось открыть входной файл");
        return 1;
    }

    FILE *fout = fopen(output_file, "w");
    if (!fout) {
        perror("Ошибка: Не удалось создать выходной файл");
        fclose(fin);
        return 1;
    }

    // Выделяем память под буфер чтения
    char *buffer = (char *)malloc(BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "Ошибка: Не удалось выделить память.\n");
        fclose(fin);
        fclose(fout);
        return 1;
    }

    size_t bytes_read;
    size_t key_idx = 0; // Индекс текущего символа в ключе

    // 3. Читаем файл построчно
    while ((bytes_read = read_line(buffer, BUFFER_SIZE, fin)) > 0) {
        
        // 4. Шифруем считанную строку (или часть строки, если она огромная)
        for (size_t i = 0; i < bytes_read; i++) {
            
            // Если встретили конец строки, сбрасываем индекс ключа для новой строки
            if (buffer[i] == '\n') {
                key_idx = 0;
            } 
            // Символы переноса строк (\n и \r) не шифруем, чтобы сохранить 
            // оригинальное количество строк и структуру файла
            else if (buffer[i] != '\r') {
                buffer[i] ^= key[key_idx % key_len]; // Операция XOR
                key_idx++;
            }
        }

        // 5. Записываем обработанную строку в новый файл
        fwrite(buffer, 1, bytes_read, fout);
    }

    printf("Файл успешно зашифрован (или расшифрован)!\n");

    // Освобождаем ресурсы
    free(buffer);
    fclose(fin);
    fclose(fout);

    return 0;
}