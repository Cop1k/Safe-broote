#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <windows.h>
#include <winternl.h> 

#include "vm_check.h"
#include "decrypt.h"

#define MAX_LEN 256
#define SERIAL_SIZE 10
#define KEY 5
#define TARGET_PASSWORD "\x2B\x1A\x37\x4B\x23\x1D" //qwerty
#define TARGET_PASSWORD_SIZE 6
#define FAKE_TARGET_PASSWORD "554529787C355749" //P@$sw0RD
#define FAKE_TARGET_PASSWORD_SIZE 16
#define TARGET_SERIAL "\x05\x20\x3D\x57\x24\x10\x24\x67\x0E\x17"

//Проверка дебагга через SEH
BOOL isDebugged = TRUE;
LONG WINAPI debugg_checker(PEXCEPTION_POINTERS pExceptionPointers) {
    isDebugged = FALSE;
    return EXCEPTION_CONTINUE_EXECUTION;
}

//Получение информации о процессе
typedef NTSTATUS (WINAPI* NtQueryInformationProcess_check)(
    HANDLE, //Дескриптор (хэндл) процесса
    PROCESSINFOCLASS, //Класс информации
    PVOID, //Указатель на буфер для записи ответа
    ULONG, //Размер буфера
    PULONG //Указатель на переменную, куда система запишет реальный размер переданных данных
);
NtQueryInformationProcess_check NtQuery = NULL; //Адрес экспортируемой функции

//Значения crc для функций, процеряющих пароль
unsigned int crc_fake_check_1 = 0;
unsigned int crc_fake_check_2 = 0;
unsigned int crc_check_1 = 0;
unsigned int crc_check_2 = 0;
char serial_const[SERIAL_SIZE + 1] = {0}; //Серийный номер

//Массив, содержащий псевдослучайные числа, зависимые от синуса числа i: T[i] = 4,294,967,296 * (abs(sin(i)))
static const unsigned int white_noise_arr[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
//Массив величин циклического сдвига
static const unsigned int rotate_amounts_arr[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //Раунд 1 (операции 0-15)
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,     //Раунд 2 (операции 16-31)
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //Раунд 3 (операции 32-47)
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21  //Раунд 4 (операции 48-63)
};

bool compare_md5(const unsigned char *hash_arr1, const unsigned char *hash_arr2); //Функция для сравнения двух MD5 хешей
void md5(const unsigned char *input_str, int input_len, unsigned char *hash); //Процедура для расчета MD5
void hash_selection(char* input_hash); //Процедура для подбора хеша
void str_read(char* input_hash); //Процедура для считывания входной строки

void save_print(char* hex_str); //Функция для вывода HEX-строк
bool password_read(bool mode); //Функция для считывания пароля из файла
__attribute__((noinline)) bool fake_check(char* pass_str); //Функция для фиктовной проверки пароля
__attribute__((noinline)) void second_fake_check(char* pass_str); //Процедура для второй фиктивной проверки пароля
__attribute__((noinline)) bool password_check(char* pass_str); //Функция для проверки пароля
__attribute__((noinline)) int password_second_check(); //Функция для повторной проверки пароля
__attribute__((noinline)) void dummy_len_check(); //Функция для определения размера остальных
bool serial_gen(); //Функция для генерации серийного номера
unsigned int calculate_crc32(const unsigned char *data, unsigned int length); //Функция для расчета CRC
bool crc(bool mode); //Функция для сравнения CRC

//Функция для сравнения двух MD5 хешей
bool compare_md5(const unsigned char *hash_arr1, const unsigned char *hash_arr2) {
    //Проверка флагов отладки процесса
    DWORD debugFlags = 0;
    NtQuery(
        GetCurrentProcess(), //Проверяемый процесс (текущий)
        (PROCESSINFOCLASS)0x1F, //Проверяемая часть процесса (ProcessDebugFlags)
        &debugFlags, //Адрес для записи ответа
        sizeof(debugFlags), //Размер переменной для ответа
        NULL //Получение точного размера ответа
    );

    for(int i = 0; i < 16; i++) {
        if (debugFlags == 0 || hash_arr1[i] != hash_arr2[i]) {
            return 0;
        }
    }
    return 1;
}
//Процедура для расчета MD5
void md5(const unsigned char *input_str, int input_len, unsigned char *hash) {
    //Выделение памяти для будущего хеша
    int max_padding = 72; //1 байт (0x80) + 63 нуля (От 0 до 63 байт нулей, чтобы дойти до len % 64 == 56) + 8 байт длины = 72 байта 
    unsigned char *changing_hash = (unsigned char*)malloc((input_len + max_padding) * sizeof(unsigned char));
    if (changing_hash == NULL) {
        exit(1);
    }
    memcpy(changing_hash, input_str, input_len); //Копирование входного текста в созданную строку
    int current_len = input_len;
    
    //Impossible Disassembly
    __asm__ volatile(
        "movw $0x05EB, %%ax \n\t" //mov ax, 0x05EB
        "xorl %%eax, %%eax \n\t" //После операции Zero Flag = 1
        "jz .-4 \n\t" //74 FA, это интерпритируется как прыжок на -6 байт
        ".byte 0xE8 \n\t" //Мусорный байт
        : //Входные параметры для кода
        : //Выходные параметры для кода
        : "eax", "cc" //Изменения в регистрах и флагах
    );

    //1. Append Padding Bits
    changing_hash[current_len++] = 0x80; //Добавление бита '1' (байт 0x80)
    //Дополнение нулями до длины, сравнимой с 56 по модулю 64 (448 бит = 56 байт, 512 бит = 64 байт)
    while (current_len % 64 != 56) {
        changing_hash[current_len++] = 0;
    }
    
    //2. Append len
    unsigned long long bits_len = (unsigned long long)input_len * 8; //Перевод длины исходного сообщения из байт в биты
    unsigned char len_bytes[8]; //Буфер для байтов. Размер равен 8, т.к. 8 * 8 = 64

    //Преобразование в little-endian (младший бит идет вначале)
    //Сначала происходит сдвиг, который меняет младшие биты (int b = 16 >> 3, где 16 - это 10000 в 2 СС, сдвиг на три разряда вправо = 10, или 2 в 10 СС)
    //Затем происхрдит приведение к типу unsigned char, который занимает ровно 8 бит
    //При приведении числа к unsigned char, компилятор берет только младшие 8 бит
    for (int i = 0; i < 8; i++) { 
        len_bytes[i] = (unsigned char)(bits_len >> (i * 8)); 
    } 
    memcpy(changing_hash + current_len, len_bytes, 8); //Копирование 8 байт длины в конец сообщения
    current_len += 8; //Теперь длина сообщения всегда кратна 64 байтам (512 бит)

    //3. Initialize MD Buffer
    //Константы для сбора хеша
    unsigned int h0 = 0x67452301; //Word A
    unsigned int h1 = 0xefcdab89; //Word B
    unsigned int h2 = 0x98badcfe; //Word C
    unsigned int h3 = 0x10325476; //Word D
    
    //4. Process Message in 32-Word Blocks
    //Входная строка разбивается на блоки по 64 байта (512 бит), каждый из которых обрабатвыется на основе предыдущих блоков
    for(int offset = 0; offset < current_len; offset += 64) {
        //Разбитие блока на 16 32-битных слов (16 * 32 = 512), каждое в формате little-endian
        unsigned int bit_words_arr[16];
        for (int i = 0; i < 16; i++) {
            bit_words_arr[i] = (unsigned int)(changing_hash[offset + i*4]) | //Биты 0-7
                   (unsigned int)(changing_hash[offset + i*4 + 1] << 8) |    //Биты 8-15 
                   (unsigned int)(changing_hash[offset + i*4 + 2] << 16) |   //Биты 16-23
                   (unsigned int)(changing_hash[offset + i*4 + 3] << 24);    //Биты 24-31
        }
        //Сохранение текущих значений констант
        unsigned int h0_temp = h0;
        unsigned int h1_temp = h1;
        unsigned int h2_temp = h2;
        unsigned int h3_temp = h3;
        
        //Основной цикл - 4 раунда по 16 операций
        unsigned int func; //Результат работы одной из 4-х нелинейных функций
        unsigned int word_index; //Индекс слова, которое будет использоваться
        for(int i = 0; i < 64; i++) {
            if (i < 16) {
                func = (h1_temp & h2_temp) | (~h1_temp & h3_temp); //Функция F
                word_index = i;
            }
            else if (i < 32) {
                func = (h1_temp & h3_temp) | (h2_temp & ~h3_temp); //Функция G
                word_index = (5 * i + 1) % 16;
            }
            else if (i < 48) {
                func = h1_temp ^ h2_temp ^ h3_temp; //Функция H
                word_index = (3 * i + 5) % 16;
            }
            else {
                func = h2_temp ^ (h1_temp | ~h3_temp); //Функция I
                word_index = (7 * i) % 16;
            }
            //Изменение значений констант
            unsigned int temp = h3_temp;
            h3_temp = h2_temp;
            h2_temp = h1_temp;
            h1_temp = h1_temp + (((h0_temp + func + white_noise_arr[i] + bit_words_arr[word_index]) << rotate_amounts_arr[i]) | 
                    ((h0_temp + func + white_noise_arr[i] + bit_words_arr[word_index]) >> (32 - rotate_amounts_arr[i]))); //Циклический сдвиг влево
            h0_temp = temp;
        }
        //Добавление изменений от обработки блока к общему хешу
        h0 += h0_temp;
        h1 += h1_temp;
        h2 += h2_temp;
        h3 += h3_temp;
    }
    free(changing_hash);
    
    //5. Output
    //Преобразование 32-битных слов в байты в формате little-endian
    for (int i = 0; i < 16; i++) {
        if (i < 4) {
            hash[i] = (unsigned char)(h0 >> (i * 8));
        } 
        else if (i < 8) {
            hash[i] = (unsigned char)(h1 >> ((i - 4) * 8));
        } 
        else if (i < 12) {
            hash[i] = (unsigned char)(h2 >> ((i - 8) * 8));
        } 
        else {
            hash[i] = (unsigned char)(h3 >> ((i - 12) * 8));
        }
    }
}
//Процедура для подбора хеша
void hash_selection(char* input_hash){
    //Преобразование входной строки в массив из 16 байт
    unsigned char input_hash_bytes[16];
    for(int i = 0; i < 16; i++) {
        sscanf(input_hash + i*2, "%2hhx", &input_hash_bytes[i]); //Считывает по 2 байта из строки и выполняет преобразование
    }
    
    //Открытие файла
    char filename[MAX_LEN] = {0};
    char hex_name[] = "557C69676479747532363535353535353533797D79"; //Pwdb_top-10000000.txt
    decode_cesar(filename, hex_name);
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
       exit(1);
    }
    memset(filename, 0, MAX_LEN);

    //Подготовка строки для считования
    int buf = 10;
    char *file_str = (char*)malloc(buf * sizeof(char));
    if (file_str == NULL){
        fclose(file);
        exit(1);
    }
    //Считование строк с файла
    int symb;
    int iter = 0;
    bool found = 0;
    while(1){
        symb = fgetc(file);
        if(symb != '\n' && symb != EOF){
            file_str[iter++] = (char)symb;
            if(iter == buf - 1){
                buf *= 2;
                char* temp = file_str;
                file_str = realloc(file_str, buf * sizeof(char));
                if(file_str == NULL){
                    free(temp);
                    fclose(file);
                    exit(1);
                }
            }
        }
        else {
            file_str[iter] = '\0';
            unsigned char hash[16];
            md5((unsigned char*)file_str, iter, hash); //Рассчет MD5 для считанной строки
            //Сравнение входного и полученного хешей
            if(compare_md5(hash, input_hash_bytes)){
                //Сдвиг исходного результата в случае, если пароль не верный
                int shift = password_second_check();
                for (int i = 0; i < buf; i++) {
                    int offset = file_str[i] - 33;
                    file_str[i] = (char)(33 + (offset + abs(shift)) % 94);
                }
                save_print("4E736B743F25556678787C747769256B747A73693F25"); //Info: Password found:

                printf("%s\n", file_str);
                found = 1;
                break;
            } 
            iter = 0;
        }
        //Если конец файла
        if(symb == EOF){
            break;
        }
    }
    //Если строка не найдена
    if (!found) {
        save_print("4E736B743F25556678787C74776925737479256B747A7369"); //Info: Password not found
    }

    free(file_str);
    fclose(file);
}
//Процедура для считывания входной строки
void str_read(char* input_hash){
    save_print("4A73796A7725796D6A256D66786D3F"); //Enter the hash:
    password_read(1);
    scanf("%32s", input_hash); 
    if(strlen(input_hash) != 32){
        exit(1);
    }
}

//Функция для вывода HEX-строк
void save_print(char* hex_str){
    //Самомодиыицирующийся код
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

    serial_const[6] = '\x24';
    serial_const[7] = '\x67';

    char res_str[MAX_LEN] = {0};
    decode_cesar(res_str, hex_str);
    printf("%s\n", res_str);
    memset(res_str, 0, MAX_LEN);
}
//Функция для считывания пароля из файла
bool password_read(bool mode){
    char filename[MAX_LEN] = {0};
    char hex_name[] = "756678787C74776933797D79"; //password.txt
    decode_cesar(filename, hex_name);

    FILE *pass_file = fopen(filename, "r");
    memset(filename, 0, MAX_LEN);
    if (pass_file == NULL) {
        save_print("4A777774773F255374256B6E716A257C6E796D257366726A25756678787C74776933797D79256B747A7369"); //Error: No file with name password.txt found
        return 1;
    }
    char pass_str[100] = {0};
    if (fgets(pass_str, 100, pass_file) == NULL) {
        save_print("4A777774773F25756678787C74776933797D79256E78256A7275797E"); //Error: password.txt is empty
        fclose(pass_file);
        return 1;
    }
    fclose(pass_file);

    if(mode == 0){
        if(fake_check(pass_str)) return 1;
    }
    else{
        second_fake_check(pass_str);
    }
    return 0;
}
//Функция для фиктовной проверки пароля
__attribute__((noinline)) bool fake_check(char* pass_str){
    char pass[MAX_LEN] = {0};
    char hex_pass[] = FAKE_TARGET_PASSWORD;
    decode_cesar(pass, hex_pass);
    if (strcmp(pass, pass_str) == 0){
        serial_const[4] = '\x15';
        serial_const[5] = '\x08';
        memset(pass, 0, MAX_LEN);

        RaiseException(EXCEPTION_INT_DIVIDE_BY_ZERO, 0, 0, NULL); //Вызов исключения (деление на 0)

        if (isDebugged) {
            save_print("5879747525696A677A6C6C6E736C25726A26");
            exit(1);
        }
        save_print("4A777774773F255C7774736C25756678787C747769256E7325756678787C74776933797D79"); //Error: Wrong password in password.txt
        //Проверка на неизменность crc
        if (crc(1)){
            save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
            exit(1);
        }
        return 1;
    }
    else{
        if(password_check(pass_str)) return 1;
        //Проверка на неизменность crc
        if (crc(1)){
            save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
            exit(1);
        }
        return 0;
    }

    //Проверка на неизменность crc
    if (crc(1)){
        save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
        exit(1);
    }
    return 1;
}
//Процедура для второй фиктивной проверки пароля
__attribute__((noinline)) void second_fake_check(char* pass_str){
    char pass[MAX_LEN] = {0};
    unsigned char xor_pass[FAKE_TARGET_PASSWORD_SIZE + 1] = FAKE_TARGET_PASSWORD;
    decode_cesar(pass, FAKE_TARGET_PASSWORD);
    if (MAX_LEN ^ 2 > 0 || strcmp(pass, pass_str) == 0){
        memset(pass, 0, MAX_LEN); 
        //serial_const[4] = '\x24';
        //serial_const[5] = '\x10';
    }
    else if(strcmp(FAKE_TARGET_PASSWORD, pass_str) == 0){
        //serial_const[4] = '\x0C';
        //serial_const[5] = '\x15';
    }
    else{
        //serial_const[4] = '\x2A';
        //serial_const[5] = '\x3C';
    }

    //Проверка на неизменность crc
    if (crc(1)){
        save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
        exit(1);
    }
}
//Функция для проверки пароля
__attribute__((noinline)) bool password_check(char* pass_str){
    char pass[MAX_LEN] = {0};
    unsigned char xor_pass[TARGET_PASSWORD_SIZE + 1] = TARGET_PASSWORD;
    decode_xor(pass, xor_pass, TARGET_PASSWORD_SIZE);
    if (strcmp(pass, pass_str) == 0){
        memset(pass, 0, MAX_LEN);

        //Генерация части серийного номера
        serial_const[4] = '\x24';
        serial_const[5] = '\x10';

        save_print("4E736B743F254C6A736A7766796E736C25786A776E667125706A7E"); //Info: Generating serial key
        if(serial_gen()){
            save_print("4A777774773F254866732C79256C6A736A7766796A25706A7E"); //Error: Can't generate key
            //Проверка на неизменность crc
            if (crc(1)){
                save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not try to change or skip crc
                exit(1);
            }
            return 1;   
        }
        else{
            save_print("4E736B743F25586A776E667125706A7E257C6678256C6A736A7766796A6933254D6675757E2567777474796A6B7477686E736C26"); //Info: Serial key was generated. Happy brooteforcing!
            //Проверка на неизменность crc
            if (crc(1)){
                save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
                exit(1);
            }
            return 0; 
        }  
    }
    else{
        save_print("4A777774773F255C7774736C25756678787C747769256E7325756678787C74776933797D79"); //Error: Wrong password in password.txt
        //Проверка на неизменность crc
        if (crc(1)){
            save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
            exit(1);
        }
        return 1;
    }
    //Проверка на неизменность crc
    if (crc(1)){
        save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
        exit(1);
    }
    return 1;
}
//Функция для повторной проверки пароля
__attribute__((noinline)) int password_second_check(){
    char filename[MAX_LEN] = {0};
    char hex_name[] = "756678787C74776933797D79"; //password.txt
    decode_cesar(filename, hex_name);
    
    FILE *pass_file = fopen(filename, "r");
    memset(filename, 0, MAX_LEN);
    if (pass_file == NULL) {
        save_print("4A777774773F255374256B6E716A257C6E796D257366726A25756678787C74776933797D79256B747A7369"); //Error: No file with name password.txt found
        
        //Проверка на неизменность crc
        if (crc(1)){
            save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
            exit(1);
        }
        return 1;
    }
    char pass_str[100] = {0};
    if (fgets(pass_str, 100, pass_file) == NULL) {
        save_print("4A777774773F25756678787C74776933797D79256E78256A7275797E"); //Error: password.txt is empty
        fclose(pass_file);

        //Проверка на неизменность crc
        if (crc(1)){
            save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
            exit(1);
        }
        return 1;
    }
    fclose(pass_file);
    pass_str[strcspn(pass_str, "\n")] = '\0';

    char pass[MAX_LEN] = {0};
    unsigned char xor_pass[TARGET_PASSWORD_SIZE + 1] = TARGET_PASSWORD;
    decode_xor(pass, xor_pass, TARGET_PASSWORD_SIZE);
    int pass_len = strlen(pass);
    int file_pass_len = strlen(pass_str);

    //XOR пароля в файле с TARGET_PASSWORD. Если они одинаковые, вернется 0
    //Если пароли разные, в переменной diff накопится разница (через побитоовое ИЛИ) 
    unsigned int diff = 0;
    diff |= (unsigned int)(pass_len ^ file_pass_len);

    int max_len = (pass_len > file_pass_len) ? pass_len : file_pass_len;
    for (int i = 0; i < max_len; i++) {
        char pass_target = (i < pass_len) ? pass[i] : 0;
        char pass_file = (i < file_pass_len) ? pass_str[i] : 0;
        diff |= (unsigned char)(pass_target ^ pass_file);
    }
    memset(pass, 0, MAX_LEN);

    //Проверка на неизменность crc
    if (crc(1)){
        save_print("4974257374792579777E25797425686D66736C6A2574772578706E7525687768"); //Do not change try to change or skip crc
        exit(1);
    }
    return (int)diff;
}
//Функция для определения размера остальных
__attribute__((noinline)) void dummy_len_check(){

}
//Функция для генерации серийного номера
bool serial_gen(){
    //Генерация начала серийного номера
    char serial[MAX_LEN] = {0};
    char hex_serial[16] = "504A5E29 "; //KEY$
    decode_cesar(serial, hex_serial);

    //Заполнение последнийх байтов серийного номера
    serial_const[8] = '\x0E';
    serial_const[9] = '\x17';

    //Расшифровка серийного номера (должно получится _Monstr1k_)
    char temp[MAX_LEN] = {0};
    decode_xor(temp, serial_const, 10);
    strcat(serial, temp);
    memset(temp, 0, MAX_LEN);

    //Завершение генерации серийного номера
    char last_symb[MAX_LEN] = {0};
    decode_cesar(last_symb, "29"); //$
    serial[14] = last_symb[0];
    serial[15] = '\0'; 

    //Запись сгенерированного номера в файл
    char filename[MAX_LEN] = {0};
    char hex_filename[] = "786A776E667133797D79"; //serial.txt
    decode_cesar(filename, hex_filename);

    FILE *serial_file = fopen(filename, "w");
    memset(filename, 0, MAX_LEN);
    if (serial_file == NULL) {
        save_print("4A777774773F254866732C792574756A73256B6E716A25786A776E667133797D79"); //Error: Can't open file serial.txt
        return 1;
    }

    if (fputs(serial, serial_file) == EOF){
        save_print("4A777774773F254866732C79257C776E796A256B6E716A25786A776E667133797D79"); //Error: Can't write file serial.txt
        fclose(serial_file);
        return 1;
    }
    fclose(serial_file);
    memset(serial, 0, MAX_LEN);   
    return 0;
}
//Функция для расчета CRC
unsigned int calculate_crc32(const unsigned char *data, unsigned int length){
    unsigned int crc = 0xFFFFFFFF;
    for(unsigned int i = 0; i < length; i++){
        crc ^= data[i];
        for(int j = 0; j < 8; j++){
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return ~crc;
}
//Функция для сравнения CRC
bool crc(bool mode){
    HANDLE debugObject = NULL;
    //Проверка наличия объекта отладки (ProcessDebugObjectHandle)
    NtQuery(
        GetCurrentProcess(), //Проверяемый процесс (текущий)
        (PROCESSINFOCLASS)0x1E, //Проверяемая часть процесса (ProcessDebugObjectHandle)
        &debugObject, //Адрес для записи ответа
        sizeof(debugObject), //Размер переменной для ответа
        NULL //Получение точного размера ответа
    );
    //Начальные адреса функций
    const unsigned char *fake_check_1 = (const unsigned char*)fake_check;
    const unsigned char *fake_check_2 = (const unsigned char*)second_fake_check;
    const unsigned char *check_1 = (const unsigned char*)password_check;
    const unsigned char *check_2 = (const unsigned char*)password_second_check;
    const unsigned char *end = (const unsigned char*)dummy_len_check;
    //Первичный расчет crc
    if (!mode){
        crc_fake_check_1 = calculate_crc32(fake_check_1, (unsigned int)(fake_check_2 - fake_check_1));
        crc_fake_check_2 = calculate_crc32(fake_check_2, (unsigned int)(check_1 - fake_check_2));
        crc_check_1 = calculate_crc32(check_1, (unsigned int)(check_2 - check_1));
        crc_check_2 = calculate_crc32(check_2, (unsigned int)(end - check_2));
        if(debugObject != NULL) return 1;
        return 0;
    }
    //Проверка crc
    else{
        if(crc_fake_check_1 != calculate_crc32(fake_check_1, (unsigned int)(fake_check_2 - fake_check_1))) return 1;
        if(crc_fake_check_2 != calculate_crc32(fake_check_2, (unsigned int)(check_1 - fake_check_2))) return 1;
        if(debugObject != NULL) return 1;
        if(crc_check_1 != calculate_crc32(check_1, (unsigned int)(check_2 - check_1))) return 1;
        if(crc_check_2 != calculate_crc32(check_2, (unsigned int)(end - check_2))) return 1;
    }
    return 0;
}

int main(){
    //Return Pointer Abuse
    __asm__ volatile(
        "call 1f \n\t" //Вызов метки "1"
        "1: \n\t" //Адрес сохраняется в стек (из-за работы CALL)
        "addq $(2f - 1b), (%%rsp) \n\t"  //Модификация адреса возврата (сложение числа, с вершины стека, с разницой адресов меток 2 и 1), $ - работа с константами, f - forward, b - backward
        "ret \n\t" //Прыжок на модифицированный адрес
        ".byte 0xE8 \n\t" // Мусорный CALL для добивания дизассемблера
        "2: \n\t" //Реальный код
        : //Входные параметры для кода
        : //Выходные параметры для кода
        : "cc" //Изменения в регистрах и флагах
    );

    SetUnhandledExceptionFilter(debugg_checker); //Пользовательский обработчик прерываний
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll"); //Получение дескриптора уже загруженного в память процесса модуля (DLL), L - закодировать строку в w_char
    if (hNtdll == NULL) {
        return 1;
    }
    NtQuery = (NtQueryInformationProcess_check)GetProcAddress(hNtdll, "NtQueryInformationProcess"); //Получение адреса экспортируемой функции внутри загруженной DLL
    if (NtQuery == NULL) {
        return 1;
    }

    //Функция для обнаружения виртуальной машины
    if(vm_decision()){
        save_print("4A777774773F255B6E77797A6671255266686D6E736A25696A796A68796A69"); //Error: Virtual Machine detected
        return 1; 
    }

    crc(0); //Расчет crc

    //Значения серийного номера
    serial_const[2] = '\x3D';
    serial_const[3] = '\x57';

    if(password_read(0)) return 1; //Функция для считывания пароля из файла
    
    char input_hash[33] = {0};
    str_read(input_hash); //Процедура для считывания входной строки
    hash_selection(input_hash); //Процедура для подбора хеша

    return 0;
}

//Первая строка: 123456 e10adc3949ba59abbe56e057f20f883e
//Примерно серединная строка: 240806obrigado 816ca66c15715c8ebeee7783738fc1dc
//Последняя строка: 05081992s f8ac2b1dbaf289036157b794b7c30fb2
