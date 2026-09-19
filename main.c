#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <windows.h>

#include "wm_check.h"

#define KEY 5
#define MAX_LEN 256
#define TARGET_PASSWORD "767C6A77797E" //qwerty
#define FAKE_TARGET_PASSWORD "554529787C355749" //P@$sw0RD

BOOL isDebugged = TRUE;
LONG WINAPI debugg_checker(PEXCEPTION_POINTERS pExceptionPointers) {
    isDebugged = FALSE;
    return EXCEPTION_CONTINUE_EXECUTION;
}


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

void bad_pass_read(char* input_hash); //Дублирование процедуры для считывания входной строки

bool save_print(char* hex_str); //Функция для вывода HEX-строк
void decode(char* res_str, char* hex_str); //Функция для дешифровки HEX-строк
unsigned char hex_char_to_val(char symb); //Функция для преобразования HEX в ASCII
int password_second_check(); //Функция для повторной проверки пароля
bool password_read(); //Функция для считывания пароля из файла
bool fake_check(char* pass_str); //Функция для фиктовной проверки пароля
bool password_check(char* pass_str); //Функция для проверки пароля
bool serial_gen(); //Функция для генерации серийного номера

//Функция для сравнения двух MD5 хешей
bool compare_md5(const unsigned char *hash_arr1, const unsigned char *hash_arr2) {
    for(int i = 0; i < 16; i++) {
        if (hash_arr1[i] != hash_arr2[i]) {
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
    //char* filename = NULL;
    char filename[MAX_LEN] = {0};
    char hex_name[] = "557C69676479747532363535353535353533797D79"; //Pwdb_top-10000000.txt
    decode(filename, hex_name);
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
                int shift = password_second_check();
                //if (shift != 1){
                    for (int i = 0; i < buf; i++) {
                        //if ((unsigned char)file_str[i] >= 33 && (unsigned char)file_str[i] <= 126) {
                            int offset = file_str[i] - 33;
                            file_str[i] = (char)(33 + (offset + abs(shift)) % 94);
                        //}
                    }
                    save_print("4E736B743F25556678787C747769256B747A73693F25"); //Info: Password found:
                    printf("%s\n", file_str);
                    found = 1;
                //}
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
        save_print("4E736B743F25556678787C747769256B747A736925"); //Info: Password not found
    }
    free(file_str);
    fclose(file);
}
//Процедура для считывания входной строки
void str_read(char* input_hash){
    save_print("4A73796A7725796D6A256D66786D3F25"); //Info: Enter the hash:
    //if(password_read()){
        //bad_pass_read(input_hash);
    //}
    //else{
        //Считывание не более 32 символов
        scanf("%32s", input_hash); 
        if(strlen(input_hash) != 32){
            exit(1);
        }
    //}
}

//Дублирование процедуры для считывания входной строки
void bad_pass_read(char* input_hash){
    //Считывание не более 32 символов
    scanf("%32s", input_hash); 
    if(strlen(input_hash) != 32){
        exit(1);
    }
}

//Функция для вывода HEX-строк
bool save_print(char* hex_str){
    char res_str[MAX_LEN] = {0};
    decode(res_str, hex_str);
    printf("%s", res_str);
    memset(res_str, 0, MAX_LEN);
}
//Функция для дешифровки HEX-строк
void decode(char* res_str, char* hex_str) {
    int hex_len = strlen(hex_str);
    int len = hex_len / 2;

    for (int i = 0; i < len && i < MAX_LEN; i++) {
        unsigned char high = hex_char_to_val(hex_str[i * 2]);
        unsigned char low  = hex_char_to_val(hex_str[i * 2 + 1]);
        unsigned char byte_val = (high << 4) | low;
        res_str[i] = (char)(byte_val - KEY);
    }
    res_str[len] = '\0';
}
//Функция для преобразования HEX в ASCII
unsigned char hex_char_to_val(char symb) {
    if (symb >= '0' && symb <= '9') return symb - '0';
    if (symb >= 'a' && symb <= 'f') return symb - 'a' + 10;
    if (symb >= 'A' && symb <= 'F') return symb - 'A' + 10;
    return 0;
}
//Функция для повторной проверки пароля
int password_second_check(){
    char filename[MAX_LEN] = {0};
    char hex_name[] = "756678787C74776933797D79"; //password.txt
    decode(filename, hex_name);
    
    FILE *pass_file = fopen(filename, "r");
    memset(filename, 0, MAX_LEN);
    if (pass_file == NULL) {
        save_print("4A777774773F255374256B6E716A257C6E796D257366726A25756678787C74776933797D79256B747A7369"); //Error: No file with name password.txt found
        return 1;
    }
    char pass_str[100] = {0};
    if (fgets(pass_str, 100, pass_file) == NULL) {
        save_print("4A777774773F25756678787C74776933797D79256E78256A7275797Ec"); //Error: password.txt is empty
        fclose(pass_file);
        return 1;
    }
    fclose(pass_file);
    pass_str[strcspn(pass_str, "\n")] = '\0';

    char pass[MAX_LEN] = {0};
    decode(pass, TARGET_PASSWORD);
    int pass_len = strlen(pass);
    int file_pass_len = strlen(pass_str);

    unsigned int diff = 0;
    diff |= (unsigned int)(pass_len ^ file_pass_len);

    int max_len = (pass_len > file_pass_len) ? pass_len : file_pass_len;
    for (int i = 0; i < max_len; i++) {
        char pass_target = (i < pass_len) ? pass[i] : 0;
        char pass_file = (i < file_pass_len) ? pass_str[i] : 0;
        diff |= (unsigned char)(pass_target ^ pass_file);
    }
    memset(pass, 0, MAX_LEN);

    return (int)diff;
}
//Функция для считывания пароля из файла
bool password_read(){
    char filename[MAX_LEN] = {0};
    char hex_name[] = "756678787C74776933797D79"; //password.txt
    decode(filename, hex_name);

    FILE *pass_file = fopen(filename, "r");
    memset(filename, 0, MAX_LEN);
    if (pass_file == NULL) {
        save_print("4A777774773F255374256B6E716A257C6E796D257366726A25756678787C74776933797D79256B747A7369"); //Error: No file with name password.txt found
        return 1;
    }
    char pass_str[100] = {0};
    if (fgets(pass_str, 100, pass_file) == NULL) {
        save_print("4A777774773F25756678787C74776933797D79256E78256A7275797Ec"); //Error: password.txt is empty
        fclose(pass_file);
        return 1;
    }
    fclose(pass_file);

    if(fake_check(pass_str)) return 1;
    return 0;
}
//Функция для фиктовной проверки пароля
bool fake_check(char* pass_str){
    char pass[MAX_LEN] = {0};
    char hex_pass[] = FAKE_TARGET_PASSWORD;
    decode(pass, hex_pass);
    if (strcmp(pass, pass_str) == 0){
        memset(pass, 0, MAX_LEN);
        RaiseException(EXCEPTION_INT_DIVIDE_BY_ZERO, 0, 0, NULL);

        if (isDebugged) {
            save_print("5879747525696A677A6C6C6E736C25726A26");
            char arr[10];
            scanf("%s", &arr);
            exit(-1);
        }
        save_print("4A777774773F255C7774736C25756678787C747769256E7325756678787C74776933797D79"); //Error: Wrong password in password.txt
        return 1;
    }
    else{
        if(password_check(pass_str)) return 1;
        return 0;
    }
    return 1;
}
//Функция для проверки пароля
bool password_check(char* pass_str){
    char pass[MAX_LEN] = {0};
    char hex_pass[] = TARGET_PASSWORD;
    decode(pass, hex_pass);
    if (strcmp(pass, pass_str) == 0){
        memset(pass, 0, MAX_LEN);
        if(serial_gen()){
            save_print("4A777774773F254866732C79256C6A736A7766796A25706A7E"); //Error: Can't generate key
            return 1;   
        }
        else{
            save_print("4E736B743F25586A776E667125706A7E257C6678256C6A736A7766796A6933254D6675757E2567777474796A6B7477686E736C26"); //Info: Serial key was generated. Happy brooteforcing!
            printf("\n");
            return 0; 
        }   
    }
    else{
        save_print("4A777774773F255C7774736C25756678787C747769256E7325756678787C74776933797D79"); //Error: Wrong password in password.txt
        return 1;
    }
}
//Функция для генерации серийного номера
bool serial_gen(){
    //char* dict = NULL;
    char dict[MAX_LEN] = {0};
    char hex_dict[] = "763C72377D3E75397B36703D7F38733B67357C3A773D79377E397A3B6E3E74366638783A693C6B3E6C376D396F3B713D68356A38"; //q7m2x9p4v1k8z3n6b0w5r8t2y4u6i9o1a3s5d7f9g2h4j6l8c0e3
    decode(dict, hex_dict);

    //char* serial = NULL;
    char serial[MAX_LEN] = {0};
    char hex_serial[16] = "504A5E29 "; //KEY$
    decode(serial, hex_serial);

    srand((unsigned)time(NULL));
    for (int i = 4; i < 14; i++) {
        serial[i] = dict[rand() % 36];
    }
    memset(dict, 0, MAX_LEN);

    //char* last_symb = NULL;
    char last_symb[MAX_LEN] = {0};
    char hex_last_symb[] = "29"; //$
    decode(last_symb, hex_last_symb);
    serial[14] = last_symb[0];
    serial[15] = '\0'; 
    memset(last_symb, 0, MAX_LEN);

    //char* filename = NULL;
    char filename[MAX_LEN] = {0};
    char hex_filename[] = "786A776E667133797D79"; //serial.txt
    decode(filename, hex_filename);

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

int main(){
    SetUnhandledExceptionFilter(debugg_checker); //Пользовательский обработчик прерываний

    if(vm_decision()){
        printf("VW detected");
        return 1; //Функция для обнаружения виртуальной машины
    }

    if(password_read()) return 1; //Функция для считывания пароля из файла
    
    char input_hash[33] = {0};
    str_read(input_hash); //Процедура для считывания входной строки
    hash_selection(input_hash); //Процедура для подбора хеша

    return 0;
}

//Первая строка: 123456 e10adc3949ba59abbe56e057f20f883e
//Примерно серединная строка: 240806obrigado 816ca66c15715c8ebeee7783738fc1dc
//Последняя строка: 05081992s f8ac2b1dbaf289036157b794b7c30fb2
