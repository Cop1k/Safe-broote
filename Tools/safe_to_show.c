#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <windows.h>

#define KEY 5
#define MAX_LEN 256
#define TARGET_PASSWORD "767C6A77797E" //qwerty

void str_read(char* input_hash); //Процедура для считывания входной строки
void bad_pass_read(char* input_hash); //Дублирование процедуры для считывания входной строки

bool save_print(char* hex_str); //Функция для вывода HEX-строк
void decode(char* res_str, char* hex_str); //Функция для дешифровки HEX-строк
unsigned char hex_char_to_val(char symb); //Функция для преобразования HEX в ASCII
int password_check(); //Функция для повторной проверки пароля
bool password_read(); //Функция для считывания пароля из файла
bool serial_gen(); //Функция для генерации серийного номера
static unsigned int seh_probe(); //Внутренняя SEH-проверка окружения (используется при генерации серийника)

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
int password_check(){
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
    
    /*
    char filename[MAX_LEN] = {0};
    char hex_name[] = "756678787C74776933797D79"; //password.txt
    decode(filename, hex_name);

    FILE *pass_file = fopen(filename, "r");
    memset(filename, 0, MAX_LEN);
    if (pass_file == NULL) {
        save_print("4A777774773F255374256B6E716A257C6E796D257366726A25756678787C74776933797D79256B747A7369"); //Error: No file with name password.txt found
        return 1;
    }
    */

    char path[] = "D://Projects//Safe-broote//Tools//password.txt";
    FILE *pass_file = fopen(path, "r");

    char pass_str[100] = {0};
    if (fgets(pass_str, 100, pass_file) == NULL) {
        save_print("4A777774773F25756678787C74776933797D79256E78256A7275797Ec"); //Error: password.txt is empty
        fclose(pass_file);
        return 1;
    }
    fclose(pass_file);

    //char* pass = NULL;
    char pass[MAX_LEN] = {0};
    char hex_pass[] = TARGET_PASSWORD;
    decode(pass, hex_pass);
    if (strcmp(pass, pass_str) == 0){
        memset(pass, 0, MAX_LEN);
        if(serial_gen()){
            save_print("4A777774773F254866732C79256C6A736A7766796A25706A7E"); //Error: can't generate key
            return 1;   
        }
        else{
            printf("good pass");
            printf("\n");
            return 0; 
        }   
    }
    else{
        save_print("4A777774773F255C7774736C25756678787C747769256E7325756678787C74776933797D79"); //Error: Wrong password in password.txt
        return 1;
    }
}
//Внутренняя SEH-проверка окружения: если отладчик перехватывает
//исключение раньше нас (first-chance), наш векторный обработчик
//не вызовется и функция вернёт 0; в норме (без отладчика) вернёт 1.
//Реализовано через AddVectoredExceptionHandler, т.к. __try/__except -
//это расширение MSVC и не поддерживается GCC/MinGW.
static volatile unsigned int g_seh_probe_handler_ran = 0;

static LONG WINAPI seh_probe_handler(EXCEPTION_POINTERS *ExceptionInfo){
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT){
        g_seh_probe_handler_ran = 1;
#if defined(__x86_64__) || defined(_M_X64)
        ExceptionInfo->ContextRecord->Rip += 1; //пропускаем инструкцию int3
#else
        ExceptionInfo->ContextRecord->Eip += 1; //пропускаем инструкцию int3
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static unsigned int seh_probe(){
    g_seh_probe_handler_ran = 0;

    PVOID handle = AddVectoredExceptionHandler(1, seh_probe_handler);
    __asm__ volatile("int $3"); //аналог __debugbreak()
    if (handle != NULL){
        RemoveVectoredExceptionHandler(handle);
    }

    return g_seh_probe_handler_ran;
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

    //seh_shift == 0 в норме (нет отладчика), == 1 если отладчик перехватил проверку;
    //используется как часть индекса, а не в отдельном if/exit, чтобы не выделяться в потоке кода
    unsigned int seh_shift = 1 - seh_probe();
    printf("%u\n", seh_probe);

    srand((unsigned)time(NULL));
    for (int i = 4; i < 14; i++) {
        serial[i] = dict[(rand() % 36 + seh_shift) % 36];
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

int main(){
    if(password_read()) return 1; //Функция для считывания пароля из файла
    
    char input[33] = {0};
    str_read(input); //Процедура для считывания входной строки
    printf("%s\n", input);

    return 0;
}