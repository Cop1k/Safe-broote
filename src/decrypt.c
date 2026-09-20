#include <string.h>

#define CESAR_KEY 5
#define XOR_KEY "ZmR9WdVVeHc3dExm1IICMy91Xyadh1SvI6jTTPliuWOPVe8zOt"
#define XOR_LEN 50
#define MAX_LEN 256

void decode_cesar(char* res_str, char* hex_str); //Процедура для дешифровки шифра Цезаря
static unsigned char hex_char_to_ascii(char symb); //Процедура для преобразования HEX в ASCII
void decode_xor(char* res_str, unsigned char *data, int data_len); //Процедура для дешифровки XOR

//Процедура для дешифровки шифра Цезаря
void decode_cesar(char* res_str, char* hex_str) {
    int hex_len = strlen(hex_str);
    int len = hex_len / 2;

    for (int i = 0; i < len && i < MAX_LEN; i++) {
        unsigned char high = hex_char_to_ascii(hex_str[i * 2]);
        unsigned char low  = hex_char_to_ascii(hex_str[i * 2 + 1]);
        unsigned char byte_val = (high << 4) | low;
        res_str[i] = (char)(byte_val - CESAR_KEY);
    }
    res_str[len] = '\0';
}
//Процедура для преобразования HEX в ASCII
static unsigned char hex_char_to_ascii(char symb) {
    if (symb >= '0' && symb <= '9') return symb - '0';
    if (symb >= 'a' && symb <= 'f') return symb - 'a' + 10;
    if (symb >= 'A' && symb <= 'F') return symb - 'A' + 10;
    return 0;
}
//Процедура для дешифровки XOR
void decode_xor(char* res_str, unsigned char *data, int data_len){
    for (int i = 0; i < data_len; i++) {
        res_str[i] = data[i] ^ XOR_KEY[i % XOR_LEN];
    }
    res_str[data_len] = '\0';
}
