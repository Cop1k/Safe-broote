#include <stdio.h>
#include <string.h>

#define CESAR_KEY 5
#define XOR_KEY "ZmR9WdVVeHc3dExm1IICMy91Xyadh1SvI6jTTPliuWOPVe8zOt"
#define XOR_LEN 50
#define MAX_LEN 256

void encrypt_and_print_xor(char *str); //Процедура для шифрования строк через XOR
void encrypt_and_print_cesar(char *str); //Процедура для шифрования строк шифром Цезаря

//Процедура для шифрования строк через XOR
void encrypt_and_print_xor(char *str){
    size_t len = strlen(str);
    if(len > MAX_LEN) len = MAX_LEN;
    for(size_t i = 0; i < len; i++){
        unsigned char enc_byte = (unsigned char)str[i] ^ (unsigned char)XOR_KEY[i % XOR_LEN];
        printf("%02X ", enc_byte);
    }
    printf("\n");
}
//Процедура для шифрования строк шифром Цезаря
void encrypt_and_print_cesar(char *str){
    size_t len = strlen(str);
    if (len > MAX_LEN) len = MAX_LEN;

    for(size_t i = 0; i < len; i++){
        unsigned char enc_byte = (unsigned char)str[i] + CESAR_KEY;
        printf("%02X", enc_byte);
    }
    printf("\n");
}

int main(){
    //Строки для шифрования через XOR
    char *xor_strings[] = {
        "qwerty",
        "serial"
    };
    int xor_count = sizeof(xor_strings) / sizeof(xor_strings[0]);

    //Строки для шифрования шифром Цезаря
    char *cesar_strings[] = {
        "Stop debugging program"
    };
    int cesar_count = sizeof(cesar_strings) / sizeof(cesar_strings[0]);

    printf("--- XOR Encryption Results ---\n");
    for(int i = 0; i < xor_count; i++){
        encrypt_and_print_xor(xor_strings[i]);
    }

    printf("\n--- Caesar Encryption Results ---\n");
    for(int i = 0; i < cesar_count; i++){
        encrypt_and_print_cesar(cesar_strings[i]);
    }
    return 0;
}
