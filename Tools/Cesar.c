#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* encode(const char* str){
    int len = strlen(str);

    // Выделяем память под слитную HEX-строку (2 символа на байт + '\0')
    char* hex_str = (char*)malloc((len * 2 + 1) * sizeof(char));
    if (!hex_str) exit(1);

    for (int i = 0; i < len; i++) {
        unsigned char shifted = (unsigned char)str[i] + 5;
        sprintf(&hex_str[i * 2], "%02X", shifted);
    }
    hex_str[len * 2] = '\0';

    return hex_str; // temp_str убран, чтобы избежать лишней аллокации и утечки
}

char* decode(const char* hex_str){
    int len = strlen(hex_str) / 2;

    // Выделяем память под строку результата (+ 1 для '\0')
    char *res_str = (char*)malloc((len + 1) * sizeof(char));
    if (!res_str) exit(1);

    const char *ptr = hex_str;
    unsigned int byte_val;
    int offset = 0;
    int i = 0;

    // %2x читает строго по 2 HEX-символа
    while (sscanf(ptr, "%2x%n", &byte_val, &offset) == 1) {
        res_str[i++] = (char)((unsigned char)byte_val - 5);
        ptr += offset;
    }
    res_str[i] = '\0';
    return res_str;
}

int main(){
    //char str[] = "Password found: ";

    const char *str[] = {"Info: Password found ", //4E736B743F25556678787C747769256B747A736925
        "Info: Password not found: ", //4E736B743F25556678787C74776925737479256B747A73693F25
        "Info: Enter the hash: ", //4E736B743F254A73796A7725796D6A256D66786D3F25
        "Error: Memmory allocation failure", //4A777774773F25526A727274777E25667171746866796E7473256B666E717A776A
        "Error: No file with name password.txt found", //4A777774773F255374256B6E716A257C6E796D257366726A25756678787C74776933797D79256B747A7369
        "Error: password.txt is empty", //4A777774773F25756678787C74776933797D79256E78256A7275797Ec
        "Error: Can't generate key", //4A777774773F254866732C79256C6A736A7766796A25706A7E
        "Info: Serial key was generated. Happy brooteforcing!", //4E736B743F25586A776E667125706A7E257C6678256C6A736A7766796A6933254D6675757E2567777474796A6B7477686E736C26
        "Error: Wrong password in password.txt", //4A777774773F255C7774736C25756678787C747769256E7325756678787C74776933797D79
        "Error: Can't open file serial.txt", //4A777774773F254866732C792574756A73256B6E716A25786A776E667133797D79
        "Error: Can't write file serial.txt", //4A777774773F254866732C79257C776E796A256B6E716A25786A776E667133797D79
        "Pwdb_top-10000000.txt", //557C69676479747532363535353535353533797D79
        "password.txt", //756678787C74776933797D79
        "serial.txt", //786A776E667133797D79
        "q7m2x9p4v1k8z3n6b0w5r8t2y4u6i9o1a3s5d7f9g2h4j6l8c0e3", //763C72377D3E75397B36703D7F38733B67357C3A773D79377E397A3B6E3E74366638783A693C6B3E6C376D396F3B713D68356A38
        "Stop debugging me!", //5879747525696A677A6C6C6E736C25726A26
        "KEY$", //504A5E29 
        "qwerty", //767C6A77797E
        "P@$sw0RD", //554529787C355749
        "abcd", //66676869
        "$" //29
    };

    for (int i = 0; i < 21; i++){
        char *hex = encode(str[i]);
        printf("%s\n", hex);
    }

    //char *hex = encode(str);
    //printf("%s\n", hex);

    //char *res = decode(hex);
    //printf("%s\n", res);

    //free(hex);
    //free(res);
    return 0;
}