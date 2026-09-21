#include <stdio.h>
#include <string.h>

void encryprion(){ // + file_str + input_hash
    const char *src[] = {"Password found: ",
        "Enter the hash: ",
        "Error: No file with name password.txt found",
        "Error: password.txt is empty",
        "Error: Can't generate key",
        "Info: Serial key was generated. Happy brooteforcing!",
        "Error: Wrong password in password.txt",
        "Error: Can't open file serial.txt",
        "Error: Can't write file serial.txt",
        "Pwdb_top-10000000.txt",
        "password.txt",
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "KEY$",
        "qwerty"
    };

    char KEY[] = "ZmR9WdVVeHc3dExm1IICMy91Xyadh1SvI6jTTPliuWOPVe8zOt";
    int KEY_LEN = 50;


    for (int i = 0; i < 13; i++) {
        int len = strlen(src[i]);
        for (int j = 0; j < len; j++) {
            unsigned char enc_byte = (unsigned char)src[i][j] ^ (unsigned char)KEY[j % KEY_LEN];
            printf("%02X ", enc_byte);
        }
        printf("\n");
    }
}

void decrypt_and_print(const unsigned char *cipher, size_t len, const char *key, size_t key_len) {
    char decrypted[128];
    for (size_t j = 0; j < len; j++) {
        decrypted[j] = cipher[j] ^ key[j % key_len];
    }
    decrypted[len] = '\0';

    printf("%s\n", decrypted);
}

int main(){
    encryprion();

    const char KEY[] = "ZmR9WdVVeHc3dExm1IICMy91Xyadh1SvI6jTTPliuWOPVe8zOt";
    // Если в вашей логике был j % 49:
    size_t KEY_LEN = 50; 
    // Если хотите использовать весь ключ целиком:
    // size_t KEY_LEN = sizeof(KEY) - 1; // 50

    // Пример 1: "Password found: " (длина 16 байт) 0A 0C 21 4A 20 0B 24 32 45 2E 0C 46 0A 21 42 4D
    const unsigned char cipher1[] = {
        0x0a, 0x0c, 0x21, 0x4a, 0x20, 0x0b, 0x24, 0x32,
        0x45, 0x2e, 0x0c, 0x46, 0x0a, 0x21 , 0x42, 0x4d
    };

    // Пример 2: "Enter the hash: " (длина 15 байт)
    const unsigned char cipher2[] = {
        0x1f, 0x03, 0x16, 0x5c, 0x25, 0x44, 0x38, 0x3d,
        0x35, 0x57, 0x5d, 0x47, 0x1b, 0x6d, 0x73
    };

    printf("Расшифрованные строки:\n");
    decrypt_and_print(cipher1, sizeof(cipher1), KEY, KEY_LEN);
    decrypt_and_print(cipher2, sizeof(cipher2), KEY, KEY_LEN);

    return 0;
}