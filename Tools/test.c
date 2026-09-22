#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> // Для типа bool

char str[] = "abcd";

// Глобальный флаг для подтверждения факта перехвата.
// volatile указывает компилятору не кэшировать эту переменную, 
// так как она может измениться асинхронно в обработчике.
volatile bool g_ExceptionHandled = false;

LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    
    if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
    {
        printf("Stop debugging program!\n");
        exit(-1);
    }
    
    // МАРКЕР УСПЕХА: Исключение поймано нашим кодом
    g_ExceptionHandled = true;
    
    ctx->Rip += 2; 

    str[0] = 'e';
    str[1] = 'f';
    
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{

    int test_var = 0;

    printf("%s\n", str);

    // 1. ПРОВЕРКА РЕГИСТРАЦИИ:
    // Функция возвращает указатель на обработчик. Если вернулся NULL - произошла ошибка.
    PVOID pHandler = AddVectoredExceptionHandler(0, ExceptionHandler);
    if (pHandler == NULL) 
    {
        printf("Error: Failed to register VEH.\n");
        return 1;
    }
    
    printf("Triggering exception...\n");
    
    // Вызов исключения
    __asm__ volatile("int $1");
    
    // 2. ПРОВЕРКА ФАКТИЧЕСКОГО ПЕРЕХВАТА:
    // Если программа дошла до этой строчки и не «упала» с ошибкой ОС, 
    // значит инструкция int $1 была как-то обработана/пропущена. 
    // Проверяем флаг, чтобы убедиться, что это сделал именно НАШ VEH.
    if (g_ExceptionHandled) 
    {
        printf("Success: Exception was intercepted by OUR handler!\n");
    } 
    else 
    {
        // Сюда мы можем попасть, если программу перехватил другой обработчик 
        // или, например, подключенный отладчик проглотил исключение 
        // и проигнорировал наш VEH.
        printf("Warning: Execution continued, but our VEH didn't catch the exception.\n");
    }

    printf("%s\n", str);

    char a[10];
    scanf("%s", &a);

    // Правилом хорошего тона является удаление обработчика за собой
    RemoveVectoredExceptionHandler(pHandler);
    
    return 0;
}