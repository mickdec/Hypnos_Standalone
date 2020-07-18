#include <windows.h>
#include <stdio.h>
#include <psapi.h>

void init_socket()
{
    printf("ok");
}

int main()
{
    CreateThread(NULL, 0, init_socket, NULL, 0, NULL);
    int a = 0;
    for (;;)
    {
        printf("INFINI.\n");
        scanf("%d", &a);
    }
    return 0;
}