#include <windows.h>
int main(int argc, char const *argv[])
{
    WinExec("cmd.exe /C \"calc && calc\"", 0);
    return 0;
}
