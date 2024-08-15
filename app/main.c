#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "driver.h"

DWORD find_process(const wchar_t* name) {
    DWORD  id = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);

        if (Process32First(snap, &entry)) {
            do {
                if (strcmp(entry.szExeFile, name) == 0) {
                    id = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &entry));
        }
        CloseHandle(snap);
    }
    return id;
}

int main(void) {
    struct drv drv_inst;
    drv_obj drv = &drv_inst;
    drv_init(drv);

    DWORD pid = find_process(L"chrome.exe");
    printf("pid : %d\n", pid);

    PVOID peb = drv_get_peb(drv, pid);
    printf("peb : %p\n", peb);

    bool being_debugged = false;
    drv_read(drv, pid, (uintptr_t)peb + 2, &being_debugged, 1);

    printf("being_debugged : %s\n", being_debugged ? "true" : "false");

	return 0;
}
